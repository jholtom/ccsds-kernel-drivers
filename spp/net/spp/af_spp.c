/*
 * Jacob Holtom
 *
 * CCSDS Space Packet Protocol
 */

#define pr_fmt(fmt) "SPP: " fmt

#include <linux/capability.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/uaccess.h>
#include <linux/fcntl.h>
#include <linux/termios.h>	/* For TIOCINQ/OUTQ */
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/notifier.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/sysctl.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <net/spp.h>

int sysctl_spp_no_activity_timeout = SPP_DEFAULT_IDLE;
int sysctl_spp_link_fail_timeout = SPP_DEFAULT_FAIL_TIMEOUT;

/* This list is a list of sockets */
HLIST_HEAD(spp_list);
DEFINE_SPINLOCK(spp_list_lock); /* Create a spin lock for the list */

spp_address spp_addr; /* Current address of the local entity */

static const struct proto_ops spp_proto_ops; /* Forward define the protocol ops */

/*  
 * Remove Socket (interrupt safe)
 */
static void spp_remove_sock(struct sock *sk)
{
    spin_lock_bh(&spp_list_lock); /* Acquire lock on socket list */
    sk_del_node_init(sk); /* Remove socket from list and let it die */
    spin_unlock_bh(&spp_list_lock); /* Release lock on socket list */
}

/* 
 * Kill all bound sockets on a device that dropped 
 */
static void spp_kill_by_device(struct net_device *dev)
{
    struct sock *s; /* Temporary Socket Pointer */
    spin_lock_bh(&spp_list_lock); /* Acquire lock on socket list */
    sk_for_each(s, &spp_list) { /* Iterate over sockets */
        struct spp_sock *spp = spp_sk(s); /* Grab the SPP specific socket representation */
        if(spp->device == dev){
            spp_disconnect(s, ENETUNREACH,SPP_OUT_OF_ORDER,0); /* Terminate the socket with a NETWORK UNREACHABLE and OUT OF ORDER message */
            /* TODO: Remove from routes */
            spp->device = NULL; /* Terminate its representation by deassigning its device */
        }
    }
    spin_unlock_bh(&spp_list_lock); /* Release socket list */
}

/* 
 * Add a socket to the bound sockets list 
 */
static void spp_insert_socket(struct sock *sk)
{
    spin_lock_bh(&spp_list_lock); /* Acquire socket list lock */
    sk_add_node(sk, &spp_list); /* Add socket to the list of SPP sockets */
    spin_unlock_bh(&spp_list_lock); /* Release socket list lock */
}

void spp_destroy_socket(struct sock *); /* Forward definition of socket destroy */ 

/* 
 * Handles deferred socket kills on a timer
 */
static void spp_destroy_timer(unsigned long data)
{
    spp_destroy_socket((struct sock *)data); /* Slay the socket */
}

/*
 * Handles setting options on a socket
 * Handles SPP specific socket options (and possibly socket level options too)
 */
static int spp_setsockopt(struct socket *sock, int level, intoptname, char __user *optval, unsigned int optlen)
{
    /* TODO: implement socket option setter */
}

/*
 * Handles getting the current options of a socket
 * Handles SPP specific socket options (and possibly socket level options too)
 */
static int spp_getsockopt(struct socket *sock, int level, intoptname, char __user *optval, unsigned int optlen)
{
    /* TODO: implement socket option getter */
}

/*
 * Puts socket into listening mode (Enables a socket to listen!) 
 */
static int spp_listen(struct socket *sock, int backlog)
{
    struct sock *sk = sock->sk; /* Gets the socket representation */
    /* TODO: verify functionality and correctness */ 
    if(sk->sk_state != TCP_LISTEN){ /* If it is not already in a listening state */
        struct spp_sock *spp = spp_sk(sk); /* Get the SPP specific representation */

        memset(&spp->d_addr, 0, SPP_ADDR_LEN); /* Set the destination address */
        sk->sk_max_ack_backlog = backlog; /* Adjust backlog for acknowledgements (SPP technically doesn't have this)*/
        sk->sk_state = TCP_LISTEN; /* Set state into listen */
        return 0; /* We did it! */
    }
    return -EOPNOTSUPP; /* If we can't go into listen mode, it isn't supported */
}

/* 
 * Defines the Protocol Family kernel object (the socket)
 */
static struct proto spp_proto = {
    .name = "SPP",
    .owner = THIS_MODULE,
    .obj_size = sizeof(struct spp_sock),
};
/*
 * Creates a new instance of the Space Packet Protocol Address Family
 */
static int spp_create(struct net *net, struct socket *sock, int protocol, int kern)
{
    struct sock *sk;
    struct spp_sock *spp;

    if(!net_eq(net, &init_net))
        return -EAFNOSUPPORT;

    if(sock->type != SOCK_SEQPACKET || protocol != 0)
        return -ESOCKTNOSUPPORT;

    sk = sk_alloc(net, PF_SPP, GFP_ATOMIC, &spp_proto,kern);
    if (sk == NULL)
        return -ENOMEM;
    spp = spp_sk(sk);
    sock_init_data(sock, sk);
    skb_queue_head_init(&spp->ack_queue);
#ifdef M_BIT
    skb_queue_head_init(&spp->frag_queue);
    spp->fraglen = 0;
#endif
    sock->ops = &spp_proto_ops;
    sk->sk_protocol = protocol;

    init_timer(&spp->timer);
    init_timer(&spp->idletimer);

    spp->t1 = msecs_to_jiffies(sysctl_spp_call_request_timeout);
    spp->t2 = msecs_to_jiffies(sysctl_spp_reset_request_timeout);
    spp->t3 = msecs_to_jiffies(sysctl_spp_clear_request_timeout);
    spp->idle = msecs_to_jiffies(sysctl_spp_no_activity_timeout);

    spp->state = SPP_STATE_0;

    return 0;
}

/* 
 * Handle Device Status changes 
 */
static int spp_device_event(struct notifier_block *this, unsigned long event, void *ptr)
{
    /* TODO: Implement device status change handling */
}

/*
 * Releases a socket
 */
static int spp_release(struct socket *sock)
{
    /* TODO: Implement socket release */
}

/*
 * Binds a socket to an address
 */
static int spp_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
   struct sock *sk = sock->sk;
   struct sockaddr_spp *addr = (struct sockaddr_spp *)uaddr;
   int len, i, rc = 0;

   if(!sock_flag(sk, SOCK_ZAPPED) ||
           addr_len != sizeof(struct sockaddr_spp) ||
           addr->sspp_family != AF_SPP) {
            rc = -EINVAL;
            goto out;
   }
   if(!sppval(addr->sspp_addr)){
        rc = -EINVAL;
        goto out;
   }
   lock_sock(sk);
   spp_sk(sk)->s_addr = addr->sspp_addr;
   spp_insert_socket(sk);
   sock_reset_flag(sk, SOCK_ZAPPED);
   release_sock(sk);
   SOCK_DEBUG(sk, "spp_bind: socket is bound\n");
    /* TODO: Implement socket bind */
}

/*
 * Connects a socket
 */
static int spp_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags)
{
    struct sock *sk = sock->sk;
    struct spp_sock *spp = spp_sk(sk);
    struct sockaddr_spp *addr = (struct sockaddr_spp *)uaddr;
    int rc = 0;

    lock_sock(sk);
    if (sk->sk_state == TCP_ESTABLISHED && sock->state == SS_CONNECTING){
        sock->state = SS_CONNECTED;
        goto out;
    }
    rc = -ECONNNREFUSED;
    if (sk->sk_state == TCP_COSE && sock->state == SS_CONNECTING){
        sock->state == SS_UNCONNECTED;
        goto out;
    }
    rc = -EISCONN;
    if (sk->sk_state == TCP_ESTABLISHED)
        goto out;

    sk->sk_state = TCP_CLOSE;
    sock->state = SS_UNCONNECTED;

    rc = -EINVAL;
    if (addr_len != sizeof(struct sockaddr_spp) || addr->sspp_family != AF_SPP)
        goto out;

    spp_limit_facilities(&spp->facilities); /* TODO: adjust for no routing */

    rc = -EINVAL;
    if (sock_flag(sk, SOCK_ZAPPED))
        goto out;

   if(!sppcmp(spp->s_addr, spp_nulladdr))
       /*TODO: set spp->s_addr to null address */

   spp->d_addr = addr->sspp_addr;
   sock->state = SS_CONNECTING;
   sk->sk_state = /* TODO: in connecting for no time at all, immediately shift to connected? */;

   /* Start timeout... */
   sock->state = SS_CONNECTED;
   rc = 0;
out:
    release_sock(sk);
    return rc;
}

/*
 * Accept incoming connection (create socket)
 * TODO: complete implementation
 */
static int spp_accept(struct socket *sock, struct socket *newsock, int flags)
{
    struct sock *sk = sock->sk;
    struct sock *newsk;
    struct sk_buff *skb;
    int rc = -EINVAL;
}

/*
 * Socket Get Name: If peer and connected, set addr to d_addr, else, set to s_addr.  Also set AF and adjust address length
 */
static int spp_getname(struct socket *sock, struct sockaddr *uaddr, int *uaddr_len, int peer)
{
    /* TODO: Figure out expected behavior and implement */
}

/*
 * Socket Send Message
 * TODO: Complete method with correct implementation
 */
static int spp_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len)
{
   struct sock *sk = sock->sk;
   struct spp_sock *spp = spp_sk(sk); /* Get SPP specific socket representation */
   DECLARE_SOCKADDR(struct sockaddr_spp *, usspp, msg->msg_name); /* Use this macro to do x,y,y */
   int err; /* Error flag */
   struct sockaddr_spp sspp; /* Temporary addressing struct */
   struct sk_buff *skb; /* Socket buffer for message handling */
   unsigned char *asmptr;
   int n, size, qbit = 0;
   /* Potentially need to bind socket here */
    
   /* Check MSG length */

   lock_sock(sk);
   /* Do some checks whether or not something is bad about the message */
   if(msg->msg_flags & ~(MSG_DONTWAIT|MSG_EOR|MSG_CMSG_COMPAT))
        return -EINVAL;
   /* Check whether or not the socket is zapped */

   /* Check if pipe has shutdown */

   /* Can't reach the other end? */

   if(usspp != NULL) {
        /* Do something */
   }
}

/*
 * Socket Receive Message
 * TODO: Complete method with correct implementation
 */
static int spp_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags)
{
    struct sock *sk = sock->sk;
    struct spp_sock *spp = spp_sk(sk); /* SPP specific socket representation */
    size_t copied;
    unsigned char *asmptr;
    struct sk_buff *skb; /* Socket Buffer for message handling */
    int n, er, qbit;

}

/*
 * Handle SPP ioctl() calls
 * TODO: Define method behavior
 * TODO: Complete implementation
 */
static int spp_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
    struct sock *sk = sock->sk;
    struct spp_sock *spp = spp_sk(sk);
    void __user *argp = (void __user *)arg;

    switch (cmd) {
    case :
    case :

    default:
        return -ENOIOCTLCMD;
    }
    return 0;
}

#ifdef CONFIG_PROC_FS
/* Implementations of procfs statistics and accounting functions */

/*
 * Display SPP status information
 * TODO: Complete method, test behavior
 */
static int spp_info_show(struct seq_file *seq, void *v)
{
    char buf[11], rsbuf[11];

    if(v == SEQ_START_TOKEN)
	    seq_puts(seq, "dest_addr  src_addr  dev   lci  st vs vr va   t  t1  t2  t3  hb    idle Snd-Q Rcv-Q inode\n"); /* Check formatting as it applies to the rest of my prints */
    else {
        struct sock *s = sk_entry(v);
        struct spp_sock *spp = spp_sk(s);
        const char *devname, *address;
        if (!dev)
            devname = "???";
        else
            devname = dev->name;

	 seq_printf(seq, "%-10s ", spp2ascii(rsbuf, &spp->d_addr)); /*Prints destination address */
         
         seq_printf(seq, "%-10s %-5s %3.3X  %d  %d  %d  %d %3lu %3lu %3lu %3lu %3lu %3lu/%03lu %5d %5d %ld\n", spp2ascii(rsbuf, &spp->s_addr),
                 devname,
                 spp->lci & 0x0FFF,
                 spp->state,
                 spp->vs,
                 spp->vr,
                 spp->va,
                 /* TODO: take care of timer prints here*/
                 sk_wmem_alloc_get(s),
                 sk_rmem_alloc_get(s), 
                 s->sk_socket ? SOCK_INDOE(s->sk_socket)->i_indo : 0L);

    }
    return 0;
}

/*
 * Moves to next info object
 */
static void *spp_info_next(struct seq_file *seq, void *v, loff_t *pos)
{
    return seq_hlist_next(v, &spp_list, pos);
}

/*
 * Begins the process of spitting out info
 */
static void *spp_info_start(struct seq_file *seq, loff_t *pos) __acquires(spp_list_lock)
{
    spin_lock_bh(&spp_list_lock); /* Acquires lock on socket list */
    return seq_hlist_start_head(&spp_list, *pos); /* Begins moving through the list */
}

/*
 * Terminates the information process 
 */
static void spp_info_stop(struct seq_file *seq, void *v) __releases(spp_list_lock)
{
    spin_unlock_bh(&spp_list_lock); /* Release lock on socket list */
}

/* 
 * Sequence Operations kernel object
 */
static const struct seq_operations spp_info_seqops = {
    .start = spp_info_start,
    .next = spp_info_next,
    .stop = spp_info_stop,
    .show = spp_info_show,
};

/*
 * Opens file representation to feed info into
 */
static int spp_info_open(struct inode *inode, struct file *file){
    return seq_open(file, &spp_info_seqops); /* Open up file */
}

/*
 * File operations kernel object
 */
static const struct file_operations spp_info_fops = {
    .owner = THIS_MODULE,
    .open = spp_info_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release,
};
#endif /* CONFIG_PROC_FS */

/* 
 * SPP Family operations (kernel object)
 */
static const struct net_proto_family spp_family_ops = {
    .family = PF_SPP,
    .create = spp_create,
    .owner = THIS_MODULE,
};

/* 
 * Space Packet Protocol protocol operations (kernel object)
 */
static const struct proto_ops spp_proto_ops = {
    .family = PF_SPP,
    .owner = THIS_MODULE,
    .release = spp_release,
    .bind = spp_bind,
    .connect = spp_connect,
    .socketpair = sock_no_socketpair,
    .accept = spp_accept,
    .getname = spp_getname,
    .poll = datagram_poll,
    .ioctl = spp_ioctl,
    .listen = spp_listen,
    .shutdown = spp_shutdown,
    .setsockopt = spp_setsockopt,
    .getsockopt = spp_getsockopt,
    .sendmsg = spp_sendmsg,
    .recvmsg = spp_recvmsg,
    .mmap = sock_no_mmap,
    .sendpage = sock_no_sendpage,
};

/* 
 * Space Packet Protocol packet type (kernel object)
 */
static struct packet_type spp_packet_type __read_mostly = {
    .type = cpu_to_be16(ETH_P_SPP),
    .func = spp_kiss_rcv,
};

/*
 * Space Packet Protocol event handler (kernel object)
 */
static struct notifier_block spp_dev_notifier = {
    .notifier_call = spp_device_event,
};

/* 
 * Initializes SPP in kernel (module_init) 
 */
static int __init spp_init(void)
{
    int i;
    int rc;
    
    rc = proto_register(&spp_proto, 0);
    
    if( rc != 0)
        goto out;
    
    spp_addr = spp_nulladdr; /* TODO: Ensure I'm setting the right global and create a null SPP address */
    
    sock_register(&spp_family_ops);
    register_netdevice_notifier(&spp_dev_notifier);

    spp_register_pid(&spp_pid); /*TODO: I don't think I need this, ensure I don't, then remove */
    spp_linkfail_register(&spp_linkfail_notifier); /* TODO: Probably need, but check */

#ifdef CONFIG_SYSCTL
    spp_register_sysctl();
#endif
    spp_loopback_init(); /* TODO: May not need a loopback as we have no routing */

    proc_create("spp", S_IRUGO, init_net.proc_net, &spp_info_fops);
    proc_create("spp_entities", S_IRUGO, init_net.proc_net, &spp_nodes_fops);

out:
    return rc;
}
module_init(spp_init);

MODULE_AUTHOR("Jacob Holtom <jacob@holtom.me>");
MODULE_DESCRIPTION("The CCSDS Space Packet Protocol");
MODULE_LICENSE("GPL");
MODULE_ALIAS_NETPROTO(PF_SPP);

/* 
 * Called on module_exit, removes SPP from kernel
 */
static void __exit spp_exit(void)
{
    remove_proc_entry() //Probably only need one to kill the family
    unregister_netdevice_notifier(&spp_dev_notifier);
    //Unregister sysctl parts

    dev_remove_pack(&spp_packet_type);
    sock_unregister(PF_SPP);
    proto_unregister(&spp_proto);

    /* TODO: Any other free()'s */
}
module_exit(spp_exit);
