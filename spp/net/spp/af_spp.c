/*
 * Jacob Holtom
 *
 * CCSDS Space Packet Protocol
 */

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

int sysctl_spp_restart_request_timeout = SPP_DEFAULT_T0;
int sysctl_spp_call_request_timeout    = SPP_DEFAULT_T1;
int sysctl_spp_reset_request_timeout   = SPP_DEFAULT_T2;
int sysctl_spp_clear_request_timeout   = SPP_DEFAULT_T3;
int sysctl_spp_no_activity_timeout = SPP_DEFAULT_IDLE;
int sysctl_spp_link_fail_timeout = SPP_DEFAULT_FAIL_TIMEOUT;
int sysctl_spp_window_size = SPP_DEFAULT_WINDOW_SIZE; //Who knows if I need a window, just put it here in case I do.

HLIST_HEAD(spp_list);
DEFINE_SPINLOCK(spp_list_lock);

spp_address spp_addr;

static const struct proto_ops spp_proto_ops;

/* Remove the poor socket 
 * also its safe to do it in an interrupt now lol.
 */
static void spp_remove_sock(struct sock *sk)
{
    spin_lock_bh(&spp_list_lock);
    sk_del_node_init(sk);
    spin_unlock_bh(&spp_list_lock);
}

/* Kill all bound sockets on a device that dropped */
static void spp_kill_by_device(struct net_device *dev)
{
    struct sock *s;
    spin_lock_bh(&spp_list_lock);
    sk_for_each(s, &spp_list) {
        struct spp_sock *spp = spp_sk(s);
        if(spp->device == dev){
            spp_disconnect(s, ENETUNREACH,SPP_OUT_OF_ORDER,0);
            /* TODO: Remove from routes */
            spp->device = NULL;
        }
    }
    spin_unlock_bh(&spp_list_lock);
}

/* Add a socket to the bound sockets list */
spp_insert_socket(structk sock *sk)
{
    spin_lock_bh(&spp_list_lock);
    sk_add_node(sk, &spp_list);
    spin_unlock_bh(&spp_list_lock);
}

/* Deferred destroy */
void spp_destroy_socket(struct sock *);

/* Handles deferred socket kills */
static void spp_destroy_timer(unsigned long data)
{
    spp_destroy_socket((struct sock *)data);
}

static int spp_setsockopt(struct socket *sock, int level, intoptname, char __user *optval, unsigned int optlen)
{
    /* TODO: implement socket option setter */
}

static int spp_setsockopt(struct socket *sock, int level, intoptname, char __user *optval, unsigned int optlen)
{
    /* TODO: implement socket option getter */
}

static int spp_listen(struct socket *sock, int backlog)
{
    struct sock *sk = sock->sk;
    /* TODO: verify functionality and correctness */ 
    if(sk->sk_state != TCP_LISTEN){
        struct spp_sock *spp = spp_sk(sk);

        memset(&spp->d_addr, 0, SPP_ADDR_LEN);
        sk->sk_max_ack_backlog = backlog;
        sk->sk_state = TCP_LISTEN;
        return 0;
    }
    return -EOPNOTSUPP;
}

static struct proto spp_proto = {
    .name = "SPP",
    .owner = THIS_MODULE,
    .obj_size = sizeof(struct spp_sock),
};

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

static struct sock *spp_make_new(struct sock *osk)
{

}


/* Handle Device Status changes */
static int spp_device_event(struct notifier_block *this, unsigned long event, void *ptr)
{

}

static int spp_release(struct socket *sock)
{

}

static int spp_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{

}

static int spp_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags)
{

}

static int spp_accept(struct socket *sock, struct socket *newsock, int flags)
{

}

static int spp_getname(struct socket *sock, struct sockaddr *uaddr, int *uaddr_len, int peer)
{

}

static int spp_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
   struct sock *sk = sock->sk;
   struct spp_sock *spp = spp_sk(sk);
   DECLARE_SOCKADDR(struct sockaddr_spp *, usspp, msg->msg_name);
   int err;
   struct sockaddr_spp sspp;
   struct sk_buff *skb;
   unsigned char *asmptr;
   int n, size, qbit = 0;

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

static int spp_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags)
{
    struct sock *sk = sock->sk;
    struct spp_sock *spp = spp_sk(sk);
    size_t copied;
    unsigned char *asmptr;
    struct sk_buff *skb;
    int n, er, qbit;


}

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

static void *spp_info_next(struct seq_file *seq, void *v, loff_t *pos)
{
    return seq_hlist_next(v, &spp_list, pos);
}

static void *spp_info_start(struct seq_file *seq, loff_t *pos) __acquires(spp_list_lock)
{
    spin_lock_bh(&spp_list_lock);
    return seq_hlist_start_head(&spp_list, *pos);
}

static void spp_info_stop(struct seq_file *seq, void *v) __releases(spp_list_lock)
{
    spin_unlock_bh(&spp_list_lock);
}

static const struct seq_operations spp_info_seqops = {
    .start = spp_info_start,
    .next = spp_info_next,
    .stop = spp_info_stop,
    .show = spp_info_show,
};

static int spp_info_open(struct inode *inode, struct file *file){
    return seq_open(file, &spp_info_seqops);
}

static const struct file_operations spp_info_fops = {
    .owner = THIS_MODULE,
    .open = spp_info_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release,
};
#endif /* CONFIG_PROC_FS */

/* SPP Family operations */
static const struct net_proto_family spp_family_ops = {
    .family = PF_SPP,
    .create = spp_create,
    .owner = THIS_MODULE,
};

/* Protocol operations struct */
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

static struct packet_type spp_packet_type __read_mostly = {
    .type = cpu_to_be16(ETH_P_SPP),
    .func = spp_kiss_rcv,
};

static struct notifier_block spp_dev_notifier = {
    .notifier_call = spp_device_event,
};

/* Initializes SPP in kernel (module_init) */
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

/* Called on module_exit, removes SPP from kernel */
static void __exit spp_exit(void)
{
    remove_proc_entry() //Probably only need one to kill the family
        unregister_netdevice_notifier(&spp_dev_notifier);
    //Unregister sysctl parts

    dev_remove_pack(&spp_packet_type);
    sock_unregister(PF_SPP);
    proto_unregister(&spp_proto);

    //Any other free()'s
}
module_exit(spp_exit);
