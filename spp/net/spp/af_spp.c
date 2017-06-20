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
#include <linux/smp_lock.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/if.h>
#include <linux/if_arp.h>
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
#include <net/tcp_states.h>
#include <net/spp.h>

int sysctl_spp_idle_timer = SPP_DEFAULT_IDLE;

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
    struct sock *s;
    struct hlist_node *node;
    write_lock_bh(&spp_list_lock);
    sk_for_each(s, node, &spp_list){
        struct spp_sock *spp = spp_sk(s);
        if(spp->device == dev){
            spp_disconnect(s, ENETUNREACH,SPP_OUT_OF_ORDER,0);
            spp->device = NULL;
        }
    }
    write_unlock_bh(&spp_list_lock);
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
static int spp_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen)
{
    int opt;
    struct sock *sk = sock->sk;
    int rc = -ENOPROTOOPT;

    lock_kernel();
    if (level != SOL_SPP || optname != SPP_PKTTYPE)
        goto out;

    rc = -EINVAL;
    if (optlen < sizeof(int))
        goto out;

    rc = -EFAULT;
    if(get_user(opt, (int __user *)optval))
        goto out;

    spp_sk(sk)->type = !!opt;
    rc = 0;

out:
    unlock_kernel();
    return rc;
}

/*
 * Handles getting the current options of a socket
 * Handles SPP specific socket options (and possibly socket level options too)
 */
static int spp_getsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int *optlen)
{
    struct sock *sk = sock->sk;
    int val, len, rc = -ENOPROTOOPT;

    lock_kernel();
    if (level != SOL_SPP || optname != SPP_PKTTYPE)
        goto out;

    rc = -EFAULT;
    if(get_user(len,optlen))
        goto out;

    len = min_t(unsigned int, len, sizeof(int));

    rc = -EINVAL;
    if (len < 0)
        goto out;

    rc = -EFAULT;
    if(put_user(len,optlen))
        goto out;

    val = spp_sk(sk)->type;
    rc = copy_to_user(optval,&val,len) ? -EFAULT : 0;
out:
    unlock_kernel();
    return rc;
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

        memset(&spp->d_addr, 0, SPP_APID_LEN); /* TODO: should we really be setting it to 0? why memset, shouldn't we just reference the null_addr? */
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

    sk = sk_alloc(net, AF_SPP, GFP_ATOMIC, &spp_proto);
    if (sk == NULL)
        return -ENOMEM;
    spp = spp_sk(sk);
    sock_init_data(sock, sk);

    /* TODO: rewrite so that it actually adjusts all the appropriate things/flags */

    return 0;
}

/*
 * Handle Device Status changes
 */
static int spp_device_event(struct notifier_block *this, unsigned long event, void *ptr)
{
    struct net_device *dev = ptr;
    if(!net_eq(dev_net(dev), &init_net))
        return NOTIFY_DONE;

    /* TODO: enable it to also switch if the type is SDLP, or another layer
     * This is fairly mission specific...*/
    if (dev->type == ARPHRD_SLIP){
        switch(event) {
            case NETDEV_UP:
                /* TODO: Probably just initialize the idle timer here
                 * spp_link_device_up(dev);*/
                break;
            case NETDEV_GOING_DOWN:
                /* TODO: probably just kill off the idle timer here
                spp_terminate_link(); */
                break;
            case NETDEV_DOWN:
                spp_kill_by_device(dev);
                /* spp_link_device_down(dev); TODO: probably don't need since we are point to point and have no "links" */
                break;
        }
    }
    return NOTIFY_DONE;
}

/*
 * Releases a socket
 */
static int spp_release(struct socket *sock)
{
    /* TODO: Implement socket release */
    return 0;
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
    if(!sppval(&(addr->sspp_addr))){
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

out:
    return rc;
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
    rc = -ECONNREFUSED;
    if (sk->sk_state == TCP_CLOSE && sock->state == SS_CONNECTING){
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

    rc = -EINVAL;
    if (sock_flag(sk, SOCK_ZAPPED))
        goto out;

    spp_address spp_null = spp_nulladdr;
    if(!sppcmp(&(spp->s_addr), &spp_null))
        /*TODO: set spp->s_addr to null address */
        spp->d_addr = addr->sspp_addr;

    sock->state = SS_CONNECTING;
    sk->sk_state = SS_CONNECTED;/* TODO: in connecting for no time at all, immediately shift to connected? */;

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
    struct sockaddr_spp *sspp = (struct sockaddr_spp *)uaddr;
    struct sock *sk = sock->sk;
    struct spp_sock *spp = spp_sk(sk);
    int rc = 0;

    lock_kernel();
    if (peer) {
        if(sk->sk_state != TCP_ESTABLISHED){
            rc = -ENOTCONN;
            goto out; /* Theoretically this should never happen, but we have the potential to go into IDLE_TIMEOUT and then we go into a dead state...*/
        }
        sspp->sspp_addr = spp->d_addr;
    } else
        sspp->sspp_addr = spp->s_addr;

    sspp->sspp_family = AF_SPP;
    *uaddr_len = sizeof(*sspp);

out:
    unlock_kernel();
    return rc;
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
    SOCK_DEBUG(sk, "SPP: sendto: Addresses assembled. Making packet.\n");

    size = 8192; /* TODO: Assume worst case size for packet header + data...so MTU */

    skb = sock_alloc_send_skb(sk, size, msg->msg_flags&MSG_DONTWAIT, &err);
    if(skb == NULL)
        goto out;

    skb_reserve(skb, size - len);
    SOCK_DEBUG(sk, "SPP: Adding user data\n");

    if(memcpy_fromiovec(skb_put(skb,len), msg->msg_iov, len)){
        err = -EFAULT;
        kfree_skb(skb);
        goto out;
    }

    skb_reset_network_header(skb);

    SOCK_DEBUG(sk, "SPP: Transmitting buffer\n");



out:
    return err;
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
    struct ifreq ifr;
    struct sockaddr_spp sin_orig;
    struct sockaddr_spp *sin = (struct sockaddr_spp *)&ifr.ifr_addr;
    struct net_device *dev;
    int rc = -EFAULT;
    int tryaddrmatch = 0;
    lock_kernel();
    /* Bring the user request into kernel space */
    if (copy_from_user(&ifr, arg, sizeof(struct ifreq)))
        goto out;
    ifr.ifr_name[IFNAMSIZ - 1] = 0; /* Why? */

    memcpy(&sin_orig,sin, sizeof(*sin)); /* Copy the old address for comparison */

    dev_load(spp, ifr.ifr_name);

    rtnl_lock();
    rc = -ENODEV;
    dev = __dev_get_by_name(spp, ifr.ifr_name);
    if(!dev)
        goto done;

    switch (cmd) {
        case TIOCOUTQ: {
            int amount = sk->sk_sndbuf - sk_wmem_alloc_get(sk);
            if (amount < 0)
                amount = 0;
            rc = put_user(amount, (unsigned int __user *)argp);
            break;
        }
        case TIOCINQ: {
            struct sk_buff *skb;
            int amount = 0;
            if((skb = skb_peek(&sk->sk_receive_queue)) != NULL)
                amount = skb->len;
            rc = put_user(amount, (unsigned int __user *)argp);
            break;
        }
        case SIOCGSTAMP: {
                rc = -EINVAL;
                if (sk)
                        rc = sock_get_timestamp(sk,
                                        (struct timeval __user *)argp);
                break;
        }
        case SIOCGSTAMPNS: {
                rc = -EINVAL;
                if (sk)
                        rc = sock_get_timestampns(sk,
                                        (struct timespec __user *)argp);
                break;
        }
        case SIOCGIFADDR: {
                tryaddrmatch = (sin_orig.sspp_family == AF_SPP);
                memset(sin, 0, sizeof(*sin));
                sin->sspp_family = AF_SPP;
                /*sin->sspp_addr = 1; TODO: get the current interface address */
                printk(KERN_INFO "SPP: IOCTL: Get Interface Address\n");
                goto rarok;
        }
        case SIOCSIFADDR: {
                rc = -EACCES;
                if(!capable(CAP_NET_ADMIN))
                    goto out;
                rc = -EINVAL;
                if (sin->sspp_family != AF_SPP)
                    goto out;
                /* TODO: set the interface address */
                printk(KERN_INFO "SPP: IOCTL: Set Interface Address\n");
                break;
        }
        case SIOCSIFFLAGS: {
                rc = -EACCES;
                if(!capable(CAP_NET_ADMIN))
                    goto out;
                /* TODO: change device flags...data from ifr.ifr_flags applied to dev*/
                printk(KERN_INFO "SPP: IOCTL: Set Interface Flags\n");
                break;
        }
        case SIOCGIFFLAGS: {
                /* TODO: Return current flags...*/
                printk(KERN_INFO "SPP: IOCTL: Get Interface Flags\n");
                break;
        }
        case SIOCGIFMTU: {
                /* TODO: Get current interface MTU */
                break;
        }
        case SIOCSIFMTU: {
                /* TODO: Set interface MTU */
                break;
        }
        default:
            return -ENOIOCTLCMD;
            break;
    }
    unlock_kernel();
done:
    rtnl_unlock();
out:
    return rc;
rarok:
    rtnl_unlock();
    rc = copy_to_user(arg, &ifr, sizeof(struct ifreq)) ? -EFAULT : 0;
    goto out;
}

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
    .shutdown = sock_no_shutdown,
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
    int rc;
    rc = proto_register(&spp_proto, 0);

    if( rc != 0)
        goto out;
    rc = sock_register(&spp_family_ops);
    if(rc != 0)
        goto out_proto;

    dev_add_pack(&spp_packet_type);

    rc = register_netdevice_notifier(&spp_dev_notifier);
    if(rc != 0)
        goto out_sock;

    printk(KERN_INFO "SPP For Linux Version 0.1\n");
    spp_register_sysctl();
    rc = spp_proc_init();
    if(rc != 0)
        goto out_dev;

out:
    return rc;
out_dev:
    unregister_netdevice_notifier(&spp_dev_notifier);
out_sock:
    sock_unregister(AF_SPP);
out_proto:
    proto_unregister(&spp_proto);
    goto out;
}
module_init(spp_init);

/*
 * Called on module_exit, removes SPP from kernel
 */
static void __exit spp_exit(void)
{
    spp_proc_exit();
    spp_unregister_sysctl();
    unregister_netdevice_notifier(&spp_dev_notifier);
    dev_remove_pack(&spp_packet_type);
    sock_unregister(PF_SPP);
    proto_unregister(&spp_proto);
}
module_exit(spp_exit);

MODULE_AUTHOR("Jacob Holtom <jacob@holtom.me>");
MODULE_DESCRIPTION("The CCSDS Space Packet Protocol");
MODULE_LICENSE("GPL");
MODULE_ALIAS_NETPROTO(PF_SPP);
