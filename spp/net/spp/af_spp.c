/*
 *    Space Packet Protocol Packet Layer release 001
 *
 *    This is BETA software, it may break your machine, fail randomly and
 *    maybe have a lot of problems.  It works enough that its going to space.
 *
 *    This module:
 *              This module is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 *      History
 *      SPP 001         Jacob Holtom and Jacob Willis   Wrote the initial implementation
 *
 *      Authors: Jacob Holtom <jacob@holtom.me>
 *               Jacob Willis <willisj2@byu.edu>
 *
 */
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
    int rc;

    if(!net_eq(net, &init_net))
	return -EAFNOSUPPORT;

    if(sock->type != SOCK_DGRAM || protocol != 0)
	return -ESOCKTNOSUPPORT;

    sk = sk_alloc(net, AF_SPP, GFP_ATOMIC, &spp_proto);
    if (sk == NULL)
	return -ENOMEM;

    spp = spp_sk(sk);
    sock_init_data(sock, sk);
    /* TODO:  initialize timer here */
    sock->ops = &spp_proto_ops;
    sk->sk_protocol = protocol;
    sk->sk_backlog_rcv = spp_backlog_rcv;

    /* TODO: set idle timer value here */

    rc = 0;
    return rc;
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
		spp_dev_device_up(dev);
		break;
		/*case NETDEV_GOING_DOWN:
TODO: probably just kill off the idle timer here
spp_terminate_link();
break;
TODO: Add other types of NETDEV events just in case */
	    case NETDEV_DOWN:
		spp_dev_device_down(dev);
		spp_kill_by_device(dev);
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
    struct spp_sock *spp = spp_sk(sk);
    struct sockaddr_spp *addr = (struct sockaddr_spp *)uaddr;
    int len, i, rc = 0;

    rc = -EINVAL;
    if (addr_len < sizeof(struct sockaddr_spp))
	goto out;
    rc = -EADDRNOTAVAIL; /* TODO: add check to make sure address is available */
    rc = -EACCES;
    if(!capable(CAP_NET_BIND_SERVICE)) /*TODO: This only checks to make sure you can bind ports...i.e either has capabilties or is root */
	goto out;

    lock_sock(sk);
    rc = -EINVAL;
    if(sk->sk_state != TCP_CLOSE)
	goto out_release_sock;

    spp->s_addr.spp_apid = addr->sspp_addr.spp_apid;
    spp_insert_socket(sk);
    sock_reset_flag(sk, SOCK_ZAPPED);
    if(spp->s_addr.spp_apid)
	sk->sk_userlocks |= SOCK_BINDADDR_LOCK;
    spp->d_addr.spp_apid = 0;
    sk_dst_reset(sk);
    rc = 0;
out_release_sock:
    release_sock(sk);
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
 */
static int spp_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len)
{
    struct sock *sk = sock->sk;
    struct spp_sock *spp = spp_sk(sk);
    int free, connected = 0;
    struct sockaddr_spp *usspp = (struct sockaddr_spp *)msg->msg_name;
    spp_address daddr,saddr;
    struct spphdr *hdr;
    int rc,slen;

    /* Check that length is not too big */
    if(len > 0xFFFF)
	return -EMSGSIZE;

    /* Check if someone wants OOB data, cause we don't do it */
    if(msg->msg_flags & MSB_OOB)
	return -EOPNOTSUPP;

    lock_sock(sk);

    if(sock_flag(sk, SOCK_ZAPPED)){
	rc = -EADDRNOTAVAIL;
	goto out;
    }

    if(sk->sk_shutdown & SEND_SHUTDOWN) {
	send_sig(SIGPIPE, current, 0);
	rc = -EPIPE;
	goto out;
    }

    if(spp->spp_dev == NULL){
	rc = -ENETUNREACH;
	goto out;
    }

    if(usspp != NULL){
	if(usspp->sspp_family != AF_SPP || addr_len != sizeof(struct sockaddr_spp)){
	    rc = -EINVAL;
	    goto out;
	}
	daddr = *usspp;
    } else {
	if(sk->sk_state != TCP_ESTABLISHED){
	    rc = -ENOTCONN;
	    got out;
	}
	daddr.sspp_family = AF_SPP;
	daddr.sspp_addr = spp->d_addr;
    }
    printk(KERN_INFO "SPP: sendmsg: Addresses ready, building packet.\n");

    slen = len + sizeof(struct spphdr);

    skb = sock_alloc_send_skb(sk, slen, msg->msg_flags&MSG_DONTWAIT, &rc);
    if(skb == NULL)
	goto out;

    skb_reserve(skb, slen - len);

    printk(KERN_INFO "SPP: sendmsg: adding user data into the equation.\n");

    if(memcpy_fromiovec(skb_put(skb, len), msg->msg_iov, len)){
	rc = -EFAULT;
	kfree_skb(skb);
	goto out;
    }
    skb_reset_network_header(skb);

    printk(KERN_INFO "SPP: sendmsg: transmitting buffer\n");

    /* Handle packets in a sequence here */
    /* determine this if the data length is greater than 1k */

    skb_push(skb, sizeof(struct spphdr));
    hdr = spp_hdr(skb);
    hdr->pvn = 0;
    hdr->pt = 0; /*TODO: configure this to actually be able to swithc between TM and TC */
    hdr->shf = 0; /* TODO: one day we will support secondary headers */
    hdr->apid = daddr.sspp_addr.spp_apid;
    hdr->seqflgs = 3; /* This is unsegmented data, therefore it is 11b or 3 in dec */
    hdr->psc = 0; /* This is unsegmented data, so we will always be the first packet in the count */
    pdf->pdl = len - 1;
    printk(KERN_INFO "SPP: sendmsg: built header of %d bytes\n", sizeof(struct spphdr));
    /* Note: this should always be the same number, 6 bytes */

    skb_set_transport_header(skb, sizeof(struct spphdr));

    /* We aren't in an sequence of packets, so UnSegmented */
    /* *skb_transport_header(skb) = SPP_US; 
     *  But I don't think it needs to be set, because this gets sent on the line too...
     * */

    spp_queue_xmit(skb, spp->spp_dev->dev);

    rc = len;

    printk(KERN_INFO "SPP: sendmsg: Completed sendmsg");
out:
    release_sock(sk);
    return rc;
}

/*
 * Socket Receive Message
 * TODO: Complete method with correct implementation
 */
static int spp_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags)
{
    struct sock *sk = sock->sk;
    struct spp_sock *spp = spp_sk(sk); /* SPP specific socket representation */
    struct sockaddr_spp *sspp = (struct sockaddr_spp *)msg->msg_name;
    unsigned int ulen, copied;
    int peeked;
    int rc;
    struct sk_buff *skb; /* Socket Buffer for message handling */

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
    struct spp_dev *spp_device;
    struct spp_ifaddr **ifap = NULL;
    struct spp_ifaddr *ifa = NULL;
    struct net_device *dev;
    int rc = -EFAULT;
    lock_kernel();
    /* Bring the user request into kernel space */
    if (copy_from_user(&ifr, arg, sizeof(struct ifreq)))
	goto out;
    ifr.ifr_name[IFNAMSIZ - 1] = 0; /* Why? */

    memcpy(&sin_orig,sin, sizeof(*sin)); /* Copy the old address for comparison */

    rtnl_lock();

    rc = -ENODEV;
    dev = __dev_get_by_name(&init_net, ifr.ifr_name);

    if(!dev)
	goto done;
    spp_device = __spp_dev_get_rtnl(dev);
    if(spp_device){
	for(ifap = &spp_device->ifa_list; (ifa = *ifap) != NULL; ifap = &ifa->ifa_next)
	{
	    if(!strcmp(ifr.ifr_name, ifa->ifa_label))
		break;
	}
    }
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
			      memset(sin, 0, sizeof(*sin));
			      sin->sspp_family = AF_SPP;
			      sin->sspp_addr.spp_apid = ifa->ifa_local;
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
			      if(!sppval(&(sin->sspp_addr)))
				  break;
			      if(!ifa){
				  rc = -ENOBUFS;
				  ifa = spp_alloc_ifa();
				  if(!ifa)
				      break;
				  memcpy(ifa->ifa_label, dev->name, IFNAMSIZ);
			      }
			      else {
				  rc = 0;
				  if(ifa->ifa_local == sin->sspp_addr.spp_apid)
				      break;
				  spp_del_ifa(spp_device, ifap, 0);
			      }
			      ifa->ifa_address = ifa->ifa_local = sin->sspp_addr.spp_apid;
			      rc = spp_set_ifa(dev, ifa);
			      printk(KERN_INFO "SPP: IOCTL: Set Interface Address\n");
			      break;
			  }
	case SIOCSIFFLAGS: {
			       rc = -EACCES;
			       if(!capable(CAP_NET_ADMIN))
				   goto out;
			       /* TODO: change device flags...data from ifr.ifr_flags applied to dev*/
			       printk(KERN_INFO "SPP: IOCTL: Set Interface Flags\n");
			       rc = 0;
			       break;
			   }
	case SIOCGIFFLAGS: {
			       /* TODO: Return current flags...*/
			       printk(KERN_INFO "SPP: IOCTL: Get Interface Flags\n");
			       rc = 0;
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
    rtnl_unlock();
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
    .func = spp_rcv,
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
