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
#include <linux/mutex.h>
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
#include <linux/crypto.h>

static DEFINE_MUTEX(spp_mutex); //TODO move this to better location.

/* Assorted variables for use */

int sysctl_spp_idle_timer = SPP_DEFAULT_IDLE;
int sysctl_spp_encrypt = 0;
char sysctl_spp_encryptionkey[17] = "loremipsumdolore";

const char SPP_ENCRYPTION_ALG_NAME[4] = "aes";

const spp_address spp_defaddr = {2001};
const spp_address spp_nulladdr = {0};
const spp_address spp_idleaddr = {2047};

/* This list is a list of sockets */
HLIST_HEAD(spp_list);
DEFINE_RWLOCK(spp_list_lock); /* Create a spin lock for the list */

spp_address spp_addr; /* Current address of the local entity */

static const struct proto_ops spp_proto_ops; /* Forward define the protocol ops */

struct sock *spp_get_socket(spp_address *dest_addr, int type){
    struct sock *s = NULL;
    
    read_lock_bh(&spp_list_lock);
    sk_for_each(s, &spp_list){
        if(sppcmp(&(spp_sk(s)->s_addr), dest_addr) && s->sk_type == type){
            sock_hold(s);
            return s;
        }
    }
    read_unlock_bh(&spp_list_lock);
    return NULL;
}

/*
 * Remove Socket (interrupt safe)
 */
static void spp_remove_sock(struct sock *sk)
{
    write_lock_bh(&spp_list_lock); /* Acquire lock on socket list */
    sk_del_node_init(sk); /* Remove socket from list and let it die */
    write_unlock_bh(&spp_list_lock); /* Release lock on socket list */
}

/*
 * Kill all bound sockets on a device that dropped
 */
static void spp_kill_by_device(struct net_device *dev)
{
    struct sock *s;
    
    write_lock_bh(&spp_list_lock);
    sk_for_each(s, &spp_list){
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
    write_lock_bh(&spp_list_lock); /* Acquire socket list lock */
    sk_add_node(sk, &spp_list); /* Add socket to the list of SPP sockets */
    write_unlock_bh(&spp_list_lock); /* Release socket list lock */
}

void spp_destroy_socket(struct sock *sk){
    struct sk_buff *skb;

    spp_remove_sock(sk);
    spp_clear_queues(sk);

    while((skb = skb_dequeue(&sk->sk_receive_queue)) != NULL){
        if(skb->sk != sk){
            sock_set_flag(skb->sk, SOCK_DEAD);
        }
        kfree_skb(skb);
    }
    __sock_put(sk);
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

    mutex_lock(&spp_mutex);
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
    mutex_unlock(&spp_mutex);
    return rc;
}

/*
 * Handles getting the current options of a socket
 * Handles SPP specific socket options (and possibly socket level options too)
 */
static int spp_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen)
{
    struct sock *sk = sock->sk;
    int val, len, rc = -ENOPROTOOPT;

    mutex_lock(&spp_mutex);
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
    mutex_unlock(&spp_mutex);
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

    sk = sk_alloc(net, AF_SPP, GFP_ATOMIC, &spp_proto, kern);
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
    struct sock *sk = sock->sk;
    struct spp_sock *spp;

    if (sk == NULL)
        return 0;
    sock_hold(sk);
    sock_orphan(sk);
    lock_sock(sk);
    spp = spp_sk(sk);
    sk->sk_state = TCP_CLOSE;
    sk->sk_shutdown |= SEND_SHUTDOWN;
    sk->sk_state_change(sk);
    spp_destroy_socket(sk);
    sock->sk = NULL;
    release_sock(sk);
    sock_put(sk);
    return 0;
}

/*
 * Binds a socket to an address
 */
static int spp_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
    struct sock *sk = sock->sk;
    struct spp_sock *spp = spp_sk(sk);
    struct spp_dev *spp_dev = NULL;
    struct sockaddr_spp *addr = (struct sockaddr_spp *)uaddr;
    int rc = 0;

    rc = -EINVAL;
    if (addr_len < sizeof(struct sockaddr_spp))
        goto out;
    rc = -EACCES;
    if(!capable(CAP_NET_BIND_SERVICE)) /*TODO: This only checks to make sure you can bind ports...i.e either has capabilties or is root */
        goto out;

    lock_sock(sk);
    rc = -EINVAL;
    if(sk->sk_state != TCP_CLOSE)
        goto out_release_sock;

    spp->s_addr.spp_apid = addr->sspp_addr.spp_apid;
    sock_reset_flag(sk, SOCK_ZAPPED);
    if(spp->s_addr.spp_apid)
        sk->sk_userlocks |= SOCK_BINDADDR_LOCK;
    spp->d_addr.spp_apid = 0;
    sk_dst_reset(sk);

    if(spp->device != NULL)
        goto done;

    spp_dev = spp_addr_sppdev(&addr->sspp_addr);
    if(spp_dev != NULL){
        spp->device = spp_dev->dev;
        rc = 0;
        goto done;
    }
    rc = -EADDRNOTAVAIL;
    goto out_release_sock;
done:
    spp_insert_socket(sk);
    sock_reset_flag(sk, SOCK_ZAPPED);
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
        sock->state = SS_UNCONNECTED;
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

    if(!sppcmp(&(spp->s_addr), &spp_nulladdr)){
        spp->d_addr = addr->sspp_addr;
    }

    sk->sk_state = SS_CONNECTED;
    sock->state = SS_CONNECTED;
    rc = 0;
out:
    release_sock(sk);
    return rc;
}

/*
 * Accept incoming connection (create socket)
 * TODO: Figure out correct behavior
 * NOTE: This isn't really something that can happen in SPP, since it is a connectionless protocol.
 */
static int spp_accept(struct socket *sock, struct socket *newsock, int flags, bool kern)
{
    int rc = -EINVAL;
    return rc;
}

/*
 * Socket Get Name: If peer and connected, set addr to d_addr, else, set to s_addr.  Also set AF and adjust address length
 */
static int spp_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
{
    struct sockaddr_spp *sspp = (struct sockaddr_spp *)uaddr;
    struct sock *sk = sock->sk;
    struct spp_sock *spp = spp_sk(sk);
    int rc = 0;
    // May not actually need to lock here
    mutex_lock(&spp_mutex);
    if (peer) {
        if(sk->sk_state != TCP_ESTABLISHED){
            rc = -ENOTCONN;
            goto out; /* Theoretically this should never happen, but we have the potential to go into IDLE_TIMEOUT and then we go into a dead state...*/
        }
        sspp->sspp_addr = spp->d_addr;
    } else
        sspp->sspp_addr = spp->s_addr;

    sspp->sspp_family = AF_SPP;
    rc = sizeof(*sspp);

out:
    mutex_unlock(&spp_mutex);
    return rc;
}

/*
 * Copy data of length len from an iovec into kernel space starting at an offset.
 * Returns -EFAULT on error.
 */
static int memcpy_partial_fromiovec(u8 *kdata, struct iovec *iov, size_t offset, size_t len) {
    size_t copy, rem;

    /* Skip over finished iovecs */
    while (offset >= iov->iov_len) {
        offset -= iov->iov_len;
        iov++;
    }

    while (len > 0) {
        rem = iov->iov_len - offset;        /* Remaining bytes in iovec */
        copy = min_t(size_t, len, rem);     /* Number of bytes to copy from this iovec */

        /* Copy bytes */
        if(copy_from_user(kdata, iov->iov_base + offset, copy))
            return -EFAULT;

        /* Update counters */
        offset = 0;         /* We only need the offset on the first copy */
        kdata += copy;
        len -= copy;
        if (copy == rem)
            iov++;          /* iovec was consumed */
    }

    return 0;
}

/*
 * Encrypt data from an iovec into a sk_buff. sk_buff must be large enough to handle padded data.
 * Returns -EFAULT on error.
 *
 * Note: this modifies the original iovec.
 */
static int spp_encrypt_fromiovec(struct sk_buff *skb, struct iovec *iov, size_t len, struct crypto_cipher *tfm)
{
    size_t copy;
    size_t plen = 0;                                /* Length of padding for block */
    size_t blksize = crypto_cipher_blocksize(tfm);  /* Size of transform block size */
    size_t offset = 0;
    unsigned char buff[blksize];                    /* Buffer space (iovec may not be properly sized) */

    while (len > 0) {
        /* Get copy size */
        if (len < blksize) {
            /* Block and padding */
            plen = blksize - len;
            copy = len;

            /* Pad end of block (PKCS#5) */
            memset(buff + (blksize - plen), plen, plen * sizeof(char));
        } else {
            /* Full data block */
            copy = blksize;
        }

        /* Copy block */
        if (memcpy_partial_fromiovec(buff, iov, offset, copy))
            return -EFAULT;

        /* Encrypt block to socket buffer */
        crypto_cipher_encrypt_one(tfm, skb_put(skb, blksize) /* append data */, buff);

        /* If ||M|| mod blksize = 0, append extra padded block */
        if (len == blksize) {
            memset(buff, blksize, blksize * sizeof(char));
            crypto_cipher_encrypt_one(tfm, skb_put(skb, blksize) /* advance skb pointer */, buff);
        }

        /* Update counters */
        offset += blksize;
        len -= (plen) ? (blksize - plen) : blksize;
    }

    return 0;
}

/*
 * Socket Send Message
 */
static int spp_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
    struct sock *sk = sock->sk;
    struct spp_sock *spp = spp_sk(sk);
    struct sk_buff *skb;
    struct sockaddr_spp *usspp = (struct sockaddr_spp *)msg->msg_name;
    struct sockaddr_spp daddr;
    struct spphdr *hdr;
    struct crypto_cipher *tfm = 0;
    int rc,slen,pkttype,shf,blksize;
    int addr_len = msg->msg_namelen;

    /* Check that length is not too big */
    if(len > 0xFFFF)
        return -EMSGSIZE;

    /* Check if someone wants OOB data, cause we don't do it */
    if(msg->msg_flags & MSG_OOB)
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

    if(spp->device == NULL){
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
            goto out;
        }
        daddr.sspp_family = AF_SPP;
        daddr.sspp_addr = spp->d_addr;
    }

    /* Allocate encryption transform */
    tfm = crypto_alloc_cipher(SPP_ENCRYPTION_ALG_NAME, 0, 0);
    if(IS_ERR(tfm)) {
        printk("Failed to allocate encryption transform");
        goto out;
    }
    blksize = crypto_tfm_alg_blocksize(crypto_cipher_tfm(tfm));

    /* Set transform key */
    if(crypto_cipher_setkey(tfm, sysctl_spp_encryptionkey, strlen(sysctl_spp_encryptionkey))) {
        printk("Failed to set encryption key");
        goto out;
    }

    /* SPP header size, SPP data length, and encryption padding length */
    if(sysctl_spp_encrypt){
        slen = sizeof(struct spphdr) + len + blksize - (len % blksize);
    }
    else{
        slen = sizeof(struct spphdr) + len;
    }
    skb = sock_alloc_send_skb(sk, slen, (msg->msg_flags & MSG_DONTWAIT), &rc);
    if(!skb)
        goto out;

    skb->sk = sk;
    skb->dev = spp->device;
    skb->protocol = spp_type_trans(skb, spp->device);
    skb_reserve(skb, sizeof(struct spphdr));

    pkttype = 0; /* TODO: allow setting of packet type (TM/TC), I think this should be a socket option */
    shf = 0; /* TODO: Enable secondary header support */
    hdr = (struct spphdr *)skb_push(skb, sizeof(struct spphdr));
    hdr->fields = 0;
    hdr->fields = (hdr->fields << 1) | (pkttype ? 0x00000001 : 0x00000000); /* Packet Type - Can be TM or TC */
    hdr->fields = (hdr->fields << 1) | (shf ? 0x00000001 : 0x00000000); /* Second Header Field -> Currently should also be disabled */
    hdr->fields = (hdr->fields << 11) | daddr.sspp_addr.spp_apid; /* APID */
    hdr->fields = (hdr->fields << 2) | 0x00000003; /* We are unsegmented data */
    hdr->fields = (hdr->fields << 14) | 0x000000FF;
    hdr->fields = htonl(hdr->fields); /* Translates to the correct network endianness */
    if(sysctl_spp_encrypt){
        /* Encrypt to skb */
        hdr->pdl = htons(slen - 1 - sizeof(struct spphdr)); /* Subtract 1 from length as per spec -> Packet data Length (thus we also remove the header length) */
        rc = spp_encrypt_fromiovec(skb, (struct iovec *)msg->msg_iter.iov, len, tfm);
    }
    else {
        hdr->pdl = htons(len - 1); /* Subtract 1 from length as per spec */
        //rc = memcpy_fromiovec(skb_put(skb,len), msg->msg_iov,len);
        rc = copy_from_iter(skb_put(skb,len), len, &msg->msg_iter);
    }
    if(rc){
        kfree_skb(skb);
        rc = -EFAULT;
        goto out;
    }
    dev_queue_xmit(skb);
    rc = len;

out:
    if (tfm)
        crypto_free_cipher(tfm);
    release_sock(sk);
    return rc;
}

/*
 * Decrypt data from a sk_buff into an iovec.
 * Returns -EFAULT on error.
 */
static int spp_decrypt_toiovec(u8 *kdata, struct iov_iter iov, size_t len, struct crypto_cipher *tfm) {
    size_t copy;                                    /* bytes to copy */
    size_t offset = 0;                              /* iovec write offset */
    size_t blksize = crypto_cipher_blocksize(tfm);  /* Encryption blocksize */
    u8 buff[blksize];                               /* Decryption buffer */

    while (len > 0) {
        /* Decrypt to buffer */
        crypto_cipher_decrypt_one(tfm, buff, kdata);

        /* Write buffer to iovec */
        copy = min_t(size_t, len, blksize);
        //if(memcpy_toiovecend(iov, buff, offset, copy) != )
        if(copy_to_iter(buff,copy,&iov) != copy)
            return -EFAULT;

        /* Update counters */
        kdata += blksize;
        offset += blksize;
        len -= copy;
    }

    return 0;
}

/*
 * Socket Receive Message
 * TODO: Complete method with correct implementation
 */
static int spp_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags)
{
    struct sock *sk = sock->sk;
    unsigned int copied, offset;
    int rc = 0;
    struct sk_buff *skb;
    struct spphdr *hdr;
    unsigned int hdrfields;
    __be16 pdl;
    struct crypto_cipher *tfm = 0;

    lock_sock(sk);

    skb = skb_recv_datagram(sk, flags & ~MSG_DONTWAIT, flags & MSG_DONTWAIT, &rc);

    if(skb == NULL)
        goto out;

    copied = skb->len;
    offset = sizeof(struct spphdr);
    copied -= offset;
    if( copied > size){
        copied = size;
        msg->msg_flags |= MSG_TRUNC;
    }

    /* Set up decryption transform */
    tfm = crypto_alloc_cipher(SPP_ENCRYPTION_ALG_NAME, 0, 0);
    if(IS_ERR(tfm)) {
        printk("Failed to allocate decryption transform");
        goto out;
    }

    /* Set transform key */
    if(crypto_cipher_setkey(tfm, sysctl_spp_encryptionkey, strlen(sysctl_spp_encryptionkey))) {
        printk("Failed to set encryption key");
        goto out;
    }

    if(sysctl_spp_encrypt){
        spp_decrypt_toiovec(skb->data + offset, msg->msg_iter, copied, tfm);
    }
    else {
         skb_copy_datagram_msg(skb, offset, msg, copied);
    }

    if(msg->msg_namelen != 0){
        struct sockaddr_spp *addr = (struct sockaddr_spp *)msg->msg_name;
        addr->sspp_family = AF_SPP;
        hdr = (struct spphdr *)skb->data;
        hdrfields = ntohl(hdr->fields);
        /* TODO: Retrieve all fields from header */
        addr->sspp_addr.spp_apid = ((hdrfields & 0x07FF0000) >> 16); /* Retrieve APID */
        pdl = ntohs(hdr->pdl) + 1; /* Restore the full length by adding that 1 back */
        /* TODO: Add check of the Packet Data Length for validity */
        msg->msg_namelen = sizeof(struct sockaddr_spp);
    }
    skb_free_datagram(sk,skb);
    rc = copied;

out:
    if (tfm)
        crypto_free_cipher(tfm);
    release_sock(sk);
    return rc;
}

/*
 * Handle SPP ioctl() calls
 * TODO: Define method behavior
 * TODO: Complete implementation
 */
static int spp_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
    struct sock *sk = sock->sk;
    void __user *argp = (void __user *)arg;
    struct ifreq ifr;
    struct sockaddr_spp sin_orig;
    struct sockaddr_spp *sin = (struct sockaddr_spp *)&ifr.ifr_addr;
    struct spp_dev *spp_device;
    struct spp_ifaddr **ifap = NULL;
    struct spp_ifaddr *ifa = NULL;
    struct net_device *dev;
    int rc = -EFAULT;
    mutex_lock(&spp_mutex);
    /* Bring the user request into kernel space */
    if (copy_from_user(&ifr, argp, sizeof(struct ifreq)))
        goto out;
    ifr.ifr_name[IFNAMSIZ - 1] = 0; /* Why? */

    memcpy(&sin_orig,sin, sizeof(*sin)); /* Copy the old address for comparison */

    rtnl_lock();

    rc = -ENODEV;
    dev = __dev_get_by_name(&init_net, ifr.ifr_name);

    if(!dev)
        goto done;
    /*  TODO: Fix this so it no longer accidentally modifies spp_device->ifa_list
     * spp_device = __spp_dev_get_rtnl(dev);
     if(spp_device){
     for(ifap = &spp_device->ifa_list; (ifa = *ifap) != NULL; ifap = &ifa->ifa_next)
     {
     if(!strcmp(ifr.ifr_name, ifa->ifa_label))
     break;
     }
     }*/
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
                              /* TODO: Add multiple return */
                              memset(sin, 0, sizeof(*sin));
                              sin->sspp_family = AF_SPP;
                              sin->sspp_addr.spp_apid = ifa->ifa_local;
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
                                  printk(KERN_INFO "SPP: IOCTL: Returned from allocating IFA\n");
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
    mutex_unlock(&spp_mutex);
done:
    rtnl_unlock();
out:
    rtnl_unlock();
    return rc;
rarok:
    rtnl_unlock();
    rc = copy_to_user(argp, &ifr, sizeof(struct ifreq)) ? -EFAULT : 0;
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
