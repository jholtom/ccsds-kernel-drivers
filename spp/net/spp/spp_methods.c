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
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/spp.h>

void spp_clear_queues(struct sock *sk)
{
    struct spp_sock *spp = spp_sk(sk);

    skb_queue_purge(&sk->sk_write_queue);
    skb_queue_purge(&spp->interrupt_in_queue);
    skb_queue_purge(&spp->interrupt_out_queue);
    skb_queue_purge(&spp->fragment_queue);
}

void spp_disconnect(struct sock *sk, int reason, unsigned char cause, unsigned char diagnostic){
    struct spp_sock *spp = spp_sk(sk);
    spp_clear_queues(sk);

    spp->cause = cause;
    spp->diagnostic = diagnostic;

    sk->sk_state = TCP_CLOSE;
    sk->sk_err = reason;
    sk->sk_shutdown |= SEND_SHUTDOWN;

    if(!sock_flag(sk, SOCK_DEAD)){
        sk->sk_state_change(sk);
        sock_set_flag(sk, SOCK_DEAD);
    }
}

int spp_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *ptype, struct net_device *orig_dev)
{
    spp_address dest = { 0 };
    struct sock *sk;
    int type;
    int seqflags;
    unsigned int hdrfields = 0;
    struct spphdr *hdr;
    int rc = 0;
    skb_orphan(skb); /* Orphan it from everyone else, so its ours now, muahaha */
    if(!net_eq(dev_net(dev), &init_net)){
        kfree_skb(skb);
        printk("SPP: spp_rcv: SPP device and the device that gave us the packet we're not the same...I died\n");
        return 0;
    }
    hdr = (struct spphdr *)skb->data;
    hdrfields = ntohl(hdr->fields);
    type = ((hdrfields & 0x10000000) >> 28);
    dest.spp_apid =  ((hdrfields & 0x07FF0000) >> 16);
    seqflags = ((hdrfields & 0x00C000) >> 14);
    /* We are an unsegmented frame for now
     * TODO: implement frame segmentation */
    if(1){
        sk = spp_get_socket(&dest, SOCK_DGRAM); /*TODO: add support to find the correct version with the type flag as well */
        if(sk != NULL){
            bh_lock_sock(sk);
            if(atomic_read(&sk->sk_rmem_alloc) >= sk->sk_rcvbuf){
                printk(KERN_INFO "SPP: spp_rcv: Too big to fit in buffer, bailing out\n");
                kfree_skb(skb);
            } else {
                int err;
                err = sock_queue_rcv_skb(sk,skb);
                if(err != 0){
                    printk(KERN_INFO "SPP: spp_rcv: Failed to send it off, freeing.\n");
                    kfree(skb);
                }
            }
        } else {
            kfree_skb(skb);
        }
        bh_unlock_sock(sk);
        sock_put(sk);
    }
out:
    return rc;
}
