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

int spp_kiss_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *ptype, struct net_device *orig_dev)
{
    return 0;
}
