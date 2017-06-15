/*
 * Jacob Holtom - SPP
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
    struct spp_sock *spp = spp_sock(sk);
    spp_clear_queues(sk);

    spp->causediag.cause = cause;
    spp->causediag.diagnostic = diagnostic;

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
