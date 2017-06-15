/*
 * Jacob Holtom - SPP
 *
 */

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
