/*
 * Jacob Holtom
 *
 * CCSDS Space Packet Protocol
 */

/*
 *
 * Insert large string of appropriate includes here
 *
 */

static const struct proto_ops spp_proto_ops;

/*
 *
 * Methods
 *
 */

/* 
 * Structs for initilaization
 */

static const struct file_operations spp_info_fops = {
    .owner = THIS_MODULE,
    .open = spp_info_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release,
};  //This is need if CONFIG_PROC_FS is true...

static const struct net_proto_family spp_family_ops = {
    .family = PF_SPP,
    .create = spp_create,
    .owner = THIS_MODULE,
};

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

static int __init spp_init(void)
{

}
module_init(spp_init);

MODULE_AUTHOR("Jacob Holtom <jacob@holtom.me>");
MODULE_DESCRIPTION("The CCSDS Space Packet Protocol");
MODULE_LICENSE("GPL"); //This kills me inside.
MODULE_ALIAS_NETPROTO(PF_SPP);

static void __exit spp_exit(void)
{

}
module_exit(spp_exit);
