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

int sysctl_spp_window_size = SPP_DEFAULT_WINDOW_SIZE; //Who knows if I need a window, just put it here in case I do.

HLIST_HEAD(spp_list);
DEFINE_SPINLOCK(spp_list_lock);

spp_address spp_addr;

char *spp2ascii(char *buf, const spp_address *addr)
{
    //Generate a human readable version of this int
}

int sppcmp(spp_address *addr1, spp_address *addr2)
{
    if(addr1->spp_apid == addr2->spp_apid)
	    return 0;
    else
	    return 1;
}

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
    /* TODO: implement socket listener */
}

/* Handle Device Status changes */
static int spp_device_event(struct notifier_block *this, unsigned long event, void *ptr)
{

}

static int spp_info_show(struct seq_file *seq, void *v)
{
    char buf[11], rsbuf[11];

    if(v == SEQ_START_TOKEN)
            seq_puts(seq, ""); /* TODO: fill out with format */
    else {
        /* TODO: Fill with logic */ 
    }
    return 0;
}

static void *spp_info_next(struct seq_file *seq, void *v, loff_t *pos)
{
    return seq_hlist_next(v, &spp_list, pos);
}

static void *spp_info_start(struct seq_file *seq, loff_t *pos) __acquires(spp_list_lock)
{

}

static void spp_info_stop(struct seq_file *seq, void *v) __releases(spp_list_lock)
{

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
};  //This is needed if CONFIG_PROC_FS is true...

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
MODULE_LICENSE("GPL");
MODULE_ALIAS_NETPROTO(PF_SPP);

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
