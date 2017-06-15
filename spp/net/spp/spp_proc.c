/* SPP Layer
 */

#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/spp.h>

#ifdef CONFIG_PROC_FS
/* Implementations of procfs statistics and accounting functions */
static __inline__ struct sock *spp_get_socket_idx(loff_t pos)
{
    struct sock *s;
    struct hlist_node *node;
    sk_for_each(s, node, &spp_list)
        if(!pos--)
            goto found;
    s = NULL;
found:
    return s;
}
static void *spp_seq_socket_start(struct seq_file *seq, loff_t *pos) __acquires(spp_list_lock)
{
    loff_t l = *pos;
    read_lock_bh(&spp_list_lock);
    return l ? spp_get_socket_idx(--l) : SEQ_START_TOKEN;
}
static void *spp_seq_socket_next(struct seq_file *seq, void *v, loff_t *pos)
{
    struct sock *s;

    ++*pos;
    if (v == SEQ_START_TOKEN){
        s = sk_head(&spp_list);
        goto out;
    }
    s = sk_next(v);
out:
    return s;
}
static void spp_seq_socket_stop(struct seq_file *seq, void *v) __releases(spp_list_lock)
{
    read_unlock_bh(&spp_list_lock);
}
static int spp_seq_socket_show(struct seq_file *seq, void *v)
{
    return 0;
}

static const struct seq_operations spp_seq_socket_ops = {
    .start = spp_seq_socket_start,
    .next = spp_seq_socket_next,
    .stop = spp_seq_socket_stop,
    .show = spp_seq_socket_show,
};

static int spp_seq_socket_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &spp_seq_socket_ops);
}

static const struct file_operations spp_seq_socket_fops = {
    .owner = THIS_MODULE,
    .open = spp_seq_socket_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release,
};

static struct proc_dir_entry *spp_proc_dir;
int __init spp_proc_init()
{
    struct proc_dir_entry *p;
    int rc = -ENOMEM;
    spp_proc_dir = proc_mkdir("spp", init_net.proc_net);
    if(!spp_proc_dir)
        goto out;
    p = proc_create("socket", S_IRUGO, spp_proc_dir, &spp_seq_socket_fops);
    if(!p)
        goto out_socket;
    rc = 0;
out:
    return rc;
out_socket:
    remove_proc_entry("socket", spp_proc_dir);
    goto out;
}

void __exit spp_proc_exit(void)
{
    remove_proc_entry("socket", spp_proc_dir);
    remove_proc_entry("spp", init_net.proc_net);
}

#else /* CONFIG_PROC_FS */
int __init x25_proc_init(void)
{
	return 0;
}

void __exit x25_proc_exit(void)
{
}
#endif /* CONFIG_PROC_FS */
