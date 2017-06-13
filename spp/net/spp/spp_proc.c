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

/*
 * Display SPP status information
 * TODO: Complete method, test behavior
 */
static int spp_info_show(struct seq_file *seq, void *v)
{
    char buf[11], rsbuf[11];

    if(v == SEQ_START_TOKEN)
        seq_puts(seq, "dest_addr  src_addr  dev   lci  st vs vr va   t  t1  t2  t3  hb    idle Snd-Q Rcv-Q inode\n"); /* Check formatting as it applies to the rest of my prints */
    else {
        struct sock *s = sk_entry(v);
        struct spp_sock *spp = spp_sk(s);
        const char *devname, *address;
        /*TODO: define dev */
        if (!dev)
            devname = "???";
        else
            devname = dev->name;
        spp2ascii(rsbuf, &spp->d_addr)
        seq_printf(seq, "%-10s ", rsbuf); /*Prints destination address */

        seq_printf(seq, "%-10s %-5s %3.3X  %d  %d  %d  %d %3lu %3lu %3lu %3lu %3lu %3lu/%03lu %5d %5d %ld\n", spp2ascii(rsbuf, &spp->s_addr),
                devname,
                spp->lci & 0x0FFF,
                spp->state,
                spp->vs,
                spp->vr,
                spp->va,
                /* TODO: take care of timer prints here*/
                sk_wmem_alloc_get(s),
                sk_rmem_alloc_get(s), 
                s->sk_socket ? SOCK_INODE(s->sk_socket)->i_inode : 0L);

    }
    return 0;
}

/*
 * Moves to next info object
 */
static void *spp_info_next(struct seq_file *seq, void *v, loff_t *pos)
{
    return seq_hlist_next(v, &spp_list, pos);
}

/*
 * Begins the process of spitting out info
 */
static void *spp_info_start(struct seq_file *seq, loff_t *pos) __acquires(spp_list_lock)
{
    spin_lock_bh(&spp_list_lock); /* Acquires lock on socket list */
    return seq_hlist_start_head(&spp_list, *pos); /* Begins moving through the list */
}

/*
 * Terminates the information process 
 */
static void spp_info_stop(struct seq_file *seq, void *v) __releases(spp_list_lock)
{
    spin_unlock_bh(&spp_list_lock); /* Release lock on socket list */
}

/* 
 * Sequence Operations kernel object
 */
static const struct seq_operations spp_info_seqops = {
    .start = spp_info_start,
    .next = spp_info_next,
    .stop = spp_info_stop,
    .show = spp_info_show,
};

/*
 * Opens file representation to feed info into
 */
static int spp_info_open(struct inode *inode, struct file *file){
    return seq_open(file, &spp_info_seqops); /* Open up file */
}

/*
 * File operations kernel object
 */
static const struct file_operations spp_info_fops = {
    .owner = THIS_MODULE,
    .open = spp_info_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release,
};
#endif /* CONFIG_PROC_FS */
