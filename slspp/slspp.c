#define SL_CHECK_TRANSMIT
#include <linux/module.h>
#include <linux/moduleparam.h>

#include "slspp.h"
#include <asm/system.h>
#include <asm/uaccess.h>
#include <linux/bitops.h>
#include <linux/compat.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/mm.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/tty.h>
/* Probably will need this later, but can do without for now
#ifdef CONFIG_SPP
#include <linux/spp.h>
#endif
*/

#define SLSPP_VERSION "0.0.1"

static struct net_device **slspp_devs;

static int slspp_maxdev = SL_NRUNIT;
module_param(slspp_maxdev, int, 0);
MODULE_PARM_DESC(slspp_maxdev, "Maximum number of slspp devices");

static int slspp_esc(unsigned char *p, unsigned char *d, int len);
static void slspp_unesc(struct slspp *sl, unsigned char c);

/*
 * Buffer admin stuff:
 * sl_alloc_bufs()
 * sl_free_bufs()
 * sl_reallaoc_bufs()
 *
 * also sl_realloc_bufs isn't the same as sl_free_bufs + sl_alloc_bufs because
 * it provides atomicity and reallocation on the current device */

static int sl_alloc_bufs(struct slspp *sl, int mtu)
{
    int err = -ENOBUFS;
    unsigned long len;
    char *rbuff = NULL;
    char *xbuff = NULL;

    len = mtu * 2;
    if (len < 576 * 2)
        len = 576 * 2;
    rbuff = kmalloc(len + 4, GFP_KERNEL);
    if (rbuff == NULL)
        goto err_exit;
    xbuff = kmalloc(len + 4, GFP_KERNEL);
    if (xbuff == NULL)
        goto err_exit;
    spin_lock_bh(&sl->lock);
    if (sl->tty == NULL){
        spin_unlock_bh(&sl->lock);
        err = -ENODEV;
        goto err_exit;
    }
    sl->mtu = mtu;
    sl->buffsize = len;
    sl->rcount = 0;
    sl->xleft = 0;
    rbuff = xchg(&sl->rbuff, rbuff);
    xbuff = xchg(&sl->xbuff, xbuff);
    spin_unlock_bh(&sl->lock);
    err = 0;

err_exit:
    kfree(xbuff);
    kfree(rbuff);
    return err;
}

static void sl_free_bufs(struct slspp *sl)
{
    kfree(xchg(&sl->rbuff, NULL));
    kfree(xchg(&sl->xbuff, NULL));
}

static int sl_realloc_bufs(struct slspp *sl, int mtu) 
{
    int err = 0;
    struct net_device *dev = sl->dev;
    unsigned char *xbuff, *rbuff;
    int len = mtu * 2;
    if (len < 576 * 2)
        len = 576 * 2;

    xbuff = kmalloc(len + 4, GFP_ATOMIC);
    rbuff = kmalloc(len + 4, GFP_ATOMIC);

    if (xbuff == NULL || rbuff == NULL)  {
        if (mtu >= sl->mtu) {
            printk(KERN_WARNING "%s: unable to grow slspp buffers, MTU change cancelled.\n",
                    dev->name);
            err = -ENOBUFS;
        }
        goto done;
    }
    spin_lock_bh(&sl->lock);

    err = -ENODEV;
    if (sl->tty == NULL)
        goto done_on_bh;

    xbuff    = xchg(&sl->xbuff, xbuff);
    rbuff    = xchg(&sl->rbuff, rbuff);
    if (sl->xleft)  {
        if (sl->xleft <= len)  {
            memcpy(sl->xbuff, sl->xhead, sl->xleft);
        } else  {
            sl->xleft = 0;
            sl->tx_dropped++;
        }
    }
    sl->xhead = sl->xbuff;

    if (sl->rcount)  {
        if (sl->rcount <= len) {
            memcpy(sl->rbuff, rbuff, sl->rcount);
        } else  {
            sl->rcount = 0;
            sl->rx_over_errors++;
            set_bit(SLF_ERROR, &sl->flags);
        }
    }
    sl->mtu      = mtu;
    dev->mtu      = mtu;
    sl->buffsize = len;
    err = 0;

done_on_bh:
    spin_unlock_bh(&sl->lock);

done:
    kfree(xbuff);
    kfree(rbuff);
    return err;
}

static inline void sl_lock(struct slspp *sl)
{
    netif_stop_queue(sl->dev);
}

static inline void sl_unlock(struct slspp *sl)
{
    netif_wake_queue(sl->dev);
}

static void sl_bump(struct slspp *sl)
{
    struct sk_buff *skb;
    int count;

    count = sl->rcount;
    sl->rx_bytes += count;

    skb = dev_alloc_skb(count);
    if (skb == NULL) {
        printk(KERN_WARNING "%s: memory squeeze, dropping packet.\n", sl->dev->name);
        sl->rx_dropped++;
        return;
    }
    skb->dev = sl->dev;
    memcpy(skb_put(skb, count), sl->rbuff, count);
    skb_reset_mac_header(skb);
    skb->protocol = htons(ETH_P_IP);
    netif_rx(skb);
    sl->rx_packets++;
}

static void sl_encaps(struct slspp *sl, unsigned char *icp, int len)
{
    unsigned char *p;
    int actual, count;

    if (len > sl->mtu)
    {
        printk(KERN_WARNING "%s: truncating oversized packet!\n", sl->dev->name);
        sl->tx_dropped++;
        sl_unlock(sl);
        return;
    }
    p = icp;
    count = slspp_esc(p, (unsigned char *) sl->xbuff, len);
    set_bit(TTY_DO_WRITE_WAKEUP, &sl->tty->flags);
    actual = sl->tty->ops->write(sl->tty, sl->xbuff, count);
#ifdef SL_CHECK_TRANSMIT
    sl->dev->trans_start = jiffies;
#endif
    sl->xleft = count - actual;
    sl->xhead = sl->xbuff + actual;
}

static void slspp_write_wakeup(struct tty_struct *tty)
{
    int actual;
    struct slspp *sl = tty->disc_data;

    if (!sl || sl->magic != SLSPP_MAGIC || !netif_running(sl->dev))
        return;
    if (sl->xleft <=0)
    {
        sl->tx_packets++;
        clear_bit(TTY_DO_WRITE_WAKEUP, &tty->flags);
        sl_unlock(sl);
        return;
    }
    actual = tty->ops->write(tty, sl->xhead, xl->xleft);
    sl->xleft -= actual;
    xl->xhead += actual;
}

static void sl_tx_timeout(struct net_device *dev)
{
    struct slspp *sl = netdev_priv(dev);

    spin_lock(&sl->lock);

    if (netif_queue_stopped(dev)) {
        if (!netif_running(dev))
            goto out;

#ifdef SL_CHECK_TRANSMIT
        if (time_before(jiffies, dev->trans_start + 20 * HZ))  {
            goto out;
        }
        printk(KERN_WARNING "%s: transmit timed out, %s?\n",
                dev->name,
                (tty_chars_in_buffer(sl->tty) || sl->xleft) ?
                "bad line quality" : "driver error");
        sl->xleft = 0;
        clear_bit(TTY_DO_WRITE_WAKEUP, &sl->tty->flags);
        sl_unlock(sl);
#endif
    }
out:
    spin_unlock(&sl->lock);

}

static netdev_tx_t sl_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct slspp *sl = netdev_priv(dev);
    spin_lock(&sl->lock);
    if (!netif_running(dev)) {
        spin_unlock(&sl->lock);
        printk(KERN_WARNING "%s: transmit call when interface is down\n", dev->name);
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }
    if (sl->tty == NULL)
    {
        spin_unlock(&sl->lock);
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }
    sl_lock(sl);
    sl->tx_bytes += skb->len;
    sl_encaps(sl,skb->data, skb->len);
    spin_unlock(&sl->lock);
    dev_kfree_skb(skb);
    return NETDEV_TX_OK;
}

static int sl_close(struct net_device *dev)
{
    struct slspp *sl = netdev_priv(dev);
    spin_lock_bh(&sl->lock);
    if (sl->tty)
        clear_bit(TTY_DO_WRITE_WAKEUP, &sl->tty->flags);
    netif_stop_queue(dev);
    sl->rcount = 0;
    sl->xleft = 0;
    spin_unlock_bh(&sl->lock);
    return 0;
}

static int sl_open(struct net_device *dev)
{
    struct slspp *sl = netdev_priv(dev);
    if (sl->tty == NULL)
        return -ENODEV;
    sl->flags &= (1 << SLF_INUSE);
    netif_start_queue(dev);
    return 0;
}

static int sl_change_mtu(struct net_device *dev, int new_mtu)
{
    struct slspp *sl = netdev_priv(dev);

    if (new_mtu < 68 || new_mtu > 65534)
        return -EINVAL;
    if(new_mtu != dev->mtu)
        return sl_realloc_bufs(sl, new_mtu);
    return 0;
}

static struct net_device_stats * sl_get_stats(struct net_device *dev)
{
    static struct net_device_stats stats;
    struct slspp *sl = netdev_priv(dev);
    memset(&stats, 0, sizeof(struct net_device_stats));

    stats.rx_packets     = sl->rx_packets;
    stats.tx_packets     = sl->tx_packets;
    stats.rx_bytes	     = sl->rx_bytes;
    stats.tx_bytes	     = sl->tx_bytes;
    stats.rx_dropped     = sl->rx_dropped;
    stats.tx_dropped     = sl->tx_dropped;
    stats.tx_errors      = sl->tx_errors;
    stats.rx_errors      = sl->rx_errors;
    stats.rx_over_errors = sl->rx_over_errors;
    return (&stats);
}

static int sl_init(struct net_device *dev)
{
    struct slspp *sl = netdev_priv(dev);
    dev->mtu = sl->mtu;
    dev->type = ARPHRD_SLSPP + sl->mode; /* Change this to a new ARPHRD dummy number */
#ifdef SL_CHECK_TRANSMIT
    dev->watchdog_timeo = 20*HZ;
#endif
    return 0;
}

static void sl_uninit(struct net_device *dev)
{
    struct slspp *sl = netdev_priv(dev);
    sl_free_bufs(sl);
}

static void sl_free_netdev(struct net_device *dev)
{
    int i = dev->base_addr;
    free_netdev(dev);
    slspp_devs[i] = NULL;
}

static const struct net_device_ops sl_netdev_ops = {
    .ndo_init		= sl_init,
    .ndo_uninit	  	= sl_uninit,
    .ndo_open		= sl_open,
    .ndo_stop		= sl_close,
    .ndo_start_xmit		= sl_xmit,
    .ndo_get_stats	        = sl_get_stats,
    .ndo_change_mtu		= sl_change_mtu,
    .ndo_tx_timeout		= sl_tx_timeout,
    .ndo_do_ioctl           = sl_ioctl
};

static void sl_setup(struct net_device *dev)
{
    dev->netdev_ops = &sl_netdev_ops;
    dev->destructor = sl_free_netdev;
    dev->hard_header_len = 0;
    dev->addr_len = 0;
    dev->tx_queue_len = 10;
    dev->flags = IFF_NOARP|IFF_POINTTOPOINT;
}

static void slspp_receive_buf(struct tty_struct *tty, const unsigned char *cp, char *fp, int count)
{
    struct slspp *sl = tty->disc_data;
    if (!sl || sl->magic != SLSPP_MAGIC || !netif_running(sl->dev))
	return;
    while (count--) {
        if(fp && *fp++) {
            if(!test_and_set_bit(SLF_ERROR,&sl->flags))
                    sl->rx_errors++;
            cp++;
            continue;
        }
        slspp_unesc(sl, *cp++);
    }
}

static void sl_sync(void)
{
    int i;
    struct net_device *dev;
    struct slspp *sl;
    for (i = 0; i< slspp_maxdev; i++){
        dev = slspp_devs[i];
        if (dev == NULL)
            break;
        sl = netdev_priv(dev);
        if (sl->tty || sl->leased)
            continue;
        if (dev->flags & IFF_UP)
            dev_close(dev);
    }
}

static struct slspp *sl_alloc(dev_t line)
{
	int i;
	struct net_device *dev = NULL;
	struct slspp       *sl;

	if (slspp_devs == NULL)
		return NULL;	/* Master array missing ! */

	for (i = 0; i < slspp_maxdev; i++) {
		dev = slspp_devs[i];
		if (dev == NULL)
			break;
	}
	/* Sorry, too many, all slots in use */
	if (i >= slspp_maxdev)
		return NULL;

	if (dev) {
		sl = netdev_priv(dev);
		if (test_bit(SLF_INUSE, &sl->flags)) {
			unregister_netdevice(dev);
			dev = NULL;
			slspp_devs[i] = NULL;
		}
	}

	if (!dev) {
		char name[IFNAMSIZ];
		sprintf(name, "sl%d", i);

		dev = alloc_netdev(sizeof(*sl), name, sl_setup);
		if (!dev)
			return NULL;
		dev->base_addr  = i;
	}

	sl = netdev_priv(dev);

	/* Initialize channel control data */
	sl->magic       = SLSPP_MAGIC;
	sl->dev	      	= dev;
	spin_lock_init(&sl->lock);
	sl->mode        = SL_MODE_DEFAULT;
	slspp_devs[i] = dev;
	return sl;

}

static int slspp_open(struct tty_struct *tty)
{
	struct slspp *sl;
	int err;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (tty->ops->write == NULL)
		return -EOPNOTSUPP;

	rtnl_lock();
	sl_sync();
	sl = tty->disc_data;
	err = -EEXIST;
	if (sl && sl->magic == SLSPP_MAGIC)
		goto err_exit;

	err = -ENFILE;
	sl = sl_alloc(tty_devnum(tty));
	if (sl == NULL)
		goto err_exit;

	sl->tty = tty;
	tty->disc_data = sl;
	sl->line = tty_devnum(tty);
	sl->pid = current->pid;

	if (!test_bit(SLF_INUSE, &sl->flags)) {
		err = sl_alloc_bufs(sl, SL_MTU);
		if (err)
			goto err_free_chan;
		set_bit(SLF_INUSE, &sl->flags);
		err = register_netdevice(sl->dev);
		if (err)
			goto err_free_bufs;
	}
	rtnl_unlock();
	tty->receive_room = 65536;	/* We don't flow control */
	return sl->dev->base_addr;

err_free_bufs:
	sl_free_bufs(sl);

err_free_chan:
	sl->tty = NULL;
	tty->disc_data = NULL;
	clear_bit(SLF_INUSE, &sl->flags);

err_exit:
	rtnl_unlock();

	return err;
}

static void slspp_close(struct tty_struct *tty)
{
    struct slspp *sl = tty->disc_data;
    if (!sl || sl->magic != SLSPP_MAGIC || sl->tty != tty)
        return;
    tty->disc_data = NULL;
    sl->tty = NULL;
    if (!sl->leased)
        sl->line = 0;
    unregister_netdev(sl->dev);
}

static int slspp_hangup(struct tty_struct *tty)
{
    slspp_close(tty);
    return 0;
}

static int slspp_esc(unsigned char *s, unsigned char *d, int len)
{
    unsigned char *ptr = d;
    unsigned char c;

    *ptr++ = END; // Clear the receiver by sending an initial END char

    /* For each byte in the packet, send the char sequence */
    while(len-- > 0){
        switch (c = *s++){
            case END:
                *ptr++ = ESC;
                *ptr++ = ESC_END;
                break;
            case ESC:
                *ptr++ = ESC;
                *ptr++ = ESC_ESC;
                break;
            default:
                *ptr++ = c;
                break;
        }
    }
    *ptr++ = END;
    return (ptr - d);

}

static void slspp_unesc(struct slspp *sl, unsignec char s) 
{
    switch (s) {
        case END:
            if (!test_and_clear_bit(SLF_ERROR, &sl->flags) &&
                    (sl->rcount > 2))
                sl_bump(sl);
            clear_bit(SLF_ESCAPE, &sl->flags);
            sl->rcount = 0;
            return;

        case ESC:
            set_bit(SLF_ESCAPE, &sl->flags);
            return;
        case ESC_ESC:
            if (test_and_clear_bit(SLF_ESCAPE, &sl->flags))
                s = ESC;
            break;
        case ESC_END:
            if (test_and_clear_bit(SLF_ESCAPE, &sl->flags))
                s = END;
            break;
    }
    if (!test_bit(SLF_ERROR, &sl->flags))  {
        if (sl->rcount < sl->buffsize)  {
            sl->rbuff[sl->rcount++] = s;
            return;
        }
        sl->rx_over_errors++;
        set_bit(SLF_ERROR, &sl->flags);
    }
}

static int slspp_ioctl(struct tty_struct *tty, struct file *file,
        unsigned int cmd, unsigned long arg)
{
    struct slspp *sl = tty->disc_data;
    unsigned int tmp;
    int __user *p = (int __user *)arg;
    if (!sl || sl->magic != SLSPP_MAGIC)
        return -EINVAL;
    switch(cmd) {
	case SIOCGIFNAME:
		tmp = strlen(sl->dev->name) + 1;
		if (copy_to_user((void __user *)arg, sl->dev->name, tmp))
			return -EFAULT;
		return 0;

	case SIOCGIFENCAP:
		if (put_user(sl->mode, p))
			return -EFAULT;
		return 0;

	case SIOCSIFENCAP:
		if (get_user(tmp, p))
			return -EFAULT;
/*		if ((tmp & (SL_MODE_ADAPTIVE | SL_MODE_CSLIP)) ==
		    (SL_MODE_ADAPTIVE | SL_MODE_CSLIP))
			 return -EINVAL; 
			tmp &= ~SL_MODE_ADAPTIVE;
		sl->mode = tmp;
		sl->dev->type = ARPHRD_SLIP + sl->mode;
		return 0;*/
                return -EINVAL; /* Currently no supported encapsulation type changes */

	case SIOCSIFHWADDR:
		return -EINVAL;

	default:
		return tty_mode_ioctl(tty, file, cmd, arg);
    }
}

#ifdef CONFIG_COMPAT
static long slspp_compat_ioctl(struct tty_struct *tty, struct file *file,
					unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case SIOCGIFNAME:
	case SIOCGIFENCAP:
	case SIOCSIFENCAP:
	case SIOCSIFHWADDR:
	case SIOCSKEEPALIVE:
	case SIOCGKEEPALIVE:
	case SIOCSOUTFILL:
	case SIOCGOUTFILL:
		return slspp_ioctl(tty, file, cmd,
				  (unsigned long)compat_ptr(arg));
	}

	return -ENOIOCTLCMD;
}
#endif

static struct tty_ldisc_ops sl_ldsic = {.owner = THIS_MODULE,
    .magic = TTY_LDISC_MAGIC,
    .name = "slspp",
    .open = slspp_open,
    .close = slspp_close,
    .hangup = slspp_hangup,
    .ioctl = slspp_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = slspp_compat_ioctl,
#endif
    .receive_buf = slspp_receive_buf,
    .write_wakeup = slspp_write_wakeup};

static int __init slspp_init(void) 
{
    int status;

    if (slip_maxdev < 4)
        slip_maxdev = 4; /* because I want at least 4 devices */
    printk(KERN_INFO "SLSPP: version %s (dynamic chanels, max=%d)"".\n", SLSPP_VERISON, slspp_maxdev);
    slspp_devs = kzalloc(sizeof(struct net_device*)*slspp_maxdev, GFP_KERNEL);
    if(!slspp_devs)
    {
        printk(KERN_ERR "SLSPP: Cannot allocate slspp devices array.\n");
        return -ENOMEM;
    }
	status = tty_register_ldisc(N_SLIP, &sl_ldisc);
	if (status != 0) {
		printk(KERN_ERR "SLSPP: can't register line discipline (err = %d)\n", status);
		kfree(slspp_devs);
	}
	return status;
}

static void __exit slspp_exit(void)
{
    int i;
    struct net_device *dev;
    struct slspp *sl;
    unsigned long timeout = jiffies + HZ;
    int busy = 0;

    if(slspp_devs == NULL)
        return;
    do {
        if(busy)
            msleep_interruptible(100);
        busy = 0;
        for (i = 0; i < slspp_maxdev; i++)}{
            dev = slspp_devs[i];
            if (!dev) continue;
            sl = netdev_priv(dev);
            spin_lock_bh(&sl->lock);
            if (sl->tty) {
                busy++;
                tty_hangup(sl->tty);
            }
            spin_unlock_bh(&sl->lock);
        }

    } while (busy && time_before(jiffies, timeout));
	for (i = 0; i < slspp_maxdev; i++) {
		dev = slspp_devs[i];
		if (!dev)
			continue;
		slspp_devs[i] = NULL;
		sl = netdev_priv(dev);
		if (sl->tty) {
			printk(KERN_ERR "%s: tty discipline still running\n",
			       dev->name);
			dev->destructor = NULL;
		}

		unregister_netdev(dev);
	}
	kfree(slspp_devs);
	slspp_devs = NULL;
	i = tty_unregister_ldisc(N_SLIP);
	if (i != 0)
		printk(KERN_ERR "SLSPP: can't unregister line discipline (err = %d)\n", i);
}

module_init(slspp_init);
module_exit(slspp_exit);

MODULE_LICENSE("GPL");
MODULE_ALIAS_LDSIC(N_SLIP);
