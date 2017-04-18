// Copyright 2017 by Jacob Holtom and the Brigham Young University Passive
// Inspection CubeSat Team (BYU PICS)
// All rights reserved
//
// Authors: Jacob Holtom
// File:    slspp.c
//
// References:
//     Elysium Radio User Manual (elysium_manual.pdf), September 16th 2016
//     Linux Device Drivers - O'Reilly
//
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

static int sl_alloc_bufs(struct slspp *sl, int mtu) { /* METHOD STUB */
}

static void sl_free_bufs(struct slspp *sl) { /* METHOD STUB */
}

static int sl_realloc_bufs(struct slspp *sl, int mtu) { /* METHOD STUB */
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

}

static void sl_encaps(struct slspp *sl, unsigned char *icp, int len)
{

}

static void slspp_write_wakeup(struct tty_struct *tty)
{

}

static void sl_tx_timeout(struct net_device *dev)
{

}

static netdev_tx_t sl_xmit(struct sk_buff *skb, struct net_device *dev)
{

}

static int sl_close(struct net_device *dev)
{

}

static int sl_open(struct net_device *dev)
{

}

static int sl_change_mtu(struct net_device *dev, int new_mtu)
{

}

static struct net_device_stats * sl_get_stats(struct net_device *dev)
{

}

static int sl_init(struct net_device *dev)
{

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

}

static void slspp_receive_buf(struct tty_struct *tty, const unsigned char *cp, char *fp, int count)
{

}

static void sl_sync(void)
{

}

static struct slspp *sl_alloc(dev_t line)
{

}

static int slspp_open(struct tty_struct *tty)
{

}

static void slspp_close(struct tty_struct *tty)
{

}

static int slspp_hangup(struct tty_struct *tty){
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
                       unsigned int cmd, unsigned long arg) { /* METHOD STUB */
}

static int sl_ioctl(struct net_device *dev, struct ifreq *rq,
                    int cmd) { /* METHOD STUB */
}

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

static int __init slspp_init(void) { /* METHOD STUB */
}

static void __exit slspp_exit(void) { /* METHOD STUB */
}

module_init(slspp_init);
module_exit(slspp_exit);

/* Module licensing
 *
 * MODULE_LICENSE("");
 * MODULE_ALIAS_LDSIC(N_SLSPP);
 */
