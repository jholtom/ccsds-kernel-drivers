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
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/if_slip.h>
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

static struct net_device **slip_devs;

static int slip_maxdev = SL_NRUNIT;
module_param(slip_maxdev, int, 0);
MODULE_PARM_DESC(slip_maxdev, "Maximum number of slspp devices");

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

static int slspp_esc(unsigned char *s, unsigned char *d, int len)
{

}
static void slspp_unesc(struct slspp *sl, unsignec char s) 
{

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

static int __init slip_init(void) { /* METHOD STUB */
}

static void __exit slip_exit(void) { /* METHOD STUB */
}

module_init(slspp_init);
module_exit(slspp_exit);

/* Module licensing
 *
 * MODULE_LICENSE("");
 * MODULE_ALIAS_LDSIC(N_SLSPP);
 */
