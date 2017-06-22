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
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/spinlock.h>
#include <net/spp.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/init.h>

spp_dev *spp_dev_list;
DEFINE_SPINLOCK(spp_dev_lock);

spp_dev *spp_addr_sppdev(spp_address *addr)
{
    spp_dev *spp_dev, *result = NULL;

    spin_lock_bh(&spp_dev_lock);
    for(spp_dev = spp_dev_list; spp_dev != NULL; spp_dev = spp_dev->next)
    {
        if(sppcmp(addr, (spp_address *)spp_dev->dev->dev_addr) == 0) {
            result= spp_dev;
        }
    }
    spin_unlock_bh(&spp_dev_lock);
    return result;

}
void spp_dev_device_up(struct net_device *dev)
{
    spp_dev *spp_dev;

    if((spp_dev = kzalloc(sizeof(*spp_dev),GFP_ATOMIC)) == NULL){
        printk(KERN_ERR "SPP: spp_dev_device_up - out of memory\n");
        return;
    }
    spp_unregister_sysctl();

    dev->spp_ptr = spp_dev;
    spp_dev->dev = dev;
    dev_hold(dev);
    /*    spp_dev->values[
     *  TODO: set up idle value handling here later
     */
    spin_lock_bh(&spp_dev_lock);
    spp_dev->next = spp_dev_list;
    spp_dev_list = spp_dev;
    spin_unlock_bh(&spp_dev_lock);

    spp_register_sysctl();
    printk(KERN_INFO "SPP: Brought device up\n");
}
void spp_dev_device_down(struct net_device *dev)
{
    spp_dev *s, *spp_dev;
    if((spp_dev = spp_dev_sppdev(dev)) == NULL)
        return;

    spp_unregister_sysctl();

    spin_lock_bh(&spp_dev_lock);

    if ((s = spp_dev_list) == spp_dev) {
        spp_dev_list = s->next;
        spin_unlock_bh(&spp_dev_lock);
        dev_put(dev);
        kfree(spp_dev);
        spp_register_sysctl();
        return;
    }

    while (s != NULL && s->next != NULL) {
        if (s->next == spp_dev) {
            s->next = spp_dev->next;
            spin_unlock_bh(&spp_dev_lock);
            dev_put(dev);
            kfree(spp_dev);
            spp_register_sysctl();
            return;
        }

        s = s->next;
    }

    spin_unlock_bh(&spp_dev_lock);
    dev->spp_ptr = NULL;
    spp_register_sysctl();
    printk(KERN_INFO "SPP: Brought device down");
}

void __exit spp_dev_free(void)
{
    spp_dev *s, *spp_dev;

    spin_lock_bh(&spp_dev_lock);
    spp_dev = spp_dev_list;
    while(spp_dev != NULL){
        s = spp_dev;
        dev_put(spp_dev->dev);
        spp_dev = spp_dev->next;
        kfree(s);
    }
    spp_dev_list = NULL;
    spin_unlock_bh(&spp_dev_lock);
}
