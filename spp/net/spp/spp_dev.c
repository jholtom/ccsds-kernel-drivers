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

static BLOCKING_NOTIFIER_HEAD(sppaddr_chain);

void spp_free_ifa(struct spp_ifaddr *ifa)
{
    kfree(&(ifa->spp_dev));
                printk(KERN_ALERT "SPP: DEBUG: Passed %s %d \n",__FUNCTION__,__LINE__);
    kfree(ifa);
                printk(KERN_ALERT "SPP: DEBUG: Passed %s %d \n",__FUNCTION__,__LINE__);
    /*TODO/FIXME: Fix this so I absolutely do not leak memory and properly use RCU instead of not using it...*/
}
/*spp_dev *spp_addr_sppdev(spp_address *addr)
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

}*/
void spp_dev_device_up(struct net_device *dev)
{
    struct spp_dev *spp_dev;

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
    /*spin_lock_bh(&spp_dev_lock);
    spp_dev->next = spp_dev_list;
    spp_dev_list = spp_dev;
    spin_unlock_bh(&spp_dev_lock);*/

    spp_register_sysctl();
    printk(KERN_INFO "SPP: Brought device up\n");
}
void spp_dev_device_down(struct net_device *dev)
{
    struct spp_dev *s, *spp_dev;
/*    if((spp_dev = spp_dev_sppdev(dev)) == NULL)
        return;*/

    spp_unregister_sysctl();
/*
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

    spin_unlock_bh(&spp_dev_lock);*/
    dev->spp_ptr = NULL;
    spp_register_sysctl();
    printk(KERN_INFO "SPP: Brought device down");
}


int __spp_insert_ifa(struct spp_ifaddr *ifa, struct nlmsghdr *nlh, u32 pid)
{
    struct spp_dev *spp_device = ifa->spp_dev;
    struct spp_ifaddr *ifa1, **ifap, **last_primary;

    ASSERT_RTNL();
    if(!ifa->ifa_local){
        spp_free_ifa(ifa);
        return 0;
    }

    ifa->ifa_flags &= ~IFA_F_SECONDARY;
    last_primary = &spp_device->ifa_list;
    for(ifap = &spp_device->ifa_list; (ifa1 = *ifap) != NULL; ifap = &ifa1->ifa_next){
        if(!(ifa1->ifa_flags & IFA_F_SECONDARY))
            last_primary = &ifa1->ifa_next;
        if(ifa1->ifa_local == ifa->ifa_local){
            spp_free_ifa(ifa);
            return -EEXIST;
        }
        ifa->ifa_flags |= IFA_F_SECONDARY;
    }
    if(!(ifa->ifa_flags & IFA_F_SECONDARY)){
        net_srandom(ifa->ifa_local);
        ifap = last_primary;
    }
    ifa->ifa_next = *ifap;
    *ifap = ifa;
    /*TODO: either implement support for newaddr notifs, or ermove
     * rtmsg_ifa(RTM_NEWADDR, ifa, nlh, pid);*/
    blocking_notifier_call_chain(&sppaddr_chain, NETDEV_UP, ifa);
    return 0;
}

int spp_insert_ifa(struct spp_ifaddr *ifa)
{
    return __spp_insert_ifa(ifa, NULL, 0);
}

int spp_set_ifa(struct net_device *dev, struct spp_ifaddr *ifa)
{
    struct spp_dev *spp_device = __spp_dev_get_rtnl(dev);

    ASSERT_RTNL();

                printk(KERN_ALERT "SPP: DEBUG: Passed %s %d \n",__FUNCTION__,__LINE__);
    if(!spp_device){
        spp_free_ifa(ifa);
                printk(KERN_ALERT "SPP: DEBUG: Passed %s %d \n",__FUNCTION__,__LINE__);
        return -ENOBUFS;
    }
                printk(KERN_ALERT "SPP: DEBUG: Passed %s %d \n",__FUNCTION__,__LINE__);
    return spp_insert_ifa(ifa);
}

struct spp_ifaddr *spp_alloc_ifa(void)
{
    return kzalloc(sizeof(struct spp_ifaddr), GFP_KERNEL);
}

int spp_del_ifa(struct spp_dev *spp_device, struct spp_ifaddr **ifap, int destroy)
{
    return 0;
}

int register_sppaddr_notifier(struct notifier_block *nb)
{
    return blocking_notifier_chain_register(&sppaddr_chain, nb);
}
EXPORT_SYMBOL(register_sppaddr_notifier);
int unregister_sppaddr_notifier(struct notifier_block *nb)
{
    return blocking_notifier_chain_unregister(&sppaddr_chain, nb);
}
EXPORT_SYMBOL(unregister_sppaddr_notifier);

void __exit spp_dev_free(void)
{
    struct spp_dev *s, *spp_dev;

    /*spin_lock_bh(&spp_dev_lock);
    spp_dev = spp_dev_list;
    while(spp_dev != NULL){
        s = spp_dev;
        dev_put(spp_dev->dev);
        spp_dev = spp_dev->next;
        kfree(s);
    }
    spp_dev_list = NULL;
    spin_unlock_bh(&spp_dev_lock);*/
}
