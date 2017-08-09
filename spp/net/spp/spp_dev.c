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

struct spp_dev *spp_dev_list;
DEFINE_SPINLOCK(spp_dev_lock);

static BLOCKING_NOTIFIER_HEAD(sppaddr_chain);

struct spp_dev *spp_addr_sppdev(spp_address *addr)
{
    struct spp_dev *spp_dev, *res = NULL;
    struct spp_ifaddr *s;
    spin_lock_bh(&spp_dev_lock);
    for(spp_dev = spp_dev_list; spp_dev != NULL; spp_dev = spp_dev->next)
    {
        for(s = spp_dev->ifa_list; s != NULL; s = s->ifa_next){
            if(addr->spp_apid == s->ifa_address){
                res = spp_dev;
            }
        }
    }
    spin_unlock_bh(&spp_dev_lock);
    return res;
}

static void spp_rcu_free_ifa(struct rcu_head *head)
{
    struct spp_ifaddr *ifa = container_of(head, struct spp_ifaddr, rcu_head);
    if(ifa->spp_dev)
       spp_dev_put(ifa->spp_dev);
    printk(KERN_INFO "SPP: spp_rcu_free_ifa: Freeing Interface Address NOW!\n");
    kfree(ifa);
}

void spp_free_ifa(struct spp_ifaddr *ifa)
{
    call_rcu(&ifa->rcu_head, spp_rcu_free_ifa);
}

void spp_dev_device_up(struct net_device *dev)
{
    struct spp_dev *spp_dev;

    ASSERT_RTNL();

    spp_dev = kzalloc(sizeof(*spp_dev), GFP_KERNEL);
    if(!spp_dev)
        goto out;
    /* TODO: Set device specific config flags here*/
    spp_dev->dev = dev;
    dev_hold(dev);
    spp_dev_hold(spp_dev);

    spin_lock_bh(&spp_dev_lock);
    spp_dev->next = spp_dev_list;
    spp_dev_list = spp_dev;
    spin_unlock_bh(&spp_dev_lock);

    rcu_assign_pointer(dev->spp_ptr, spp_dev);
out:
    return;
}

static void spp_dev_rcu_put(struct rcu_head *head){
    struct spp_dev *sdev = container_of(head, struct spp_dev, rcu_head);
    spp_dev_put(sdev);
}

void spp_dev_device_down(struct net_device *dev)
{
    struct spp_ifaddr *ifa;
    struct spp_dev *spp_dev,*s;
    spp_dev = dev->spp_ptr;

    ASSERT_RTNL();
    spp_dev->dead = 1;
    while((ifa = spp_dev->ifa_list) != NULL){
        spp_del_ifa(spp_dev, &spp_dev->ifa_list,0);
        spp_free_ifa(ifa);
    }
    dev->spp_ptr = NULL;

    spin_lock_bh(&spp_dev_lock);
    if((s = spp_dev_list) == spp_dev){
        spp_dev_list = s->next;
        spin_unlock_bh(&spp_dev_lock);
        call_rcu(&spp_dev->rcu_head, spp_dev_rcu_put);
        return;
    }
    while(s != NULL && s->next != NULL){
        if(s->next == spp_dev){
            s->next = spp_dev->next;
            spin_unlock_bh(&spp_dev_lock);
            call_rcu(&spp_dev->rcu_head, spp_dev_rcu_put);
            return;
        }
        s = s->next;
    }
    spin_unlock_bh(&spp_dev_lock);
/* Should be called earlier...
    call_rcu(&spp_dev->rcu_head, spp_dev_rcu_put);*/
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
    printk(KERN_INFO "SPP: spp_insert_ifa: Adding new interface address now\n");
    for(ifap = &spp_device->ifa_list; (ifa1 = *ifap) != NULL; ifap = &ifa1->ifa_next){
        if(ifa1->ifa_local == ifa->ifa_local){
            spp_free_ifa(ifa);
            return -EEXIST;
        }
    }
    ifa->ifa_next = *ifap;
    *ifap = ifa;
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

    if(!spp_device){
        spp_free_ifa(ifa);
        return -ENOBUFS;
    }
    /*TODO: Set device options here*/
    if(ifa->spp_dev != spp_device){
        WARN_ON(ifa->spp_dev);
        spp_dev_hold(spp_device);
        ifa->spp_dev = spp_device;
    }
    return spp_insert_ifa(ifa);
}

struct spp_ifaddr *spp_alloc_ifa(void)
{
    return kzalloc(sizeof(struct spp_ifaddr), GFP_KERNEL);
}

static void __spp_del_ifa(struct spp_dev *spp_dev, struct spp_ifaddr **ifap, int destroy, struct nlmsghdr *nlh, u32 pid)
{
    struct spp_ifaddr *ifa, *ifa1 = *ifap;

    ASSERT_RTNL();
    struct spp_ifaddr **ifap1 = &ifa1->ifa_next;
    while((ifa = *ifap1) != NULL){
        *ifap1 = ifa->ifa_next;
        blocking_notifier_call_chain(&sppaddr_chain,NETDEV_DOWN,ifa);
        spp_free_ifa(ifa);
    }

    *ifap =ifa1->ifa_next;

    blocking_notifier_call_chain(&sppaddr_chain, NETDEV_DOWN, ifa1);

    if(destroy)
        spp_free_ifa(ifa1);
}

void spp_del_ifa(struct spp_dev *spp_device, struct spp_ifaddr **ifap, int destroy)
{
    __spp_del_ifa(spp_device, ifap, destroy, NULL, 0);
}

void spp_dev_finish_destroy(struct spp_dev *sdev)
{
    struct net_device *dev = sdev->dev;

    WARN_ON(sdev->ifa_list);
    printk(KERN_DEBUG "spp_dev_finish_destroy: %p=%s\n", sdev, dev ? dev->name : "NIL");
    dev_put(dev);
    if(!sdev->dead)
        pr_err("Freeing alive spp_dev %p\n", sdev);
    else
        kfree(sdev);
}
EXPORT_SYMBOL(spp_dev_finish_destroy);

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
