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
#include <linux/spp.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <net/neighbour.h>
#include <net/sock.h>

#define SPP_HEADER_LEN 32 /* 32 bit header length */
#define SPP_APID_LEN 11 /* 11 bit APID length */

#define SPP_DEFAULT_IDLE (180 * HZ)

#define SPP_OUT_OF_ORDER 0

#define IFA_F_SECONDARY 0x01
#define IFA_F_TEMPORARY IFA_F_SECONDARY

#define SPP_PKTTYPE 27 /* TODO: fix location of this (maybe), and assign a better value */

struct spp_entity {
    /* An end of the connection - May not need because we have no true 'routing' support */
};

struct spp_sock {
    struct sock sock;
    spp_address s_addr, d_addr;
    struct net_device *device;
    unsigned char state, condition, defer, type, cause, diagnostic;
    struct sk_buff_head fragment_queue;
    struct sk_buff_head interrupt_in_queue;
    struct sk_buff_head interrupt_out_queue;
    unsigned long idle_timer;
    struct timer_list timer;
};

static inline struct spp_sock *spp_sk(const struct sock *sk)
{
    return (struct spp_sock *)sk;
}

struct spp_ifaddr {
    struct spp_ifaddr *ifa_next;
    struct spp_dev *spp_dev;
    struct rcu_head rcu_head;
    unsigned int ifa_local;
    unsigned int ifa_address;
    unsigned char ifa_flags;
    char ifa_label[IFNAMSIZ];
};

struct spp_dev {
    struct spp_dev *next;
    struct net_device *dev;
    struct spp_ifaddr *ifa_list;
    atomic_t refcnt;
    int dead;
    struct rcu_head rcu_head;
};

extern struct hlist_head spp_list;
extern spinlock_t spp_list_lock;

/* af_spp.c */
extern int sysctl_spp_idle_timer;

static inline struct spp_dev *__spp_dev_get_rcu(const struct net_device *dev)
{
    struct spp_dev *spp_dev = dev->spp_ptr;
    if(spp_dev)
        spp_dev = rcu_dereference(spp_dev);
    return spp_dev;
}

static __inline__ struct spp_dev *spp_dev_get(const struct net_device *dev)
{
    struct spp_dev *spp_dev;
    rcu_read_lock();
    spp_dev = __spp_dev_get_rcu(dev);
    if(spp_dev)
        atomic_inc(&spp_dev->refcnt);
    rcu_read_unlock();
    return spp_dev;
}
static __inline__ struct spp_dev *__spp_dev_get_rtnl(const struct net_device *dev)
{
    return (struct spp_dev*)dev->spp_ptr;
}

/* spp_addr.c */
extern void spp2ascii(char *buf, const spp_address *addr);
extern void asii2spp(spp_address *addr, const char *buf);
extern int sppcmp(const spp_address *addr1, const spp_address *addr2);
extern int sppval(const spp_address *addr);

/* spp_dev.c */
extern void spp_dev_device_up(struct net_device *);
extern void spp_dev_device_down(struct net_device *);

extern void spp_dev_finish_destroy(struct spp_dev *sdev);

static inline void spp_dev_put(struct spp_dev *sdev)
{
    if(atomic_dec_and_test(&sdev->refcnt))
        spp_dev_finish_destroy(sdev);
}

#define __spp_dev_put(sdev)  atomic_dec(&(sdev)->refcnt)
#define spp_dev_hold(sdev)  atomic_inc(&(sdev)->refcnt)

extern void spp_free_ifa(struct spp_ifaddr *ifa);
extern int spp_set_ifa(struct net_device *dev, struct spp_ifaddr *ifa);
extern struct spp_ifaddr *spp_alloc_ifa(void);
extern int spp_del_ifa(struct spp_dev *spp_device, struct spp_ifaddr **ifap, int destroy);

/* spp_loopback.c */

/* spp_methods.c */
extern void spp_disconnect(struct sock *sk, int reason, unsigned char cause, unsigned char diagnostic);
extern int spp_kiss_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *ptype, struct net_device *orig_dev);

/* spp_in.c */
extern int spp_process_rx(struct sock *, struct sk_buff *);
extern int spp_backlog_rcv(struct sock *, struct sk_buff *);

/* spp_out.c */

/* spp_proc.c */
extern int spp_proc_init(void);
extern void spp_proc_exit(void);

/* sysctl_net_spp.c */
#ifdef CONFIG_SYSCTL
extern void spp_register_sysctl(void);
extern void spp_unregister_sysctl(void);
#else
static inline void spp_register_sysctl(void){};
static inline void spp_unregister_sysctl(void){};
#endif
