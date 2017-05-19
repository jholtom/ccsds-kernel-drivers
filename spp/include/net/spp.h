/*
 * Declarations of SPP type objects.
 *
 * Jacob Holtom
 */

#include <linux/spp.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <net/neighbour.h>
#include <net/sock.h>

#define SPP_HEADER_LEN 32 /* 32 bit header length */
#define SPP_APID_LEN 11 /* 11 bit APID length */

struct spp_entity {
/* An end of the connection - May not need because we have no true 'routing' support */
};

struct spp_sock {
    struct sock  sock;
    spp_address s_addr, d_addr;
    struct net_device *device;
    unsigned int lci, rand;
    unsigned char state, condition, qbitincl, defer;
    unsigned char cause, diagnostic;
    unsigned short vs, vr, va, vl;
    unsigned long t1,t2,t3,hb,idle;
#ifdef M_BIT
    unsigned short  fraglen;
    struct sk_buff_head     frag_queue;
#endif
    struct spp_facilities_struct facilities;
    struct timer_list timer;
    struct timer_list idletimer;
};

#define spp_sk(sk) ((struct spp_sock *)(sk))

typedef struct spp_dev {
    struct spp_dev *next;
    struct net_device *dev;
    struct net_
}

/* What do we do about secondary headers? */
