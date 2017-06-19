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
#include <net/neighbour.h>
#include <net/sock.h>

#define SPP_HEADER_LEN 32 /* 32 bit header length */
#define SPP_APID_LEN 11 /* 11 bit APID length */

#define SPP_DEFAULT_IDLE (180 * HZ) 

#define SPP_OUT_OF_ORDER 0

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

#define spp_sk(sk) ((struct spp_sock *)(sk))

struct spp_dev {
    struct spp_dev *next;
    struct net_device *dev;
};

extern struct hlist_head spp_list;
extern spinlock_t spp_list_lock;

/* af_spp.c */
extern int sysctl_spp_idle_timer;
/* spp_addr.c */
extern void spp2ascii(char *buf, const spp_address *addr);
extern void asii2spp(spp_address *addr, const char *buf);
extern int sppcmp(const spp_address *addr1, const spp_address *addr2);
extern int sppval(const spp_address *addr);
/* spp_loopback.c */

/* spp_methods.c */
extern void spp_disconnect(struct sock *sk, int reason, unsigned char cause, unsigned char diagnostic);
extern int spp_kiss_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *ptype, struct net_device *orig_dev);
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
