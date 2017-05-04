#ifndef _LINUX_SDLP_H
#define _LINUX_SDLP_H

#define SDLP_MAXCH 256 /* Maximum channels... */
#define SDLP_MTU /* Need to find out MTU */

/* Any other definitions */

struct sdlp {
    int magic;
    struct tty_struct *tty;
    struct net_device *dev;
    spinlock_t lock;
    unsigned char *rbuff; /* receive buffer */
    unsigned char *xhead; /*point to next transmit byte */
    int xleft; /* bytes left in TX queue */
    /* SDLP interface stats */
    unsigned long rx_packets;     /* inbound frames counter	*/
    unsigned long tx_packets;     /* outbound frames counter      */
    unsigned long rx_bytes;       /* inbound byte counte		*/
    unsigned long tx_bytes;       /* outbound byte counter	*/
    unsigned long rx_errors;      /* Parity, etc. errors          */
    unsigned long tx_errors;      /* Planned stuff                */
    unsigned long rx_dropped;     /* No memory for skb            */
    unsigned long tx_dropped;     /* When MTU change              */
    unsigned long rx_over_errors; /* Frame bigger than SLIP buf.  */
    int mtu; /* MTU */
    int buffsize; /* Max buffer size */
    unsigned long flags; /* flags and stuff */
    unsigned char mode;
    dev_t line;
    pid_t pid;
}

#define SDLP_MAGIC 0x /* Allocate magic number */

#endif
