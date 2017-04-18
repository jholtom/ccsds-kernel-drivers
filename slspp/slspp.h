// Copyright 2017 by Jacob Holtom and the Brigham Young University Passive
// Inspection CubeSat Team (BYU PICS)
// All rights reserved
//
// Authors: Jacob Holtom
// File:    slspp.h
//
// This file defines the SLSPP device driver interface and constants.
//
// References:
//     Elysium Radio User Manual (elysium_manual.pdf), September 16th 2016
//     Linux Device Drivers - O'Reilly
//
#ifndef _LINUX_SLSPP_H
#define _LINUX_SLSPP_H

#define SL_NRUNIT 256/* MAX number of SLSPP channels.
                        Can be overriden with insmod -oslip_maxdev=nnn */
#define SL_MTU 296 /* MTU, this could potentially be changed... */

#define END 0300     /* indicates end of frame */
#define ESC 0333     /* indicates byte stuffing */
#define ESC_END 0334 /* ESC ESC_END means END 'data' */
#define ESC_ESC 0335 /* ESC ESC_ESC means ESC 'data' */

struct slspp {
  int magic; /* May not need? */
  struct tty_struct *tty;
  struct net_device *dev;
  spinlock_t lock;
  unsigned char *rbuff; /* receive buffer */
  int rcount;           /* received character count */
  unsigned char *xbuff; /* transmit buffer */
  unsigned char *xhead; /* point to next byte to transmit */
  int xleft;            /* bytes left in transmit queue */
  /* SLIP interface statistics. */
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
#define SLF_INUSE 0
#define SLF_ESC 1
#define SLF_ERROR 2
#define SLF_KEEPTEST 3
#define SLF_OUTWAIT 4

  unsigned char mode;
  dev_t line;
  pid_t pid;
}

#define SLIP_MAGIC 0x5302 /* May not need ? */

#endif
