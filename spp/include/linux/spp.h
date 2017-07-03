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

#include <linux/socket.h>
#include <linux/skbuff.h>

#define SPP_MTU 65535 /* can be max length of 64K */

struct spphdr {
        unsigned int fields;
        __be16 pdl;
}__attribute__((packed));

typedef struct {
    unsigned int spp_apid : 11; /* 11 bit APID */
    /* Done in a struct to facilitate expansion to other addressing parameters (unlikely) */
} spp_address;
/* May need to add TM/TC parameter here, 1 bit flag */

struct sockaddr_spp {
    sa_family_t sspp_family;
    spp_address sspp_addr;
};

/* Space Packet Address' are defined to be 11-bits long
 * Space Packet Address' can be from 0 to 2047 (decimal form)
 * 2032 to 2047 are reserved by CCSDS
 * The default address is:  11111010001 (2001 dec)
 * The null address is: 00000000000 (0 dec)
 * The idle address is: 11111111111 (2047 dec)
 */

extern const spp_address spp_defaddr = {2001};
extern const spp_address spp_nulladdr = {0};
extern const spp_address spp_idleaddr = {2047};
