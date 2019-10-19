/*
 *    Space Packet Protocol Packet Layer release 001 - User Space Header
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

#ifndef _NETSPP_SPP_H
#define _NETSPP_SPP_H 1

#include <features.h>
#include <bits/sockaddr.h>

#define SOL_SPP 278 

#define SPP_MTU 65535

typedef struct {
	unsigned int spp_apid : 11; /* 11 bit APID */
} spp_address;

struct sockaddr_spp {
	sa_family_t sspp_family;
	spp_address sspp_addr;
};

#endif
