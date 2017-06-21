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
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <net/spp.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/uaccess.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/interrupt.h>

void spp2ascii(char *buf, const spp_address *addr)
{
    snprintf(buf,sizeof(buf),"%d",addr->spp_apid);
}
EXPORT_SYMBOL(spp2ascii);

void ascii2spp(spp_address *addr, const char *buf)
{
    unsigned int apid;
    sscanf(buf,"%d",&apid);
    addr->spp_apid = apid;
}
EXPORT_SYMBOL(ascii2spp);

int sppcmp(const spp_address *addr1, const spp_address *addr2)
{
    if(addr1->spp_apid == addr2->spp_apid)
        return 0;
    return 1;
}
EXPORT_SYMBOL(sppcmp);

int sppval(const spp_address *addr)
{
    if(addr->spp_apid <= 2047 && addr->spp_apid >= 0)
        return 0;
    return 1;
}
EXPORT_SYMBOL(sppval);
