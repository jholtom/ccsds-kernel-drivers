/*
 * Public elements of the kernel SPP code.
 *
 * Jacob Holtom
 */

#include <linux/socket.h>

#define SPP_MTU 65535 /* can be max length of 64K */

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

static const spp_address spp_defaddr = {2001};
static const spp_address spp_nulladdr = {0};
static const spp_address spp_idleaddr = {2047};
