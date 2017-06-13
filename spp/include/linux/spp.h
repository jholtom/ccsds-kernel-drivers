/*
 * Public elements of the kernel SPP code.
 *
 * Jacob Holtom
 */

#include <linux/socket.h>

#define SPP_MTU 65535 /* can be max length of 64K */

typedef struct {
    int spp_apid : 11; /* 11 bit APID */
    /* Done in a struct to facilitate expansion to other addressing parameters (unlikely) */
} spp_address;
/* May need to add TM/TC parameter here, 1 bit flag */

struct sockaddr_spp {
    sa_family_t sspp_family;
    spp_address sspp_addr;
};

/* Facilities Structure
 * Totally unsure of what this actually does
 */
struct spp_facilities_struct {
    spp_address s_addr, d_addr;
    unsigned int rand;
    spp_address fail_addr;
};
