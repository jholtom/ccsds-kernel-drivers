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

struct sockaddr_spp {
    __kernel_sa_family_t sspp_family;
    spp_address sspp_addr;
};
