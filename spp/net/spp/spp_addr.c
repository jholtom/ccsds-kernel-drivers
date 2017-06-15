/* SPP Address Handling */
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

char *spp2ascii(char *buf, const spp_address *addr)
{
    /* TODO: Generate a human readable version of this int (ASCII) */
}
EXPORT_SYMBOL(spp2ascii);

void ascii2spp(spp_address *addr, const char *buf)
{
    /* TODO: ASCII -> SPP address conversion */
}
EXPORT_SYMBOL(ascii2spp);

int sppcmp(spp_address *addr1, spp_address *addr2)
{
    if(addr1->spp_apid == addr2->spp_apid)
        return 0;
    else
        return 1;
}
EXPORT_SYMBOL(sppcmp);

int sppval(struct spp_address *addr)
{
    /* TODO: Implement validation method */
    return 0;
}
