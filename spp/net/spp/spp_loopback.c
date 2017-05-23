#include <linux/types.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <net/spp.h>
#include <linux/init.h>

static struct sk_buff_head loopback_queue;
static struct timer_list loopback_timer;

static void spp_set_loopback_timer(void); /* Forward declaration */
