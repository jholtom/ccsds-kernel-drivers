#include "config.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netspp/spp.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include "net-support.h"
#include "pathnames.h"
#include "intl.h"
#include "util.h"

struct aftype spp_aftype = {
  "spp", NULL, /* "Space Packet Protocol",*/ AF_SPP, 7,
  NULL, NULL, NULL, NULL,
  NULL, NULL, NULL,
  -1,
  "/proc/net/spp"
};
