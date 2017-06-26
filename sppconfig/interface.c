/* Code to manipulate interface information, shared between ifconfig and
netstat.

10/1998 partly rewriten by Andi Kleen to support an interface list.
I don't claim that the list operations are efficient @).

8/2000  Andi Kleen make the list operations a bit more efficient.
People are crazy enough to use thousands of aliases now.

$Id: interface.c,v 1.35 2011-01-01 03:22:31 ecki Exp $
*/

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <netspp/spp.h>

#if HAVE_AFIPX
#if (__GLIBC__ > 2) || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 1)
#include <netipx/ipx.h>
#else
#include "ipx.h"
#endif
#endif

#if HAVE_AFECONET
#include <neteconet/ec.h>
#endif

#if HAVE_HWSLIP
#include <linux/if_slip.h>
#include <net/if_arp.h>
#endif

#include "net-support.h"
#include "pathnames.h"
#include "version.h"
#include "proc.h"

#include "interface.h"
#include "sockets.h"
#include "util.h"
#include "intl.h"

#ifdef IFF_PORTSEL
const char *if_port_text[][4] =
{
  /* Keep in step with <linux/netdevice.h> */
  {"unknown", NULL, NULL, NULL},
  {"10base2", "bnc", "coax", NULL},
  {"10baseT", "utp", "tpe", NULL},
  {"AUI", "thick", "db15", NULL},
  {"100baseT", NULL, NULL, NULL},
  {"100baseTX", NULL, NULL, NULL},
  {"100baseFX", NULL, NULL, NULL},
  {NULL, NULL, NULL, NULL},
};
#endif

#define IPV6_ADDR_ANY		0x0000U

#define IPV6_ADDR_UNICAST      	0x0001U
#define IPV6_ADDR_MULTICAST    	0x0002U
#define IPV6_ADDR_ANYCAST	0x0004U

#define IPV6_ADDR_LOOPBACK	0x0010U
#define IPV6_ADDR_LINKLOCAL	0x0020U
#define IPV6_ADDR_SITELOCAL	0x0040U

#define IPV6_ADDR_COMPATv4	0x0080U

#define IPV6_ADDR_SCOPE_MASK	0x00f0U

#define IPV6_ADDR_MAPPED	0x1000U
#define IPV6_ADDR_RESERVED	0x2000U		/* reserved address space */

int procnetdev_vsn = 1;

int ife_short;

int if_list_all = 0;	/* do we have requested the complete proc list, yet? */

static struct interface *int_list, *int_last;

static int if_readlist_proc(const char *);

/* add the to the int_list */
static struct interface *if_cache_add(const char *name)
{
  printf("interface: if_cache_add\n");
  struct interface *ife, **nextp, *new;

  if (!int_list)
    int_last = NULL;

  /* the cache is sorted, so if we hit a smaller if, exit */
  for (ife = int_last; ife; ife = ife->prev) {
    int n = nstrcmp(ife->name, name);
    if (n == 0)
      return ife;
    if (n < 0)
      break;
  }
  new(new); /* util.h macro */
  safe_strncpy(new->name, name, IFNAMSIZ);
  nextp = ife ? &ife->next : &int_list; // keep sorting
  new->prev = ife;
  new->next = *nextp;
  if (new->next)
  new->next->prev = new;
  else
  int_last = new;
  *nextp = new;
  printf("interface: if_cache_add added %s to cache\n", new->name);
  return new;
}

struct interface *lookup_interface(const char *name)
{
  /* if we have read all, use it */
  if (if_list_all)
    return if_cache_add(name);

  /* otherwise we read a limited list */
  if (if_readlist_proc(name) < 0)
    return NULL;

  return if_cache_add(name);
}

int for_all_interfaces(int (*doit) (struct interface *, void *), void *cookie)
{
  printf("interface: for_all_interfaces \n");
  struct interface *ife;

  if (!if_list_all && (if_readlist() < 0))
  return -1;
  for (ife = int_list; ife; ife = ife->next) {
    printf("interface: for_all_interfaces: ife->name = %s\n", ife->name);
    int err = doit(ife, cookie);
    if (err)
    return err;
  }
  return 0;
}

int if_cache_free(void)
{
  struct interface *ife;
  while ((ife = int_list) != NULL) {
    int_list = ife->next;
    free(ife);
  }
  int_last = NULL;
  if_list_all = 0;
  return 0;
}

static int if_readconf(void)
{
  int numreqs = 30;
  struct ifconf ifc;
  struct ifreq *ifr;
  int n, err = -1;
  int skfd;

  /* SIOCGIFCONF currently seems to only work properly on AF_INET sockets
  (as of 2.1.128) */
  skfd = get_socket_for_af(AF_INET);
  if (skfd < 0) {
    fprintf(stderr, _("warning: no inet socket available: %s\n"),
    strerror(errno));
    /* Try to soldier on with whatever socket we can get hold of.  */
    skfd = sockets_open(0);
    if (skfd < 0)
    return -1;
  }

  ifc.ifc_buf = NULL;
  for (;;) {
    ifc.ifc_len = sizeof(struct ifreq) * numreqs;
    ifc.ifc_buf = xrealloc(ifc.ifc_buf, ifc.ifc_len);

    if (ioctl(skfd, SIOCGIFCONF, &ifc) < 0) {
      perror("SIOCGIFCONF");
      goto out;
    }
    if (ifc.ifc_len == sizeof(struct ifreq) * numreqs) {
      /* assume it overflowed and try again */
      numreqs *= 2;
      continue;
    }
    break;
  }

  ifr = ifc.ifc_req;
  for (n = 0; n < ifc.ifc_len; n += sizeof(struct ifreq)) {
    if_cache_add(ifr->ifr_name);
    ifr++;
  }
  err = 0;

  out:
  free(ifc.ifc_buf);
  return err;
}

static const char *get_name(char *name, const char *p)
{
  while (isspace(*p))
  p++;
  while (*p) {
    if (isspace(*p))
    break;
    if (*p == ':') {	/* could be an alias */
      const char *dot = p++;
      while (*p && isdigit(*p)) p++;
      if (*p == ':') {
        /* Yes it is, backup and copy it. */
        p = dot;
        *name++ = *p++;
        while (*p && isdigit(*p)) {
          *name++ = *p++;
        }
      } else {
        /* No, it isn't */
        p = dot;
      }
      p++;
      break;
    }
    *name++ = *p++;
  }
  *name++ = '\0';
  return p;
}

static int procnetdev_version(const char *buf)
{
  if (strstr(buf, "compressed"))
  return 3;
  if (strstr(buf, "bytes"))
  return 2;
  return 1;
}

static int get_dev_fields(const char *bp, struct interface *ife)
{
  printf("interface: get_dev_fields\n");
  switch (procnetdev_vsn) {
    case 3:
    sscanf(bp,
      "%Lu %Lu %lu %lu %lu %lu %lu %lu %Lu %Lu %lu %lu %lu %lu %lu %lu",
      &ife->stats.rx_bytes,
      &ife->stats.rx_packets,
      &ife->stats.rx_errors,
      &ife->stats.rx_dropped,
      &ife->stats.rx_fifo_errors,
      &ife->stats.rx_frame_errors,
      &ife->stats.rx_compressed,
      &ife->stats.rx_multicast,

      &ife->stats.tx_bytes,
      &ife->stats.tx_packets,
      &ife->stats.tx_errors,
      &ife->stats.tx_dropped,
      &ife->stats.tx_fifo_errors,
      &ife->stats.collisions,
      &ife->stats.tx_carrier_errors,
      &ife->stats.tx_compressed);
      break;
      case 2:
      sscanf(bp, "%Lu %Lu %lu %lu %lu %lu %Lu %Lu %lu %lu %lu %lu %lu",
      &ife->stats.rx_bytes,
      &ife->stats.rx_packets,
      &ife->stats.rx_errors,
      &ife->stats.rx_dropped,
      &ife->stats.rx_fifo_errors,
      &ife->stats.rx_frame_errors,

      &ife->stats.tx_bytes,
      &ife->stats.tx_packets,
      &ife->stats.tx_errors,
      &ife->stats.tx_dropped,
      &ife->stats.tx_fifo_errors,
      &ife->stats.collisions,
      &ife->stats.tx_carrier_errors);
      ife->stats.rx_multicast = 0;
      break;
      case 1:
      sscanf(bp, "%Lu %lu %lu %lu %lu %Lu %lu %lu %lu %lu %lu",
      &ife->stats.rx_packets,
      &ife->stats.rx_errors,
      &ife->stats.rx_dropped,
      &ife->stats.rx_fifo_errors,
      &ife->stats.rx_frame_errors,

      &ife->stats.tx_packets,
      &ife->stats.tx_errors,
      &ife->stats.tx_dropped,
      &ife->stats.tx_fifo_errors,
      &ife->stats.collisions,
      &ife->stats.tx_carrier_errors);
      ife->stats.rx_bytes = 0;
      ife->stats.tx_bytes = 0;
      ife->stats.rx_multicast = 0;
      break;
    }
    return 0;
  }

  static int if_readlist_proc(const char *target)
  {
    printf("interface: if_readlist_proc\n");

    FILE *fh;
    char buf[512];
    struct interface *ife;
    int err;

    fh = fopen(_PATH_PROCNET_DEV, "r");
    if (!fh) {
      fprintf(stderr, _("Warning: cannot open %s (%s). Limited output.\n"),
      _PATH_PROCNET_DEV, strerror(errno));
      return -2;
    }
    if (fgets(buf, sizeof buf, fh))
    /* eat line */;
    if (fgets(buf, sizeof buf, fh))
    /* eat line */;

    #if 0				/* pretty, but can't cope with missing fields */
    fmt = proc_gen_fmt(_PATH_PROCNET_DEV, 1, fh,
    "face", "",	/* parsed separately */
    "bytes", "%lu",
    "packets", "%lu",
    "errs", "%lu",
    "drop", "%lu",
    "fifo", "%lu",
    "frame", "%lu",
    "compressed", "%lu",
    "multicast", "%lu",
    "bytes", "%lu",
    "packets", "%lu",
    "errs", "%lu",
    "drop", "%lu",
    "fifo", "%lu",
    "colls", "%lu",
    "carrier", "%lu",
    "compressed", "%lu",
    NULL);
    if (!fmt)
    return -1;
    #else
    procnetdev_vsn = procnetdev_version(buf);
    #endif

    err = 0;
    while (fgets(buf, sizeof buf, fh)) {
      const char *s;
      char name[IFNAMSIZ];
      s = get_name(name, buf);
      ife = if_cache_add(name);
      get_dev_fields(s, ife);
      ife->statistics_valid = 1;
      if (target && !strcmp(target,name))
        break;
    }
    if (ferror(fh)) {
      perror(_PATH_PROCNET_DEV);
      err = -1;
    }

    #if 0
    free(fmt);
    #endif
    fclose(fh);
    return err;
  }

  int if_readlist(void)
  {
    /* caller will/should check not to call this too often
    *   (i.e. only if if_list_all == 0
    */
    printf ("interface: if_readlist\n");
    int proc_err, conf_err;

    proc_err = if_readlist_proc(NULL);
    conf_err = if_readconf();

    if_list_all = 1;

    if (proc_err < 0 && conf_err < 0)
    return -1;
    else
    return 0;
  }

  /* Support for fetching an IPX address */

  #if HAVE_AFIPX
  static int ipx_getaddr(int sock, int ft, struct ifreq *ifr)
  {
    ((struct sockaddr_ipx *) &ifr->ifr_addr)->sipx_type = ft;
    return ioctl(sock, SIOCGIFADDR, ifr);
  }
  #endif

  /* Fetch the interface configuration from the kernel. */
int if_fetch(struct interface *ife) {

    printf("interface: if_fetch\n");
    struct ifreq ifr;
    int fd;
    const char *ifname = ife->name;

    /* get flags */
    safe_strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0)
      return (-1);
    ife->flags = ifr.ifr_flags;

    /* get MTU */
    safe_strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(skfd, SIOCGIFMTU, &ifr) < 0)
      ife->mtu = 0;
    else
      ife->mtu = ifr.ifr_mtu;


    /* TODO: Check with Jacob Holtom about SIOCGIFTXQLEN and
             TIOCOUTQ/TIOCINQ */
#if 0
    safe_strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(skfd, SIOCGIFTXQLEN, &ifr) < 0)
    ife->tx_queue_len = -1;	/* unknown value */
    else
    ife->tx_queue_len = ifr.ifr_qlen;
#else
    ife->tx_queue_len = -1;	/* unknown value */
#endif

  /* get interface address */
    fd = get_socket_for_af(AF_SPP);
    if (fd >= 0) {
      safe_strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
      if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        ife->sppaddr = ifr.ifr_addr;
        ife->has_spp = 1;
      }
    }

    /* TODO: check if we need to implement SIOCGSTAMP */

    return 0;
  } /* if_fetch */

  int do_if_fetch(struct interface *ife)
  {
    printf("interface: do_if_fetch\n");
    if (if_fetch(ife) < 0) {
      const char *errmsg;
      if (errno == ENODEV) {
        /* Give better error message for this case. */
        errmsg = _("Device not found");
      } else {
        errmsg = strerror(errno);
      }
      fprintf(stderr, _("%s: error fetching interface information: %s\n"),
      ife->name, errmsg);
      return -1;
    }
    return 0;
  }

  int do_if_print(struct interface *ife, void *cookie)
  {
    printf("interface: do_if_print\n");
    int *opt_a = (int *) cookie;
    int res;

    res = do_if_fetch(ife);
    if (res >= 0) {
      /* print only if interface is active or -a was given */
      if ((ife->flags & IFF_UP) || *opt_a)
        ife_print(ife);
    }
    return res;
  }

  void ife_print_short(struct interface *ife){

    printf("%-8.8s ", ife->name);
    printf("%5d ", ife->mtu);
    /* If needed, display the interface statistics. */
    if (ife->statistics_valid) {
      printf("%8llu %6lu %6lu %-6lu ",
      ife->stats.rx_packets, ife->stats.rx_errors,
      ife->stats.rx_dropped, ife->stats.rx_fifo_errors);
      printf("%8llu %6lu %6lu %6lu ",
      ife->stats.tx_packets, ife->stats.tx_errors,
      ife->stats.tx_dropped, ife->stats.tx_fifo_errors);
    } else {
      printf("%-56s", _("     - no statistics available -"));
    }
    /* DONT FORGET TO ADD THE FLAGS IN ife_print_long, too */
    /* TODO: Decide if we need to git rid of the unused flags in this */
    if (ife->flags == 0)
      printf(_("[NO FLAGS]"));
    if (ife->flags & IFF_ALLMULTI)
      printf("A");
    if (ife->flags & IFF_BROADCAST)
      printf("B");
    if (ife->flags & IFF_DEBUG)
      printf("D");
    if (ife->flags & IFF_LOOPBACK)
      printf("L");
    if (ife->flags & IFF_MULTICAST)
      printf("M");
    #ifdef HAVE_DYNAMIC
    if (ife->flags & IFF_DYNAMIC)
    printf("d");
    #endif
    if (ife->flags & IFF_PROMISC)
    printf("P");
    if (ife->flags & IFF_NOTRAILERS)
    printf("N");
    if (ife->flags & IFF_NOARP)
    printf("O");
    if (ife->flags & IFF_POINTOPOINT)
    printf("P");
    if (ife->flags & IFF_SLAVE)
    printf("s");
    if (ife->flags & IFF_MASTER)
    printf("m");
    if (ife->flags & IFF_RUNNING)
    printf("R");
    if (ife->flags & IFF_UP)
    printf("U");
    /* DONT FORGET TO ADD THE FLAGS IN ife_print_long, too */
    printf("\n");
  }

  void ife_print_long(struct interface *ife)
  {
    printf("interface: ife_print_long\n");
    const struct aftype *ap;
    const struct hwtype *hw;
    int hf;
    int can_compress = 0;
    unsigned long long rx, tx, short_rx, short_tx;
    const char *Rext = "B";
    const char *Text = "B";
    static char flags[200];

    #if HAVE_AFIPX
    static const struct aftype *ipxtype = NULL;
    #endif
    #if HAVE_AFECONET
    static const struct aftype *ectype = NULL;
    #endif
    #if HAVE_AFATALK
    static const struct aftype *ddptype = NULL;
    #endif
    #if HAVE_AFINET6
    FILE *f;
    char addr6[40], devname[21];
    struct sockaddr_storage sas;
    int plen, scope, dad_status, if_idx;
    extern struct aftype inet6_aftype;
    char addr6p[8][5];
    #endif

    ap = get_afntype(ife->addr.sa_family);
    if (ap == NULL)
      ap = get_afntype(0);

    hf = ife->type;

    hw = get_hwntype(hf);
    if (hw == NULL)
      hw = get_hwntype(-1);

    sprintf(flags, "flags=%d<", ife->flags);
    /* DONT FORGET TO ADD THE FLAGS IN ife_print_short, too */
    if (ife->flags == 0)
      strcat(flags,">");
    if (ife->flags & IFF_UP)
      strcat(flags,_("UP,"));
    if (ife->flags & IFF_BROADCAST)
      strcat(flags,_("BROADCAST,"));
    if (ife->flags & IFF_DEBUG)
      strcat(flags,_("DEBUG,"));
    if (ife->flags & IFF_LOOPBACK)
      strcat(flags,_("LOOPBACK,"));
    if (ife->flags & IFF_POINTOPOINT)
      strcat(flags,_("POINTOPOINT,"));
    if (ife->flags & IFF_NOTRAILERS)
      strcat(flags,_("NOTRAILERS,"));
    if (ife->flags & IFF_RUNNING)
      strcat(flags,_("RUNNING,"));
    if (ife->flags & IFF_NOARP)
      strcat(flags,_("NOARP,"));
    if (ife->flags & IFF_PROMISC)
      strcat(flags,_("PROMISC,"));
    if (ife->flags & IFF_ALLMULTI)
      strcat(flags,_("ALLMULTI,"));
    if (ife->flags & IFF_SLAVE)
      strcat(flags,_("SLAVE,"));
    if (ife->flags & IFF_MASTER)
      strcat(flags,_("MASTER,"));
    if (ife->flags & IFF_MULTICAST)
      strcat(flags,_("MULTICAST,"));
    #ifdef HAVE_DYNAMIC
    if (ife->flags & IFF_DYNAMIC)
      strcat(flags,_("DYNAMIC,"));
    #endif
    /* DONT FORGET TO ADD THE FLAGS IN ife_print_short */
    /* remove the trailing comma */
    if (flags[strlen(flags)-1] == ',')
      flags[strlen(flags)-1] = '>';
    else
      flags[strlen(flags)-1] = 0;


    printf(_("%s: %s  mtu %d\n"),
    ife->name, flags, ife->mtu);

    /* print addresses */
    struct sockaddr_spp saddr = *((struct sockaddr_spp *) &(ife->sppaddr));
    printf("        spp addr: %d \n", (saddr.sspp_addr).spp_apid);

    if (ife->tx_queue_len != -1)
    printf(_("        txqueuelen %d"), ife->tx_queue_len);

    printf("        (%s)\n", "Serial Line IP"); /* TODO: hw->title...make this work */

    #ifdef IFF_PORTSEL
    if (ife->flags & IFF_PORTSEL) {
      printf(_("        media %s"), if_port_text[ife->map.port][0]);
      if (ife->flags & IFF_AUTOMEDIA)
      printf(_("autoselect"));
      printf("\n");
    }
    #endif


    /* If needed, display the interface statistics. */

    if (ife->statistics_valid) {
      /* XXX: statistics are currently only printed for the primary address,
      *      not for the aliases, although strictly speaking they're shared
      *      by all addresses.
      */
      rx = ife->stats.rx_bytes;
      short_rx = rx * 10;
      /* determine units to use for rx, and scale rx respectively */
      if (rx > 1125899906842624ull) {
        if (rx > (9223372036854775807ull / 10))
        short_rx = rx / 112589990684262ull;
        else
        short_rx /= 1125899906842624ull;
        Rext = "PiB";
      } else if (rx > 1099511627776ull) {
        short_rx /= 1099511627776ull;
        Rext = "TiB";
      } else if (rx > 1073741824ull) {
        short_rx /= 1073741824ull;
        Rext = "GiB";
      } else if (rx > 1048576) {
        short_rx /= 1048576;
        Rext = "MiB";
      } else if (rx > 1024) {
        short_rx /= 1024;
        Rext = "KiB";
      }
      tx = ife->stats.tx_bytes;
      short_tx = tx * 10;
      /* determine units to use for tx, and scale tx respectively */
      if (tx > 1125899906842624ull) {
        if (tx > (9223372036854775807ull / 10))
        short_tx = tx / 112589990684262ull;
        else
        short_tx /= 1125899906842624ull;
        Text = "PiB";
      } else 	if (tx > 1099511627776ull) {
        short_tx /= 1099511627776ull;
        Text = "TiB";
      } else if (tx > 1073741824ull) {
        short_tx /= 1073741824ull;
        Text = "GiB";
      } else if (tx > 1048576) {
        short_tx /= 1048576;
        Text = "MiB";
      } else if (tx > 1024) {
        short_tx /= 1024;
        Text = "KiB";
      }

      printf("        ");
      printf(_("RX packets %llu  bytes %llu (%lu.%lu %s)\n"),
      ife->stats.rx_packets,
      rx, (unsigned long)(short_rx / 10),
      (unsigned long)(short_rx % 10), Rext);

      printf("        ");
      printf(_("RX errors %lu  dropped %lu  overruns %lu  frame %lu\n"),
      ife->stats.rx_errors, ife->stats.rx_dropped,
      ife->stats.rx_fifo_errors, ife->stats.rx_frame_errors);


      printf("        ");
      printf(_("TX packets %llu  bytes %llu (%lu.%lu %s)\n"),
      ife->stats.tx_packets,
      tx, (unsigned long)(short_tx / 10),
      (unsigned long)(short_tx % 10), Text);

      printf("        ");
      printf(_("TX errors %lu  dropped %lu overruns %lu  carrier %lu  collisions %lu\n"),
      ife->stats.tx_errors,
      ife->stats.tx_dropped, ife->stats.tx_fifo_errors,
      ife->stats.tx_carrier_errors, ife->stats.collisions);
    }

    if ((ife->map.irq || ife->map.mem_start || ife->map.dma ||
      ife->map.base_addr >= 0x100)) {
        printf("        device ");
        if (ife->map.irq)
        printf(_("interrupt %d  "), ife->map.irq);
        if (ife->map.base_addr >= 0x100)	/* Only print devices using it for
        I/O maps */
        printf(_("base 0x%x  "), ife->map.base_addr);
        if (ife->map.mem_start) {
          printf(_("memory 0x%lx-%lx  "), ife->map.mem_start, ife->map.mem_end);
        }
        if (ife->map.dma)
        printf(_("  dma 0x%x"), ife->map.dma);
        printf("\n");
      }
      printf("\n");
    }

    void ife_print(struct interface *i)
    {
      printf("interface: ife_print\n");
      if (ife_short) /* -s was a parameter */
        ife_print_short(i);
      else /* no -s given */
        ife_print_long(i);
    }
