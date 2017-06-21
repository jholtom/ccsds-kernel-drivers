/*
 * ifconfig   This file contains an implementation of the command
 *              that either displays or sets the characteristics of
 *              one or more of the system's networking interfaces.
 *
 * Version:     $Id: ifconfig.c,v 1.59 2011-01-01 03:22:31 ecki Exp $
 *
 * Author:      Fred N. van Kempen, <waltje@uwalt.nl.mugnet.org>
 *              and others.  Copyright 1993 MicroWalt Corporation
 *
 *              This program is free software; you can redistribute it
 *              and/or  modify it under  the terms of  the GNU General
 *              Public  License as  published  by  the  Free  Software
 *              Foundation;  either  version 2 of the License, or  (at
 *              your option) any later version.
 *
 * Patched to support 'add' and 'del' keywords for INET(4) addresses
 * by Mrs. Brisby <mrs.brisby@nimh.org>
 *
 * {1.34} - 19980630 - Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 *                     - gettext instead of catgets for i18n
 *          10/1998  - Andi Kleen. Use interface list primitives.
 *	    20001008 - Bernd Eckenfels, Patch from RH for setting mtu
 *			(default AF was wrong)
 *          20010404 - Arnaldo Carvalho de Melo, use setlocale
 *
 * Modified by Jacob Willis and Jacob Holtom to act as a standalone config
 * tool for Space Packet Protocol.
 */

#define DFLT_AF "spp"

//#include "config.h"

#include <features.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

//#include <linux/spp.h>
#include <netspp/spp.h>

/* Ugh.  But libc5 doesn't provide POSIX types.  */
#include <asm/types.h>


#include <linux/if_slip.h>

#if HAVE_AFIPX
#if (__GLIBC__ > 2) || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 1)
#include <netipx/ipx.h>
#warning "using <netipx/ipx.h>"
#else
#include "ipx.h"
#warning "using ipx.h"
#endif
#endif
#include "net-support.h"
#include "pathnames.h"
#include "version.h"
#include "intl.h"
#include "interface.h"
#include "sockets.h"
#include "util.h"

static char *Release = RELEASE;

int opt_a = 0;			/* show all interfaces          */
int opt_v = 0;			/* debugging output flag        */

int addr_family = 0;		/* currently selected AF        */

void spp2ascii(char *buf, const spp_address *addr)
{
    snprintf(buf,sizeof(buf),"%d",addr->spp_apid);
}

void ascii2spp(spp_address *addr, const char *buf)
{
    unsigned int apid;
    sscanf(buf,"%d",&apid);
    addr->spp_apid = apid;
}

int sppcmp(const spp_address *addr1, const spp_address *addr2)
{
    if(addr1->spp_apid == addr2->spp_apid)
        return 0;
    return 1;
}

int sppval(const spp_address *addr)
{
    if(addr->spp_apid <= 2047 && addr->spp_apid >= 0)
        return 0;
    return 1;
}

static int if_print(char *ifname)
{
    int res;

    if (ife_short)
	printf(_("Iface      MTU    RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR Flg\n"));

    if (!ifname) {
	res = for_all_interfaces(do_if_print, &opt_a);
    } else {
	struct interface *ife;

	ife = lookup_interface(ifname);
	if (!ife) {
		return -1;
	}
	res = do_if_fetch(ife);
	if (res >= 0)
	    ife_print(ife);
    }
    return res;
}

/* Set a certain interface flag. */
static int set_flag(char *ifname, short flag)
{
    struct ifreq ifr;

    safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    /* Get the flags currently set */
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
	     fprintf(stderr, _("%s: ERROR while getting interface flags: %s\n"),
		     ifname,	strerror(errno));
       return (-1);
    }
    safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    /* or in the requested flag, and set it with ioctl */
    ifr.ifr_flags |= flag;
    if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0) {
    	perror("SIOCSIFFLAGS");
    	return -1;
    }
    return (0);
}

/* Clear a certain interface flag. */
static int clr_flag(char *ifname, short flag)
{
    struct ifreq ifr;

    safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    /* get currently set flags */
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
    	fprintf(stderr, _("%s: ERROR while getting interface flags: %s\n"),
    		ifname, strerror(errno));
    	return -1;
    }
    safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    /* clear requested flag */
    ifr.ifr_flags &= ~flag;
    if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0) {
    	perror("SIOCSIFFLAGS");
    	return -1;
    }
    return (0);
}

/** test if a specified flag is set */
static int test_flag(char *ifname, short flags)
{
    struct ifreq ifr;

    safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
	fprintf(stderr, _("%s: ERROR while testing interface flags: %s\n"),
		ifname, strerror(errno));
	return -1;
    }
    return (ifr.ifr_flags & flags);
}

static void usage(void)
{
    fprintf(stderr, _("Usage:\n  sppconfig [-a] [-v] [-s] <interface> \n"));
    fprintf(stderr, _("  [[-]pointopoint] [mtu <NN>] [[-]arp]\n"));
    fprintf(stderr, _("  [add <address>] [del <address>] [media <type>]\n"));
#ifdef HAVE_TXQUEUELEN
    fprintf(stderr, _("  [txqueuelen <NN>]\n"));
#endif
    fprintf(stderr, _("  [up|down] ...\n\n"));
    fprintf(stderr, _("  Address family default: %s\n"), DFLT_AF);
    exit(E_USAGE);
}

static void version(void)
{
    fprintf(stderr, "%s\n", Release);
    exit(E_VERSION);
}

int main(int argc, char **argv)
{
  //  struct sockaddr_storage _sa;
  //  struct sockaddr *sa = (struct sockaddr *)&_sa;
  //  struct sockaddr_in *sin = (struct sockaddr_in *)&_sa;

    /* FIXME: Properly declare a sockaddr_spp */
    struct sockaddr_spp _sa;
    struct sockaddr_spp *skadrspp = &_sa;

    char host[128];
    const struct aftype *ap;
    struct ifreq ifr;
    int goterr = 0, didnetmask = 0, neednetmask=0;
    char **strpp;

#if I18N
    setlocale(LC_ALL, "");
    bindtextdomain("net-tools", "/usr/share/locale");
    textdomain("net-tools");
#endif

    /* Find any options that preceed the interface name.*/
    argc--;
    argv++;
    while (argc && *argv[0] == '-') {
    	if (!strcmp(*argv, "-a"))
    	    opt_a = 1;

    	else if (!strcmp(*argv, "-s"))
    	    ife_short = 1;

    	else if (!strcmp(*argv, "-v"))
    	    opt_v = 1;

    	else if (!strcmp(*argv, "-V") || !strcmp(*argv, "-version") ||
    	    !strcmp(*argv, "--version"))
    	    version();

    	else if (!strcmp(*argv, "-?") || !strcmp(*argv, "-h") ||
    	    !strcmp(*argv, "-help") || !strcmp(*argv, "--help"))
    	    usage();

    	else {
    	    fprintf(stderr, _("sppconfig: option `%s' not recognised.\n"),
    		    argv[0]);
    	    fprintf(stderr, _("sppconfig: `--help' gives usage information.\n"));
    	    exit(1);
    	}

    	argv++;
    	argc--;
    }

    /* Create a channel to the NET kernel. */
    if ((skfd = sockets_open(0)) < 0) {
    	perror("socket"); /* FIXME: sockets_open doesn't set errno */
    	exit(1);
    }

    /* Do we have to show the current setup? */
    if (argc == 0) {
    	int err = if_print((char *) NULL);
    	(void) close(skfd);
    	exit(err < 0);
    }

    /* No. Fetch the interface name. */
    strpp = argv;
    safe_strncpy(ifr.ifr_name, *strpp++, IFNAMSIZ);
    if (*strpp == (char *) NULL) {
      /* No other arguments, display interface status */
    	int err = if_print(ifr.ifr_name);
    	(void) close(skfd);
    	exit(err < 0);
    }

    /* Get the address family (default only)*/
    ap = get_aftype(DFLT_AF);

    if (ap) {
	    addr_family = ap->af;
      skfd = ap->fd;
    }

    /* Process the remaining arguments. */
    while (*strpp != (char *) NULL) {
    	if (!strcmp(*strpp, "arp")) {
    	    goterr |= clr_flag(ifr.ifr_name, IFF_NOARP);
    	    strpp++;
    	    continue;
    	}
    	if (!strcmp(*strpp, "-arp")) {
    	    goterr |= set_flag(ifr.ifr_name, IFF_NOARP);
    	    strpp++;
    	    continue;
    	}

#ifdef IFF_PORTSEL
    /* not currently implemented
       TODO: Add support for port selection
     */

    /*
      if (!strcmp(*strpp, "media") || !strcmp(*strpp, "port")) {
    	    if (*++strpp == NULL)
    		      usage();
    	    if (!strcasecmp(*strpp, "auto")) {
    		    goterr |= set_flag(ifr.ifr_name, IFF_AUTOMEDIA);
    	    } else {
        		int i, j, newport;
        		char *endp;
        		newport = strtol(*strpp, &endp, 10);
        		if (*endp != 0) {
        		    newport = -1;
        		    for (i = 0; if_port_text[i][0] && newport == -1; i++) {
            			for (j = 0; if_port_text[i][j]; j++) {
            			    if (!strcasecmp(*strpp, if_port_text[i][j])) {
                				newport = i;
                				break;
            			    }
            			}
        		    }
        		}
        		strpp++;
        		if (newport == -1) {
        		    fprintf(stderr, _("Unknown media type.\n"));
        		    goterr = 1;
        		} else {
        		    if (ioctl(skfd, SIOCGIFMAP, &ifr) < 0) {
            			perror("port: SIOCGIFMAP");
            			goterr = 1;
            			continue;
        		    }
        		    ifr.ifr_map.port = newport;
        		    if (ioctl(skfd, SIOCSIFMAP, &ifr) < 0) {
            			perror("port: SIOCSIFMAP");
            			goterr = 1;
        		    }
        		}
    	    }
    	    continue;
    	}
      */
#endif

    	if (!strcmp(*strpp, "up")) {
    	    goterr |= set_flag(ifr.ifr_name, (IFF_UP | IFF_RUNNING));
    	    strpp++;
    	    continue;
    	}
    	if (!strcmp(*strpp, "down")) {
    	    goterr |= clr_flag(ifr.ifr_name, IFF_UP);
    	    strpp++;
    	    continue;
    	}

      if (!strcmp(*strpp, "add")) {
          /* make sure they included an address */
    	    if (*++strpp == NULL)
    		    usage();

          /* get the spp address and convert from ascii */
          ascii2spp(&(skadrspp->sspp_addr), *strpp);
    	    ifr.ifr_addr = *(struct sockaddr *) &skadrspp;
    	    if (ioctl(skfd, SIOCSIFADDR, &ifr) < 0) {
        		fprintf(stderr, "SIOCSIFADDR: %s\n", strerror(errno));
        		goterr = 1;
    	    }
    	    strpp++;
    	    continue;
    	}

      if (!strcmp(*strpp, "del")) {
          /* make sure they included an address */
          if (*++strpp == NULL)
            usage();

          /* get the spp address and convert from ascii */
          ascii2spp(&(skadrspp->sspp_addr), *strpp);
          ifr.ifr_addr = *(struct sockaddr *) &skadrspp;
          if (ioctl(skfd, SIOCDIFADDR, &ifr) < 0) {
            fprintf(stderr, "SIOCDIFADDR: %s\n", strerror(errno));
            goterr = 1;
          }
          strpp++;
          continue;
      }

    	if (!strcmp(*strpp, "mtu")) {
    	    if (*++strpp == NULL)
    		    usage();
    	    ifr.ifr_mtu = atoi(*strpp);
    	    if (ioctl(skfd, SIOCSIFMTU, &ifr) < 0) {
        		fprintf(stderr, "SIOCSIFMTU: %s\n", strerror(errno));
        		goterr = 1;
    	    }
    	    strpp++;
    	    continue;
    	}

    	if (!strcmp(*strpp, "txqueuelen")) {
    	    if (*++strpp == NULL)
    		      usage();
    	    ifr.ifr_qlen = strtoul(*strpp, NULL, 0);
    	    if (ioctl(skfd, SIOCSIFTXQLEN, &ifr) < 0) {
        		fprintf(stderr, "SIOCSIFTXQLEN: %s\n", strerror(errno));
        		goterr = 1;
    	    }
    	    strpp++;
    	    continue;
    	}

      /* Enable or disable pointopoint mode, no address setting */
    	if (!strcmp(*strpp, "-pointopoint")) {
    	    goterr |= clr_flag(ifr.ifr_name, IFF_POINTOPOINT);
    	    strpp++;
    	    if (test_flag(ifr.ifr_name, IFF_POINTOPOINT) > 0)
    	    	fprintf(stderr, _("Warning: Interface %s still in POINTOPOINT mode.\n"), ifr.ifr_name);
    	    continue;
    	}
    	if (!strcmp(*strpp, "pointopoint")) {
    	    goterr |= set_flag(ifr.ifr_name, IFF_POINTOPOINT);
    	    strpp++;
    	    continue;
    	}

    	strpp++;
    }



    if (opt_v && goterr)
    	fprintf(stderr, _("WARNING: at least one error occured. (%d)\n"), goterr);

    return (goterr);
} /* End of main */
