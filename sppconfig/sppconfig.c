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

#define DFLT_AF "inet"

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
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
	     fprintf(stderr, _("%s: ERROR while getting interface flags: %s\n"),
		     ifname,	strerror(errno));
       return (-1);
    }
    safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
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
    int fd;

    if (strchr(ifname, ':')) {
        /* This is a v4 alias interface.  Downing it via a socket for
	   another AF may have bad consequences. */
        fd = get_socket_for_af(AF_INET);
	if (fd < 0) {
	    fprintf(stderr, _("No support for INET on this system.\n"));
	    return -1;
	}
    } else
        fd = skfd;

    safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
    	fprintf(stderr, _("%s: ERROR while getting interface flags: %s\n"),
    		ifname, strerror(errno));
    	return -1;
    }
    safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_flags &= ~flag;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
    	perror("SIOCSIFFLAGS");
    	return -1;
    }
    return (0);
}

/** test is a specified flag is set */
static int test_flag(char *ifname, short flags)
{
    struct ifreq ifr;
    int fd;

    if (strchr(ifname, ':')) {
        /* This is a v4 alias interface.  Downing it via a socket for
	   another AF may have bad consequences. */
        fd = get_socket_for_af(AF_INET);
	if (fd < 0) {
	    fprintf(stderr, _("No support for INET on this system.\n"));
	    return -1;
	}
    } else
        fd = skfd;

    safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
	fprintf(stderr, _("%s: ERROR while testing interface flags: %s\n"),
		ifname, strerror(errno));
	return -1;
    }
    return (ifr.ifr_flags & flags);
}

static void usage(void)
{
    fprintf(stderr, _("Usage:\n  sppconfig [-a] [-v] [-s] <interface> \n"));
    fprintf(stderr, _("  [[-]pointopoint [<address>]]\n"));
    fprintf(stderr, _("  [hw <HW> <address>]  [mtu <NN>]\n"));
    fprintf(stderr, _("  [[-]arp]\n"));
    fprintf(stderr, _("  [mem_start <NN>]  [io_addr <NN>]  [irq <NN>]  [media <type>]\n"));
#ifdef HAVE_TXQUEUELEN
    fprintf(stderr, _("  [txqueuelen <NN>]\n"));
#endif
    fprintf(stderr, _("  [up|down] ...\n\n"));

    fprintf(stderr, _("  <HW>=Hardware Type.\n"));
    fprintf(stderr, _("  List of possible hardware types:\n"));
    print_hwlist(0); /* 1 = ARPable */
    fprintf(stderr, _("  <AF>=Address family. Default: %s\n"), DFLT_AF);
    fprintf(stderr, _("  List of possible address families:\n"));
    print_aflist(0); /* 1 = routeable */
    exit(E_USAGE);
}

static void version(void)
{
    fprintf(stderr, "%s\n", Release);
    exit(E_VERSION);
}

static int set_netmask(int skfd, struct ifreq *ifr, struct sockaddr *sa)
{
    int err = 0;

    memcpy(&ifr->ifr_netmask, sa, sizeof(struct sockaddr));
    if (ioctl(skfd, SIOCSIFNETMASK, ifr) < 0) {
    	fprintf(stderr, "SIOCSIFNETMASK: %s\n",
    		strerror(errno));
    	err = 1;
    }
    return err;
}

int main(int argc, char **argv)
{
    struct sockaddr_storage _sa, _samask;
    struct sockaddr *sa = (struct sockaddr *)&_sa;
    struct sockaddr *samask = (struct sockaddr *)&_samask;
    struct sockaddr_in *sin = (struct sockaddr_in *)&_sa;
    char host[128];
    const struct aftype *ap;
  //  const struct hwtype *hw;
    struct ifreq ifr;
    int goterr = 0, didnetmask = 0, neednetmask=0;
    char **strpp;
    //int fd;
#if HAVE_AFINET6
    extern struct aftype inet6_aftype;
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&_sa;
    struct in6_ifreq ifr6;
    unsigned long prefix_len;
    char *cp;
#endif
#if HAVE_AFINET
    extern struct aftype inet_aftype;
#endif

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
    	perror("socket");
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
    	int err = if_print(ifr.ifr_name);
    	(void) close(skfd);
    	exit(err < 0);
    }

    /* The next argument is either an address family name, or an option. */
    if ((ap = get_aftype(*strpp)) != NULL)
    	strpp++; /* it was a AF name */
    else
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

	if (!strcmp(*strpp, "mem_start")) {
	    if (*++strpp == NULL)
		usage();
	    if (ioctl(skfd, SIOCGIFMAP, &ifr) < 0) {
		fprintf(stderr, "mem_start: SIOCGIFMAP: %s\n", strerror(errno));
		strpp++;
		goterr = 1;
		continue;
	    }
	    ifr.ifr_map.mem_start = strtoul(*strpp, NULL, 0);
	    if (ioctl(skfd, SIOCSIFMAP, &ifr) < 0) {
		fprintf(stderr, "mem_start: SIOCSIFMAP: %s\n", strerror(errno));
		goterr = 1;
	    }
	    strpp++;
	    continue;
	}
	if (!strcmp(*strpp, "io_addr")) {
	    if (*++strpp == NULL)
		usage();
	    if (ioctl(skfd, SIOCGIFMAP, &ifr) < 0) {
		fprintf(stderr, "io_addr: SIOCGIFMAP: %s\n", strerror(errno));
		strpp++;
		goterr = 1;
		continue;
	    }
	    ifr.ifr_map.base_addr = strtol(*strpp, NULL, 0);
	    if (ioctl(skfd, SIOCSIFMAP, &ifr) < 0) {
		fprintf(stderr, "io_addr: SIOCSIFMAP: %s\n", strerror(errno));
		goterr = 1;
	    }
	    strpp++;
	    continue;
	}
	if (!strcmp(*strpp, "irq")) {
	    if (*++strpp == NULL)
		usage();
	    if (ioctl(skfd, SIOCGIFMAP, &ifr) < 0) {
		fprintf(stderr, "irq: SIOCGIFMAP: %s\n", strerror(errno));
		goterr = 1;
		strpp++;
		continue;
	    }
	    ifr.ifr_map.irq = atoi(*strpp);
	    if (ioctl(skfd, SIOCSIFMAP, &ifr) < 0) {
		fprintf(stderr, "irq: SIOCSIFMAP: %s\n", strerror(errno));
		goterr = 1;
	    }
	    strpp++;
	    continue;
	}
	if (!strcmp(*strpp, "-pointopoint")) {
	    goterr |= clr_flag(ifr.ifr_name, IFF_POINTOPOINT);
	    strpp++;
	    if (test_flag(ifr.ifr_name, IFF_POINTOPOINT) > 0)
	    	fprintf(stderr, _("Warning: Interface %s still in POINTOPOINT mode.\n"), ifr.ifr_name);
	    continue;
	}
	if (!strcmp(*strpp, "pointopoint")) {
	    if (*(strpp + 1) != NULL) {
		strpp++;
		safe_strncpy(host, *strpp, (sizeof host));
		if (ap->input(0, host, &_sa)) {
		    if (ap->herror)
		    	ap->herror(host);
		    else
		    	fprintf(stderr, _("sppconfig: Error resolving '%s' for pointopoint\n"), host);
		    goterr = 1;
		    strpp++;
		    continue;
		}
		memcpy(&ifr.ifr_dstaddr, sa, sizeof(struct sockaddr));
		if (ioctl(ap->fd, SIOCSIFDSTADDR, &ifr) < 0) {
		    fprintf(stderr, "SIOCSIFDSTADDR: %s\n",
			    strerror(errno));
		    goterr = 1;
		}
	    }
	    goterr |= set_flag(ifr.ifr_name, IFF_POINTOPOINT);
	    strpp++;
	    continue;
	}

	/* If the next argument is a valid hostname, assume OK. */
  /* TODO: Figure out what this section does and if it is needed for SPP */
	safe_strncpy(host, *strpp, (sizeof host));

	/* FIXME: sa is too small for INET6 addresses, inet6 should use that too */
	if (ap->getmask) {
	    switch (ap->getmask(host, &_samask, NULL)) {
	    case -1:
		usage();
		break;
	    case 1:
		if (didnetmask)
		    usage();

		// remeber to set the netmask from samask later
		neednetmask = 1;
		break;
	    }
	}
	if (ap->input == NULL) {
	   fprintf(stderr, _("sppconfig: Cannot set address for this protocol family.\n"));
	   exit(1);
	}
	if (ap->input(0, host, &_sa) < 0) {
	    if (ap->herror)
	    	ap->herror(host);
	    else
	    	fprintf(stderr,_("sppconfig: error resolving '%s' to set address for af=%s\n"), host, ap->name); fprintf(stderr,
	    _("sppconfig: `--help' gives usage information.\n")); exit(1);
	}
	memcpy(&ifr.ifr_addr, sa, sizeof(struct sockaddr));
	{
	    int r = 0;		/* to shut gcc up */
	    switch (ap->af) {
#if HAVE_AFINET
	    case AF_INET:
		fd = get_socket_for_af(AF_INET);
		if (fd < 0) {
		    fprintf(stderr, _("No support for INET on this system.\n"));
		    exit(1);
		}
		r = ioctl(fd, SIOCSIFADDR, &ifr);
		break;
#endif
#if HAVE_AFECONET
	    case AF_ECONET:
		fd = get_socket_for_af(AF_ECONET);
		if (fd < 0) {
		    fprintf(stderr, _("No support for ECONET on this system.\n"));
		    exit(1);
		}
		r = ioctl(fd, SIOCSIFADDR, &ifr);
		break;
#endif
	    default:
		fprintf(stderr,
		_("Don't know how to set addresses for family %d.\n"), ap->af);
		exit(1);
	    }
	    if (r < 0) {
		perror("SIOCSIFADDR");
		goterr = 1;
	    }
	}

       /*
        * Don't do the set_flag() if the address is an alias with a - at the
        * end, since it's deleted already! - Roman
        * Same goes if they used address 0.0.0.0 as the kernel uses this to
        * destroy aliases.
        *
        * Should really use regex.h here, not sure though how well it'll go
        * with the cross-platform support etc.
        */
        {
            char *ptr;
            short int found_colon = 0;
            short int bring_up = 1;
            for (ptr = ifr.ifr_name; *ptr; ptr++ )
                if (*ptr == ':') found_colon++;

            if (found_colon) {
                if (ptr[-1] == '-')
                    bring_up = 0;
                else if (ap->af == AF_INET && sin->sin_addr.s_addr == 0)
                    bring_up = 0;
            }

            if (bring_up)
                goterr |= set_flag(ifr.ifr_name, (IFF_UP | IFF_RUNNING));
        }

	strpp++;
    }

    if (neednetmask) {
    	goterr |= set_netmask(skfd, &ifr, samask);
    	didnetmask++;
    }

    if (opt_v && goterr)
    	fprintf(stderr, _("WARNING: at least one error occured. (%d)\n"), goterr);

    return (goterr);
} /* End of main */

struct ifcmd {
    int flag;
    unsigned long addr;
    char *base;
    int baselen;
};

//static unsigned char searcher[256];

// static int set_ip_using(const char *name, int c, unsigned long ip)
// {
//     struct ifreq ifr;
//     struct sockaddr_in sin;
//
//     safe_strncpy(ifr.ifr_name, name, IFNAMSIZ);
//     memset(&sin, 0, sizeof(struct sockaddr));
//     sin.sin_family = AF_INET;
//     sin.sin_addr.s_addr = ip;
//     memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
//     if (ioctl(skfd, c, &ifr) < 0)
// 	return -1;
//     return 0;
// }
//
// static int do_ifcmd(struct interface *x, struct ifcmd *ptr)
// {
//     char *z, *e;
//     struct sockaddr_in *sin;
//     int i;
//
//     if (do_if_fetch(x) < 0)
// 	return 0;
//     if (strncmp(x->name, ptr->base, ptr->baselen) != 0)
// 	return 0; /* skip */
//     z = strchr(x->name, ':');
//     if (!z || !*z)
// 	return 0;
//     z++;
//     for (e = z; *e; e++)
// 	if (*e == '-') /* deleted */
// 	    return 0;
//     i = atoi(z);
//     if (i < 0 || i > 255)
// 	abort();
//     searcher[i] = 1;
//
//     /* copy */
//     sin = (struct sockaddr_in *)&x->dstaddr_sas;
//     if (sin->sin_addr.s_addr != ptr->addr) {
// 	return 0;
//     }
//
//     if (ptr->flag) {
// 	/* turn UP */
// 	if (set_flag(x->name, IFF_UP | IFF_RUNNING) == -1)
// 	    return -1;
//     } else {
// 	/* turn DOWN */
// 	if (clr_flag(x->name, IFF_UP) == -1)
// 	    return -1;
//     }
//
//     return 1; /* all done! */
// }
