/*
* lib/af.c   This file contains the top-level part of the protocol
*              support functions module for the NET-2 base distribution.
*
* Version:     $Id: af.c,v 1.14 2007/12/01 17:49:35 ecki Exp $
*
* Author:      Fred N. van Kempen, <waltje@uwalt.nl.mugnet.org>
*              Copyright 1993 MicroWalt Corporation
*
*              This program is free software; you can redistribute it
*              and/or  modify it under  the terms of  the GNU General
*              Public  License as  published  by  the  Free  Software
*              Foundation;  either  version 2 of the License, or  (at
*              your option) any later version.
*/
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#include "net-support.h"
#include "pathnames.h"
#include "intl.h"
#include "util.h"



int flag_spp;

static const struct aftrans_t {
  char *alias;
  char *name;
  int *flag;
} aftrans[] = {
  {
    "spp", "spp", &flag_spp
  },
  {
    0, 0, 0
  }
};

char afname[256] = "";

extern struct aftype spp_aftype;

static short sVafinit = 0;

struct aftype * const aftypes[] =
{
  &spp_aftype,
  NULL
};

static void afinit(void)
{
  spp_aftype.title = _("Space Packet Protocol");
  sVafinit = 1;
}

/* set the default AF list from the program name or a constant value    */
void aftrans_def(char *tool, char *argv0, char *dflt)
{
  char *tmp;
  char *buf;

  safe_strncpy(afname, dflt, sizeof(afname));

  if (!(tmp = strrchr(argv0, '/')))
  tmp = argv0;		/* no slash?! */
  else
  tmp++;

  buf = xstrdup(tmp);

  if (strlen(tool) >= strlen(tmp)) {
    free(buf);
    return;
  }
  tmp = buf + (strlen(tmp) - strlen(tool));

  if (strcmp(tmp, tool) != 0) {
    free(buf);
    return;
  }
  *tmp = '\0';
  if ((tmp = strchr(buf, '_')))
  *tmp = '\0';

  afname[0] = '\0';
  if (aftrans_opt(buf))
  safe_strncpy(afname, buf, sizeof(afname));

  free(buf);
}


/* Check our protocol family table for this family. */
const struct aftype *get_aftype(const char *name)
{
  struct aftype * const *afp;

  if (!sVafinit)
  afinit();

  afp = aftypes;
  while (*afp != NULL) {
    if (!strcmp((*afp)->name, name))
    return (*afp);
    afp++;
  }
  if (index(name, ','))
  fprintf(stderr, _("Please don't supply more than one address family.\n"));
  return (NULL);
}


/* Check our protocol family table for this family. */
const struct aftype *get_afntype(int af) {
  struct aftype * const *afp;

  if (!sVafinit)
    afinit();

  afp = aftypes;
  while (*afp != NULL) {
    if ((*afp)->af == af)
    return (*afp);
    afp++;
  }
  return (NULL);
}

/* Check our protocol family table for this family and return its socket */
int get_socket_for_af(int af)
{
  const struct aftype *afp = get_afntype(af);
  return afp ? afp->fd : -1;
}

int aftrans_opt(const char *arg)
{
  const struct aftrans_t *paft;
  char *tmp1, *tmp2;
  char buf[256];

  safe_strncpy(buf, arg, sizeof(buf));

  tmp1 = buf;

  while (tmp1) {

    tmp2 = index(tmp1, ',');

    if (tmp2)
    *(tmp2++) = '\0';

    for (paft = aftrans; paft->alias; paft++) {
      if (strcmp(tmp1, paft->alias))
      continue;
      if (strlen(paft->name) + strlen(afname) + 1 >= sizeof(afname)) {
        fprintf(stderr, _("Too much address family arguments.\n"));
        return (0);
      }
      if (paft->flag)
      (*paft->flag)++;
      if (afname[0])
      strcat(afname, ",");
      strcat(afname, paft->name);
      break;
    }
    if (!paft->alias) {
      fprintf(stderr, _("Unknown address family `%s'.\n"), tmp1);
      return (1);
    }
    tmp1 = tmp2;
  }

  return (0);
}

/* type: 0=all, 1=getroute */
void print_aflist(int type) {
  int count = 0;
  const char * txt;
  struct aftype * const *afp;

  if (!sVafinit)
  afinit();

  afp = aftypes;
  while (*afp != NULL) {
    if ((type == 1 && ((*afp)->rprint == NULL)) || ((*afp)->af == 0)) {
      afp++; continue;
    }
    if ((count % 3) == 0) fprintf(stderr,count?"\n    ":"    ");
    txt = (*afp)->name; if (!txt) txt = "..";
    fprintf(stderr,"%s (%s) ",txt,(*afp)->title);
    count++;
    afp++;
  }
  fprintf(stderr,"\n");
}
