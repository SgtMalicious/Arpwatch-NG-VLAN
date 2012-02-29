/*
 * Copyright (c) 1990, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 2000
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * ec - manufactures ethernet code routines
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#if __STDC__
struct mbuf;
struct rtentry;
#endif
#include <net/if.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <ctype.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#include "arpwatch.h"
#include "ec.h"
#include "util.h"

/* Basic data structure */
struct ecent {
	u_int32_t o;		/* first 3 octets */
	char *text;		/* associated text */
};

static struct ecent *list;
static u_int ec_last = 0;
static u_int ec_len = 0;


/* Convert an 3 octets from an ethernet address to a u_int32_t */
static int ec_a2o(char *cp, u_int32_t * op)
{
	char xbuf[128];
	u_char e[6];

	memset(&xbuf, 0, sizeof(xbuf));

	strncpy(xbuf, &cp[0], 2);
	strcat(xbuf, ":");
	strncat(xbuf, &cp[2], 2);
	strcat(xbuf, ":");
	strncat(xbuf, &cp[4], 2);
	strcat(xbuf, ":0:0:0");

	if(!str2e(xbuf, e))
		return (0);
	*op = 0;
	BCOPY(e, op, 3);
	return (1);
}

/* Add a ethernet code to the database */
int ec_add(u_int32_t o, char *text)
{

	if(ec_last >= ec_len) {
		if(list == NULL) {
			ec_len = 512;
			list = malloc(ec_len * sizeof(*list));
		} else {
			ec_len *= 2;
			list = realloc(list, ec_len * sizeof(*list));
		}
		if(list == NULL) {
			syslog(LOG_ERR, "ec_add(): malloc: %m");
			exit(1);
		}
	}
	list[ec_last].o = o;
	/*
         list[ec_last].text = savestr(text);
	 512 was the previous limit of savestr
 	 */
	list[ec_last].text=strndup(text, 512);
	++ec_last;
	return (1);
}

/* Find the manufacture for a given ethernet address */
char *ec_find(u_char * e)
{
	u_int32_t o;
	int i;

	o = 0;
	BCOPY(e, &o, 3);
	for(i = 0; i < ec_last; ++i)
		if(list[i].o == o)
			return (list[i].text);

	return (NULL);
}

/* Loop through the ethernet code database */
int ec_loop(FILE * f, ec_process fn, const char *nm)
{
	int n;
	char *cp, *cp2, *text;
	int sawblank;
	u_int32_t o;
	char line[1024];

	n = 0;
	while(fgets(line, sizeof(line), f)) {
		++n;
		cp = line;
		cp2 = cp + strlen(cp) - 1;
		if(cp2 >= cp && *cp2 == '\n')
			*cp2++ = '\0';
		if(*cp == '#')
			continue;
		if((cp2 = strchr(cp, '\t')) == 0) {
			syslog(LOG_ERR, "ec_loop(): %s:%d missing tab", nm, n);
			continue;
		}

		/* 3 octets come first */
		*cp2++ = '\0';
		text = cp2;
		if(!ec_a2o(cp, &o)) {
			syslog(LOG_ERR, "ec_loop(): %s:%d bad octets", nm, n);
			continue;
		}

		/* Compress blanks */
		cp = cp2 = text;
		sawblank = 0;
		while(*cp != '\0') {
			if(sawblank) {
				*cp2++ = ' ';
				sawblank = 0;
			}
			*cp2++ = *cp++;
			while(isspace((int)*cp)) {
				++cp;
				sawblank = 1;
			}
		}
		*cp2 = '\0';

		if(!(*fn) (o, text))
			return (0);
	}

	return (1);
}

/* DECnet local logical address prefix */
static u_char decnet[3] = { 0xaa, 0x0, 0x4 };

/* Returns true if an ethernet address is decnet, else false */
int isdecnet(u_char * e)
{
	return (MEMCMP(e, decnet, sizeof(decnet)) == 0);
}

/* Convert an ascii ethernet string to ethernet address */
int str2e(char *str, u_char * e)
{
	int i;
	u_int n[6];

	MEMSET(n, 0, sizeof(n));
	if(sscanf(str, "%x:%x:%x:%x:%x:%x", &n[0], &n[1], &n[2], &n[3], &n[4], &n[5]) != 6)
		return (0);
	for(i = 0; i < 6; ++i) {
		if(n[i] > 0xff)
			return (0);
		e[i] = n[i];
	}
	return (1);
}

/*
 Convert an ethernet address to an ascii ethernet string
 WARNING: Not reentrant nor thread-safe
 */
char *e2str(u_char * e)
{
	static char str[32];

#ifndef FANCY_MAC
        sprintf(str, "%x:%x:%x:%x:%x:%x", e[0], e[1], e[2], e[3], e[4], e[5]);
#else
        sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x", e[0], e[1], e[2], e[3], e[4], e[5]);
#endif
	return(str);
}
