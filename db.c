/*
 * Copyright (c) 1990, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 1999, 2000
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
 * db - arpwatch database routines
 */

#include <sys/types.h>

#include <netinet/in.h>

#include <ctype.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#include "arpwatch.h"
#include "db.h"
#include "dns.h"
#include "ec.h"
#include "report.h"
#include "util.h"

#define HASHSIZE (2 << 15)

#define NEWACTIVITY_DELTA (6*30*24*60*60)	/* 6 months in seconds */
#define FLIPFLIP_DELTA (24*60*60)	/* 24 hours in seconds */

/* Ethernet info */
/*
 Ramp up h[] from 34 to 64 -Freek
 Original comment:
 DNS name components can be up to 63 octets, and
 that's not counting non-alphanumerics that may
 get expanded to \nnn. --okir
 */
struct einfo {
	u_char e[6];		/* ether address */
	char h[64];		/* simple hostname */
	time_t t;		/* timestamp */
};

/* Address info */
struct ainfo {
	u_int32_t a;		/* ip address */
	struct einfo **elist;	/* array of pointers */
	int ecount;		/* elements in use of elist */
	int esize;		/* size of elist */
	struct ainfo *next;
};

/* Address hash table */
static struct ainfo ainfo_table[HASHSIZE];

static void alist_alloc(struct ainfo *);
int cmpeinfo(const void *, const void *);
static struct einfo *elist_alloc(u_int32_t, u_char *, time_t, char *);
static struct ainfo *ainfo_find(u_int32_t);
static void check_hname(struct ainfo *);
struct ainfo *newainfo(void);

int ent_add(u_int32_t a, u_char * e, time_t t, char *h)
{
	struct ainfo *ap;
	struct einfo *ep;
	int i;
	u_int len;
	u_char *e2;
	time_t t2;

	/* Ignore 0.0.0.0 */
	if (a == 0) {
		return(1);
	}

	/* Lookup ip address */
	ap = ainfo_find(a);

	/* Check for the usual case first */
	if(ap->ecount > 0) {
		ep = ap->elist[0];
		if(MEMCMP(e, ep->e, 6) == 0) {
			if(t - ep->t > NEWACTIVITY_DELTA) {
				report(ACTION_ACTIVITY, a, e, NULL, &t, &ep->t);
				check_hname(ap);
			}
			ep->t = t;
			return (1);
		}
	}

	/* Check for a virgin ainfo record */
	if(ap->ecount == 0) {
		ap->ecount = 1;
		ap->elist[0] = elist_alloc(a, e, t, h);
		report(ACTION_NEW, a, e, NULL, &t, NULL);
		return (1);
	}

	/* Check for a flip-flop */
	if(ap->ecount > 1) {
		ep = ap->elist[1];
		if(MEMCMP(e, ep->e, 6) == 0) {
			/*
			 * Suppress report when less than
			 * FLIPFLOP_DELTA and one of the two ethernet
			 * addresses is a DECnet logical.
			 */
			t2 = ap->elist[0]->t;
			e2 = ap->elist[0]->e;
			report(ACTION_FLIPFLOP, a, e, e2, &t, &t2);
			ap->elist[1] = ap->elist[0];
			ap->elist[0] = ep;
			ep->t = t;
			check_hname(ap);
			return (1);
		}
	}

	for(i = 2; i < ap->ecount; ++i) {
		ep = ap->elist[i];
		if(MEMCMP(e, ep->e, 6) == 0) {
			/* An old entry comes to life */
			e2 = ap->elist[0]->e;
			t2 = ap->elist[0]->t;
			report(ACTION_REUSED, a, e, e2, &t, &t2);
			/* Shift entries down */
			len = i * sizeof(ap->elist[0]);
			BCOPY(&ap->elist[0], &ap->elist[1], len);
			ap->elist[0] = ep;
			ep->t = t;
			check_hname(ap);
			return (1);
		}
	}

	/* New ether address */
	e2 = ap->elist[0]->e;
	t2 = ap->elist[0]->t;
	report(ACTION_CHANGED, a, e, e2, &t, &t2);
	/* Make room at head of list */
	alist_alloc(ap);
	len = ap->ecount * sizeof(ap->elist[0]);
	BCOPY(&ap->elist[0], &ap->elist[1], len);
	ap->elist[0] = elist_alloc(a, e, t, h);
	++ap->ecount;
	return (1);
}

static struct ainfo *ainfo_find(u_int32_t a)
{
	u_int size;
	struct ainfo *ap;

	ap = &ainfo_table[a & (HASHSIZE - 1)];
	for(;;) {
		if(ap->esize == 0) {
			/* Emtpy cell; use it */
			ap->a = a;
			break;
		}
		if(a == ap->a)
			break;

		if(ap->next != NULL) {
			/* Try linked cell */
			ap = ap->next;
			continue;
		}
		/* We collided, allocate new struct */
		ap->next = newainfo();
		ap = ap->next;
		ap->a = a;
		break;
	}
	if(ap->esize == 0) {
		ap->esize = 2;
		size = sizeof(ap->elist[0]) * ap->esize;
		ap->elist = (struct einfo **)malloc(size);
		if(ap->elist == NULL) {
			syslog(LOG_ERR, "ainfo_find(): malloc: %m");
			exit(1);
		}
		MEMSET(ap->elist, 0, size);
	}
	return (ap);
}

int ent_loop(ent_process fn)
{
	int i, j, n;
	struct ainfo *ap;
	struct einfo *ep;

	n = 0;
	for(i = 0; i < HASHSIZE; ++i)
		for(ap = &ainfo_table[i]; ap != NULL; ap = ap->next)
			for(j = 0; j < ap->ecount; ++j) {
				ep = ap->elist[j];
				/* and call the dumping function pointer */
				(*fn)(ap->a, ep->e, ep->t, ep->h);
				
				++n;
			}
	return (n);
}

/* Insure enough room for at least one more einfo pointer */
static void alist_alloc(struct ainfo *ap)
{
	u_int size;

	if(ap->esize == 0) {
		syslog(LOG_ERR, "alist_alloc(): esize 0, can't happen");
		exit(1);
	}
	if(ap->ecount < ap->esize)
		return;
	ap->esize += 2;
	size = ap->esize * sizeof(ap->elist[0]);
	ap->elist = (struct einfo **)realloc(ap->elist, size);
	if(ap->elist == NULL) {
		syslog(LOG_ERR, "alist_alloc(): realloc(): %m");
		exit(1);
	}
	size = (ap->esize - ap->ecount) * sizeof(ap->elist[0]);
	MEMSET(&ap->elist[ap->ecount], 0, size);
}

/* Allocate and initialize a elist struct */
static struct einfo *elist_alloc(u_int32_t a, u_char * e, time_t t, char *h)
{
	struct einfo *ep;
	u_int size;
	static struct einfo *elist = NULL;
	static int eleft = 0;

	if(eleft <= 0) {
		/* Allocate some more */
		eleft = 16;
		size = eleft * sizeof(struct einfo);
		elist = (struct einfo *)malloc(size);
		if(elist == NULL) {
			syslog(LOG_ERR, "elist_alloc(): malloc: %m");
			exit(1);
		}
		MEMSET(elist, 0, size);
	}

	ep = elist++;
	--eleft;
	BCOPY(e, ep->e, 6);
	if(h == NULL && !initializing)
		h = getsname(a);
	if(h != NULL && !isdigit((int)*h)) {
                /* this came from SUSE, for safety -Freek */
		memset(ep->h, 0, sizeof(ep->h));
		strncpy(ep->h, h, sizeof(ep->h)-1);
	}
	ep->t = t;

	return (ep);
}

/* Check to see if the simple hostname needs updating; syslog if so */
static void check_hname(struct ainfo *ap)
{
	struct einfo *ep;
	char *h;

	/* Don't waste time if we're loading the initial arp.dat */
	if(initializing)
		return;
	ep = ap->elist[0];
	h = getsname(ap->a);

	if(!isdigit((int)*h) && strcmp(h, ep->h) != 0) {
		syslog(LOG_INFO, "hostname changed %s %s %s -> %s", intoa(ap->a), e2str(ep->e), ep->h, h);

		/* this came from SUSE, for safety -Freek */
		memset(ep->h, 0, sizeof(ep->h));
		strncpy(ep->h, h, sizeof(ep->h)-1);
	}
}

int cmpeinfo(const void *p1, const void *p2)
{
	time_t t1, t2;

	t1 = (*(struct einfo **)p1)->t;
	t2 = (*(struct einfo **)p2)->t;
	if(t1 > t2)
		return (-1);
	if(t1 < t2)
		return (1);
	return (0);
}

void sorteinfo(void)
{
	int i;
	struct ainfo *ap;

	for(i = 0; i < HASHSIZE; ++i)
		for(ap = &ainfo_table[i]; ap != NULL; ap = ap->next)
			if(ap->ecount > 0)
				qsort(ap->elist, ap->ecount, sizeof(ap->elist[0]), cmpeinfo);
}

struct ainfo *newainfo(void)
{
	struct ainfo *ap;
	u_int size;
	static struct ainfo *ainfoptr = NULL;
	static u_int ainfosize = 0;

	if(ainfosize == 0) {
		ainfosize = 512;
		size = ainfosize * sizeof(*ap);
		ap = (struct ainfo *)malloc(size);
		if(ap == NULL) {
			syslog(LOG_ERR, "newainfo(): malloc: %m");
			exit(1);
		}
		memset((char *)ap, 0, size);
		ainfoptr = ap;
	}
	ap = ainfoptr++;
	--ainfosize;
	return (ap);
}


void debugdump(void)
{
	int i, j;
	time_t t;
	struct ainfo *ap;
	struct einfo *ep;

	for(i = 0; i < HASHSIZE; ++i)
		for(ap = &ainfo_table[i]; ap != NULL; ap = ap->next) {
			if(ap->esize == 0)
				continue;
			if(ap->ecount == 0) {
				printf("%s\n", intoa(ap->a));
				continue;
			}
			t = 0;
			for(j = 0; j < ap->ecount; ++j) {
				ep = ap->elist[j];
				if(t != 0 && t < ep->t)
					printf("*");
				printf("%s\t%s\t%u\t%s\n", intoa(ap->a), e2str(ep->e), (u_int) ep->t, ep->h);
				t = ep->t;
			}
		}
}
