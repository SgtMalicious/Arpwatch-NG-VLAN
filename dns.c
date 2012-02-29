/*
 * Copyright (c) 1992, 1993, 1994, 1995, 1996, 1998, 2000
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
 * dns - domain name system routines
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/nameser.h>
#include <arpa/inet.h>

#include <ctype.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <netdb.h>
#include <resolv.h>
#include <string.h>
#include <stdio.h>

#include "gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#include "arpwatch.h"
#include "dns.h"

#ifdef HAVE_DN_SKIPNAME
#ifndef BUFSIZ
#define BUFSIZ 1024
#endif

static char hostbuf[BUFSIZ + 1];

#if PACKETSZ > 1024
#define	MAXPACKET	PACKETSZ
#else
#define	MAXPACKET	1024
#endif

typedef union {
	HEADER hdr;
	u_char buf[MAXPACKET];
} querybuf;
#endif

int gethinfo(char *hostname, char *cpu, int cpulen, char *os, int oslen)
{
#ifdef HAVE_DN_SKIPNAME
	querybuf *qb;
	u_char *cp, *eom;
	char *bp;
	int n;
	HEADER *hp;
	int type, class, buflen, ancount, qdcount;
	querybuf qbuf;

	qb = &qbuf;
	n = res_query(hostname, C_IN, T_HINFO, qb->buf, sizeof(qb->buf));
	if(n < 0)
		return (0);

	eom = qb->buf + n;
	/*
	 * find first satisfactory answer
	 */
	hp = &qb->hdr;
	ancount = ntohs(hp->ancount);
	qdcount = ntohs(hp->qdcount);
	bp = hostbuf;
	buflen = sizeof(hostbuf);
	cp = qb->buf + sizeof(HEADER);
	if(qdcount) {
		cp += dn_skipname(cp, eom) + QFIXEDSZ;
		while(--qdcount > 0)
			cp += dn_skipname(cp, eom) + QFIXEDSZ;
	}
	while(--ancount >= 0 && cp < eom) {
		if((n = dn_expand((u_char *) qb->buf, (u_char *) eom, (u_char *) cp, (u_char *) bp, buflen)) < 0)
			break;
		cp += n;
		type = _getshort(cp);
		cp += sizeof(u_short);
		class = _getshort(cp);
		cp += sizeof(u_short) + sizeof(u_int32_t);
		n = _getshort(cp);
		cp += sizeof(u_short);
		if(type == T_HINFO) {
			/* Unpack */
			n = *cp++;
			if(n > cpulen - 1)
				return (0);
			BCOPY(cp, cpu, n);
			cp += n;
			cpu[n] = '\0';
			n = *cp++;
			if(n > oslen - 1)
				return (0);
			BCOPY(cp, os, n);
			os[n] = '\0';
			return (1);
		}
		/* Skip unexpected junk */
		cp += n;
	}
#endif
	return (0);
}

/* Return the cannonical name of the host */
char *gethname(u_int32_t a)
{
	int32_t options;
	struct hostent *hp;

	options = _res.options;
	_res.options |= RES_AAONLY;
	_res.options &= ~(RES_DEFNAMES | RES_DNSRCH);
	hp = gethostbyaddr((char *)&a, sizeof(a), AF_INET);
	_res.options = options;
	if(hp == NULL)
		return (intoa(a));
	return (hp->h_name);
}

/* Return the simple name of the host */
char *getsname(u_int32_t a)
{
	char *s, *cp;

	s = gethname(a);
	if(!isdigit((int)*s)) {
		cp = strchr(s, '.');
		if(cp != NULL)
			*cp = '\0';
	}
	return (s);
}
