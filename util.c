/*
 * Copyright (c) 1996, 1997, 1999, 2000, 2004
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
 * util - arpwatch utility routines
 */

#include <sys/types.h>
#include <sys/file.h>

#include <fcntl.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#include "arpwatch.h"
#include "db.h"
#include "ec.h"
#include "file.h"
#include "util.h"
#include "addresses.h"

char *arpdir=ARPDIR;
char *arpfile=ARPFILE;
char *ethercodes=ETHERCODESDIR "/" ETHERCODES;
char *sendmail=PATH_SENDMAIL;
char *mailto=WATCHER;
char *mailfrom=WATCHEE;

/* Broadcast ethernet addresses */
u_char zero[6] = { 0, 0, 0, 0, 0, 0 };
u_char allones[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

int debug = 0;
/* true if initializing */
int initializing = 1;
/* don't activate promisc mode */
int nopromisc = 0;

static FILE *dumpf;


/* syslog() helper routine */
void dosyslog(int p, char *s, u_int32_t a, u_char * ea, u_char * ha)
{
	char xbuf[64];

	/* No report until we're initialized */
	if(initializing)
		return;

	/* Display both ethernet addresses if they don't match */
	strcpy(xbuf, e2str(ea));
	if(ha != NULL && MEMCMP(ea, ha, 6) != 0) {
		strcat(xbuf, " (");
		strcat(xbuf, e2str(ha));
		strcat(xbuf, ")");
	}

	if(debug)
		fprintf(stderr, "%s: %s %s %s\n", prog, s, intoa(a), xbuf);
	else
		syslog(p, "%s %s %s", s, intoa(a), xbuf);
}


void dumpone(u_int32_t a, u_char * e, time_t t, char *h)
{
	fprintf(dumpf, "%s\t%s", e2str(e), intoa(a));
	if(t != 0 || h != NULL)
		fprintf(dumpf, "\t%u", (u_int32_t) t);
	if(h != NULL && *h != '\0')
		fprintf(dumpf, "\t%s", h);
	putc('\n', dumpf);
}

int dump(void)
{
	int fd;
	char oldarpfile[256], newarpfile[256];

	sprintf(oldarpfile, "%s-", arpfile);
	sprintf(newarpfile, "%s.new", arpfile);

	if((fd = creat(newarpfile, 0644)) < 0) {
		syslog(LOG_ERR, "creat(%s): %m", newarpfile);
		return (0);
	}
	if((dumpf = fdopen(fd, "w")) == NULL) {
		syslog(LOG_ERR, "fdopen(%s): %m", newarpfile);
		return (0);
	}

	ent_loop(dumpone);
	if(ferror(dumpf)) {
		syslog(LOG_ERR, "ferror %s: %m", newarpfile);
		return (0);
	}

	fclose(dumpf);
	if(rename(arpfile, oldarpfile) < 0) {
		syslog(LOG_ERR, "rename %s -> %s: %m", arpfile, oldarpfile);
		return (0);
	}
	if(rename(newarpfile, arpfile) < 0) {
		syslog(LOG_ERR, "rename %s -> %s: %m", newarpfile, arpfile);
		return (0);
	}
	return (1);
}


/*
 initialize/read from files the
 -arp.dat database
 -the ethercodes.dat database
 
 return: 0 = OK, 1 = arp.dat failed, 2 = ethercodes.dat failed
 */
int readdata()
{
	FILE *f;

	if((f = fopen(arpfile, "r")) == NULL) {
		return(1);
	}
	if(file_loop(f, ent_add, arpfile) == 0) {
		fclose(f);
		return(1);
	}
	fclose(f);

        /*
         It's not fatal if we can't open the ethercodes file
         Try first official installed, then version in CWD
         Make use of short-circuit in ||
         */
	if( ((f = fopen(ethercodes, "r")) != NULL) || ((f=fopen(ETHERCODES, "r")) != NULL) ) {
		ec_loop(f, ec_add, ethercodes);
		fclose(f);
	} else {
		return(2);
	}

	return(0);
}

