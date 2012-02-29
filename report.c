/*
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 2000
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
 * report - arpwatch report generating routines
 */

#include <sys/param.h>
#include <sys/types.h>		/* concession to AIX */
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

#if __STDC__
struct mbuf;
struct rtentry;
#endif
#include <net/if.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#include <unistd.h>

#include "gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#include "addresses.h"
#include "arpwatch.h"
#include "dns.h"
#include "ec.h"
#include "report.h"
#include "setsignal.h"
#include "util.h"

#define PLURAL(n) ((n) == 1 || (n) == -1 ? "" : "s")

static void report_orig(int action, u_int32_t v, u_int32_t a, u_char *e1, u_char *e2, time_t *t1p, time_t *t2p);
static void report_stdout(int action, u_int32_t v, u_int32_t a, u_char *e1, u_char *e2, time_t *t1p, time_t *t2p);
static void report_raw(int action, u_int32_t v, u_int32_t a, u_char *e1, u_char *e2, time_t *t1p, time_t *t2p);


/* the reporting function pointer -- initialize with default mode */
void (*report_f)(int , u_int32_t, u_int32_t, u_char *, u_char *, time_t *, time_t *)=report_orig;

/* number of outstanding children */
static int cdepth;
static char *unknown = "<UNKNOWN>";

static char * fmtdate(time_t);
static char * fmtdelta(time_t);
RETSIGTYPE reaper(int);
static int32_t gmt2local(void);


/*
 this table describes each event for
 which there is a enum in report.h
 */
static char *TAB[]={
        "new activity",
        "new station",
        "reused old mac",
        "changed mac",
        "dec flipflop",
        "bogon",
        "ether broadcast",
        "ether mismatch",
        "ether too short",
        "ether bad format",
        "ether wrong type_ip",
        "ether bad length",
        "ether wrong op",
        /* RevARP really is called RARP */
	"ether wrong RARP",
	"ether wrong type",
        0
};


/*
 this table holds all available reporting functions
 enter new reporting functions here
 */
static const struct report_mode report_modes[]={
        /* REPORT_NORMAL */
	{report_orig, "arpwatch daemon, syslog+mail (DEFAULT)", 0},

	/* REPORT_STDOUT */
	{report_stdout, "print reports to stdout, no daemon", 0},

	/* REPORT_RAW */
	{report_raw, "print comma-separated to stdout, no daemon", 0},
};

/* have a macro to return the # of entries in the table above */
#define REPORTMODES_ENTRIES (sizeof(report_modes)/sizeof(*report_modes))


static char * fmtdelta(time_t t)
{
	char *cp;
	int minus;
	static char buf[132];

	minus = 0;
	if(t < 0) {
		t = -t;
		++minus;
	}
	if(t < 60) {
		cp = "second";
	} else if(t < 60 * 60) {
		t /= 60;
		cp = "minute";
	} else if(t < 24 * 60 * 60) {
		t /= (60 * 60);
		cp = "hour";
	} else {
		t /= (24 * 60 * 60);
		cp = "day";
	}
	if(minus)
		t = -t;
	sprintf(buf, "%u %s%s", (u_int32_t) t, cp, PLURAL(t));
	return (buf);
}

static char *dow[7] = {
	"Sunday",
	"Monday",
	"Tuesday",
	"Wednesday",
	"Thursday",
	"Friday",
	"Saturday"
};

static char *moy[12] = {
	"January",
	"February",
	"March",
	"April",
	"May",
	"June",
	"July",
	"August",
	"September",
	"October",
	"November",
	"December"
};

#define DOW(d) ((d) < 0 || (d) >= 7 ? "?" : dow[d])
#define MOY(m) ((m) < 0 || (m) >= 12 ? "?" : moy[(m)])

static char * fmtdate(time_t t)
{
	struct tm *tm;
	int32_t mw;
	char ch;
	static int init = 0;
	static char zone[32], buf[132];

	if(t == 0)
		return ("<no date>");

	if(!init) {
		mw = gmt2local() / 60;
		if(mw < 0) {
			ch = '-';
			mw = -mw;
		} else {
			ch = '+';
		}
		sprintf(zone, "%c%02d%02d", ch, mw / 60, mw % 60);
	}

	tm = localtime(&t);
	sprintf(buf, "%s, %s %d, %d %d:%02d:%02d %s",
		      DOW(tm->tm_wday), MOY(tm->tm_mon), tm->tm_mday, tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec, zone);
	return (buf);
}

/*
 * Returns the difference between gmt and local time in seconds.
 * Use gmtime() and localtime() to keep things simple.
 */
static int32_t gmt2local(void)
{
	int dt, dir;
	struct tm *gmt, *loc;
	time_t t;
	struct tm sgmt;

	t = time(NULL);
	gmt = &sgmt;
	*gmt = *gmtime(&t);
	loc = localtime(&t);
	dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 + (loc->tm_min - gmt->tm_min) * 60;

	/*
	 * If the year or julian day is different, we span 00:00 GMT
	 * and must add or subtract a day. Check the year first to
	 * avoid problems when the julian day wraps.
	 */
	dir = loc->tm_year - gmt->tm_year;
	if(dir == 0)
		dir = loc->tm_yday - gmt->tm_yday;
	dt += dir * 24 * 60 * 60;

	return (dt);
}

RETSIGTYPE reaper(int signo)
{
	pid_t pid;
	DECLWAITSTATUS status;

	for(;;) {
		pid = waitpid((pid_t) 0, &status, WNOHANG);
		if((int)pid < 0) {
			/* ptrace foo */
			if(errno == EINTR)
				continue;
			/* ECHILD means no one left */
			if(errno != ECHILD)
				syslog(LOG_ERR, "reaper: %m");
			break;
		}
		/* Already got everyone who was done */
		if(pid == 0)
			break;
		--cdepth;
		if(WEXITSTATUS(status))
			syslog(LOG_DEBUG, "reaper: pid %d, exit status %d", pid, WEXITSTATUS(status));
	}
	return RETSIGVAL;
}


/* main reporting entry point */
void report(int action, u_int32_t v, u_int32_t a, u_char *e1, u_char *e2, time_t *t1p, time_t *t2p)
{
	/* No report until we're initialized */
	if(initializing) {
		return;
	}

	/* just call the setup'd report function */
	report_f(action, v, a, e1, e2, t1p, t2p);
}


/* the original form of reporting stations */
static void report_orig(int action, u_int32_t v, u_int32_t a, u_char *e1, u_char *e2, time_t *t1p, time_t *t2p)
{
	char *cp, *hn;
	int fd, pid;
	FILE *f;
        char *title;
        char tempfile[64], cpu[64], os[64];
	char *fmt = "%20s: %s\n";
	char buf[132];
	static int init = 0;

        /* lookup string to action */
        title=TAB[action];

	if(debug) {
		if(debug > 1) {
			dosyslog(LOG_NOTICE, title, a, e1, e2);
			return;
		}
		f = stdout;
		putc('\n', f);
	} else {
		/* Setup child reaper if we haven't already */
		if(!init) {
			setsignal(SIGCHLD, reaper);
			++init;
		}
		while(cdepth >= 3) {
			syslog(LOG_ERR, "report: pausing (cdepth %d)", cdepth);
			pause();
		}

		/* Syslog this event too */
		dosyslog(LOG_NOTICE, title, a, e1, e2);

		/* Update child depth */
		++cdepth;

		/* Fork off child to send mail */
		pid = fork();
		if(pid) {
			/* Parent */
			if(pid < 0)
				syslog(LOG_ERR, "report: fork() 1: %m");
			return;
		}

		/* Child */
		closelog();
		strcpy(tempfile, "/tmp/arpwatch.XXXXXX");
		if((fd = mkstemp(tempfile)) < 0) {
			syslog(LOG_ERR, "mkstemp(%s) %m", tempfile);
			exit(1);
		}
		if((f = fdopen(fd, "w+")) == NULL) {
			syslog(LOG_ERR, "child fdopen(%s): %m", tempfile);
			exit(1);
		}
		/* Cheap delete-on-close */
		if(unlink(tempfile) < 0)
			syslog(LOG_ERR, "unlink(%s): %m", tempfile);
	}

	fprintf(f, "From: %s\n", mailfrom);
	fprintf(f, "To: %s\n", mailto);
	hn = gethname(a);
	if(isdigit(*hn)) {
		hn = unknown;
	}
	fprintf(f, "Subject: %s (%s)\n", title, hn);
        putc('\n', f);
	fprintf(f, fmt, "hostname", hn);
	fprintf(f, "%20s: %d\n", "vlan", v);
	fprintf(f, fmt, "ip address", intoa(a));
	fprintf(f, fmt, "ethernet address", e2str(e1));
	if((cp = ec_find(e1)) == NULL)
		cp = unknown;
	fprintf(f, fmt, "ethernet vendor", cp);
	if(hn != unknown && gethinfo(hn, cpu, sizeof(cpu), os, sizeof(os))) {
		sprintf(buf, "%s %s", cpu, os);
		fprintf(f, fmt, "dns cpu & os", buf);
	}
	if(e2) {
		fprintf(f, fmt, "old ethernet address", e2str(e2));
		if((cp = ec_find(e2)) == NULL)
			cp = unknown;
		fprintf(f, fmt, "old ethernet vendor", cp);
	}
	if(t1p)
		fprintf(f, fmt, "timestamp", fmtdate(*t1p));
	if(t2p)
		fprintf(f, fmt, "previous timestamp", fmtdate(*t2p));
	if(t1p && t2p && *t1p && *t2p)
		fprintf(f, fmt, "delta", fmtdelta(*t1p - *t2p));

	if(debug) {
		fflush(f);
		return;
	}

	rewind(f);
	if(dup2(fileno(f), fileno(stdin)) < 0) {
		syslog(LOG_ERR, "dup2: %m");
		exit(1);
	}
	/* XXX Need to freopen()? */
	/* Always Deliver interactively (pause when child depth gets large) */
	//execl(sendmail, "sendmail", "-odi", mailto, NULL);
	//syslog(LOG_ERR, "execl: %s: %m", sendmail);
	exit(1);
}


/* instead of sending mail just use stdout */
static void report_stdout(int action, u_int32_t v, u_int32_t a, u_char *e1, u_char *e2, time_t *t1p, time_t *t2p)
{

	char *cp, *hn;
	char cpu[64], os[64];
	char *fmt = "%20s: %s\n";
	char buf[132];
        FILE *f=stdout;

        char *title=TAB[action];
        
	hn = gethname(a);
	if(isdigit(*hn)) {
		hn = unknown;
	}
        fprintf(f, "%s: %s\n\n", title, hn);
	fprintf(f, fmt, "hostname", hn);
	fprintf(f, "%20s: %d\n", "vlan", v);
	fprintf(f, fmt, "ip address", intoa(a));
	fprintf(f, fmt, "ethernet address", e2str(e1));
	if((cp = ec_find(e1)) == NULL)
		cp = unknown;
	fprintf(f, fmt, "ethernet vendor", cp);
	if(hn != unknown && gethinfo(hn, cpu, sizeof(cpu), os, sizeof(os))) {
		sprintf(buf, "%s %s", cpu, os);
		fprintf(f, fmt, "dns cpu & os", buf);
	}
	if(e2) {
		fprintf(f, fmt, "old ethernet address", e2str(e2));
		if((cp = ec_find(e2)) == NULL)
			cp = unknown;
		fprintf(f, fmt, "old ethernet vendor", cp);
	}
	if(t1p)
		fprintf(f, fmt, "timestamp", fmtdate(*t1p));
	if(t2p)
		fprintf(f, fmt, "previous timestamp", fmtdate(*t2p));
	if(t1p && t2p && *t1p && *t2p)
		fprintf(f, fmt, "delta", fmtdelta(*t1p - *t2p));

	fprintf(f, "\n");
}


/*
 output fields delimited by ','
 */
static void report_raw(int action, u_int32_t v, u_int32_t a, u_char *e1, u_char *e2, time_t *t1p, time_t *t2p)
{
	char *hn, *ip, *mac, *oldmac, *vendor;
	time_t delta;

	static int init=0;
        FILE *f=stdout;

        if(!init) {
                int i=0;
		/* print nice format banner once */
		fprintf(f, "# Format: timestamp,delta,action,hostname,vlan,ip,mac,oldmac,vendor\n");
		fprintf(f, "# actions: ");

		for(;i <= ACTION_MAX; i++) {
			fprintf(f, "%d=%s,", i, TAB[i]);
		}
                fprintf(f, "\n");
		init = 1;
        }

	hn = gethname(a);
	if(isdigit(*hn)) {
		hn = unknown;
	}

        ip=intoa(a);

	if((vendor = ec_find(e1))==NULL) {
		vendor = unknown;
	}

	/*
	 e2str() is not reentrant nor thread safe
	 so strndup() the result before e2str()ing e1
	 */
	if(e2) {
		oldmac=strndup(e2str(e2),32);
	} else {
#ifndef FANCY_MAC
                oldmac="0:0:0:0:0:0";
#else
                oldmac="00:00:00:00:00:00";
#endif
	}

	mac=e2str(e1);

        if(t1p && t2p && *t1p && *t2p) {
		delta = (*t1p - *t2p);
	} else {
                delta=0;
	}

        /* Format: timestamp,delta,action,hostname,ip,mac,oldmac,vendor */
	fprintf(f, "%d,%d,%d,%s,%d,%s,%s,%s,%s\n",
                *t1p,
                delta,
                action,
                hn,
		v,
                ip,
                mac,
                oldmac,
                vendor
               );
        /*
         needed to show the output immediately when it is redirected
         costly call, I know
         */
        fflush(f);

        /* clean up */
	if(e2) {
                free(oldmac);
	}
}


/*
 set function pointer to the reporting function
 use report_modes tab
 */
int setup_reportmode(int mode)
{
	int ret=0;

	/*
	 check if the mode we want is valid in the current data table
	 else: reset to sane default mode just for safety and bail
	 */
	if(mode > (REPORTMODES_ENTRIES - 1)) {
                report_f=report_orig;
		ret=1;
	} else {
                report_f=report_modes[mode].func;
	}

        return ret;
}

/*
 hand out a pointer to the internal report modes description table
 (for enumeration or informational purposes - writing should be prohibited)
 return how many entries the table has
 */
int get_reportmodes(const struct report_mode **out)
{
	int n;

	n=REPORTMODES_ENTRIES;
	*out=report_modes;

	return n;
}
