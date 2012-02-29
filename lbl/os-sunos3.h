/*
 * Copyright (c) 1990, 1993, 1994, 1995, 1996
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
 *
 * @(#) $Header: os-sunos3.h,v 1.23 96/11/29 15:17:51 leres Exp $ (LBL)
 */

/* Prototypes missing in SunOS 3 */
#ifdef FILE
int	_filbuf(FILE *);
int	_flsbuf(u_char, FILE *);
int	fclose(FILE *);
int	fflush(FILE *);
int	fprintf(FILE *, const char *, ...);
int	fputc(int, FILE *);
int	fputs(const char *, FILE *);
u_int	fread(void *, u_int, u_int, FILE *);
int	fseek(FILE *, long, int);
u_int	fwrite(const void *, u_int, u_int, FILE *);
void	rewind(FILE *);
void	setbuf(FILE *, char *);
int	setlinebuf(FILE *);
u_int	vfprintf(FILE *, const char *, char *);	/* arg 3 is really va_list */
#endif

#if __GNUC__ <= 1
int	read(int, const char *, u_int);
int	write(int, const char *, u_int);
#endif

__dead	void abort(void) __attribute__((volatile));
int	abs(int);
#ifdef	__STDC__
struct	sockaddr;
#endif
int	accept(int, struct sockaddr *, int *);
int	access(const char *, int);
u_int	alarm(u_int);
int	atoi(const char *);
long	atol(const char *);
int	bcmp(const void *, const void *, u_int);
void	bcopy(const void *, void *, u_int);
void	bzero(void *, u_int);
char	*calloc(u_int, u_int);
int	chdir(const char *);
int	chmod(const char *, int);
int	chown(const char *, int, int);
int	close(int);
int	connect(int, struct sockaddr *, int);
char	*crypt(const char *, const char *);
int	daemon(int, int);
void	endgrent(void);
void	endpwent(void);
void	endservent(void);
int	execl(const char *, ...);
int	execlp(const char *, ...);
int	execv(const char *, char * const *);
__dead	void exit(int) __attribute__((volatile));
__dead	void _exit(int) __attribute__((volatile));
int	fchmod(int, int);
int	fchown(int, int, int);
int	fcntl(int, int, int);
int	ffs(int);
int	flock(int, int);
int	fork(void);
void	free(void *);
#ifdef	__STDC__
struct	stat;
#endif
int	fstat(int, struct stat *);
int	ftruncate(int, u_long);
int	getdtablesize(void);
char	*getenv __P((char *));
int	gethostname(char *, int);
int	getopt(int, char * const *, const char *);
int	getpagesize(void);
char	*getlogin __P((void));
char	*getpass(char *);
int	getpeername(int, struct sockaddr *, int *);
int	getpid(void);
int	getppid(void);
int	getpriority(int, int);
int	getsockname(int, struct sockaddr *, int *);
int	getsockopt(int, int, int, char *, int *);
#ifdef	__STDC__
struct	timeval;
struct	timezone;
#endif
int	gettimeofday(struct timeval *, struct timezone *);
int	getuid(void);
char	*getusershell();
int	ioctl(int, int, caddr_t);
int	initgroups(const char *, int);
int	iruserok(u_long, int, char *, char *);
int	isatty(int);
int	kill(int, int);
int	listen(int, int);
#ifdef	__STDC__
struct	utmp;
#endif
void	login(struct utmp *);
int	logout(const char *);
__dead	void longjmp(int *, int) __attribute__((volatile));
off_t	lseek(int, off_t, int);
int	lstat(const char *, struct stat *);
void	openlog(const char *, int, int);
char	*malloc(u_int);
char	*memcpy(char *, const char *, u_int);
int	mkdir(const char *, int);
int	open(char *, int, ...);
int	pause(void);
void	perror(const char *);
int	printf(const char *, ...);
int	puts(const char *);
long	random(void);
int	rcmd(char **, u_short, char *, char *, char *, int *);
char	*realloc(char *, int);
int	recv(int, char *, u_int, int);
int	rresvport(int *);
int	sigblock(int);
int	(*signal (int, int (*) (int))) (int);
int	sigpause(int);
int	sigsetmask(int);
int	select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int	send(int, char *, u_int, int);
int	setenv(const char *, const char *, int);
int	seteuid(int);
int	setgid(int);
int	setjmp(int *);
int	setpriority(int, int, int);
int	setsockopt(int, int, int, char *, int);
int	setuid(int);
int	sleep(u_int);
int	snprintf(char *, size_t, const char *, ...);
int	socket(int, int, int);
int	socketpair(int, int, int, int *);
char	*sprintf(char *, const char *, ...);
void	srandom(int);
int	sscanf(char *, const char *, ...);
#ifdef	__STDC__
struct	stat;
#endif
int	stat(const char *, struct stat *);
int	strcmp(const char *, const char *);
char	*strerror(int);
int	strcasecmp(const char *, const char *);
char	*strcpy(char *, const char *);
char	*strdup(const char *);
int	strncasecmp(const char *, const char *, int);
int	strlen(const char *);
long	strtol(const char *, char **, int);
void	sync(void);
void	syslog(int, const char *, ...);
long	tell(int);
time_t	time(time_t *);
int	truncate(const char *, u_long);
char	*ttyname __P((int));
int	unlink(const char *);
void	unsetenv(const char *);
int	vfork(void);
char	*vsprintf(char *, const char *, ...);
int	shutdown(int, int);
int	umask(int);
int	utimes(const char *, struct timeval *);
#ifdef	__STDC__
union	wait;
struct	rusage;
#endif
int	wait(int *);
int	wait3(int *, int, struct rusage *);

/* Ugly signal hacking */
#ifdef BADSIG
#undef BADSIG
#define BADSIG		(int (*)(int))-1
#undef SIG_DFL
#define SIG_DFL		(int (*)(int))0
#undef SIG_IGN
#define SIG_IGN		(int (*)(int))1

#ifdef KERNEL
#undef SIG_CATCH
#define SIG_CATCH	(int (*)(int))2
#endif
#undef SIG_HOLD
#define SIG_HOLD	(int (*)(int))3
#endif
