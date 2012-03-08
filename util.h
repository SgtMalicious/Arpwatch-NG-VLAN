void dosyslog(int, char *, u_int32_t, u_char *, u_char *);
int dump(void);
#ifdef USE_8021Q
void dumpone(u_int32_t, u_int32_t, u_char *, time_t, char *);
#else
void dumpone(u_int32_t, u_char *, time_t, char *);
#endif
int readdata(void);
char *savestr(const char *);
#ifndef HAVE_STRNDUP
char *strndup(const char *s, size_t n);
#endif

extern char *arpdir;
extern char *newarpfile;
extern char *arpfile;
extern char *oldarpfile;
extern char *ethercodes;
extern char *sendmail;
extern char *mailto;
extern char *mailfrom;

extern u_char zero[6];
extern u_char allones[6];

extern int debug;
extern int initializing;
extern int nopromisc;
