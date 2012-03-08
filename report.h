#ifndef REPORT_H
#define REPORT_H

enum {
	REPORT_NORMAL=0,
	REPORT_STDOUT,
	REPORT_RAW,
};

enum {
        ACTION_ACTIVITY=0,
        ACTION_NEW,
        ACTION_REUSED,
        ACTION_CHANGED,
        ACTION_FLIPFLOP,
        ACTION_BOGON,
        ACTION_ETHER_BROADCAST,
        ACTION_ETHER_MISMATCH,
        ACTION_ETHER_TOOSHORT,
        ACTION_ETHER_BADFORMAT,
        ACTION_ETHER_WRONGTYPE_IP,
        ACTION_ETHER_BADLENGTH,
        ACTION_ETHER_WRONGOP,
	ACTION_ETHER_WRONGRARP,
	ACTION_ETHER_WRONGTYPE,
};


/* struct describing a report function */
struct report_mode {
#ifdef USE_8021Q
	void (*func)(int , u_int32_t, u_int32_t, u_char *, u_char *, time_t *, time_t *);
#else
	void (*func)(int , u_int32_t, u_char *, u_char *, time_t *, time_t *);
#endif
	const char *name;
        unsigned int flags;
};


#define ACTION_MAX ACTION_ETHER_WRONGTYPE

#ifdef USE_8021Q
void report(int, u_int32_t, u_int32_t, u_char *, u_char *, time_t *, time_t *);
#else
void report(int, u_int32_t, u_char *, u_char *, time_t *, time_t *);
#endif
int setup_reportmode(int mode);
int get_reportmodes(const struct report_mode **out);

#endif
