#ifdef USE_8021Q
typedef int (*file_process) (u_int32_t, u_int32_t, u_char *, time_t, char *);
#else
typedef int (*file_process) (u_int32_t, u_char *, time_t, char *);
#endif

int file_loop(FILE *, file_process, const char *);
