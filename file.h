typedef int (*file_process) (u_int32_t, u_char *, time_t, char *);

int file_loop(FILE *, file_process, const char *);
