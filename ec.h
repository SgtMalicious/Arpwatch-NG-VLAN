typedef int (*ec_process) (u_int32_t, char *);

char *e2str(u_char *);
int ec_add(u_int32_t, char *);
char *ec_find(u_char *);
int ec_loop(FILE *, ec_process, const char *);
int isdecnet(u_char *);
int str2e(char *, u_char *);
