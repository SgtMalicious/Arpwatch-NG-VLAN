typedef void (*ent_process) (u_int32_t, u_int32_t, u_char *, time_t, char *);

void debugdump(void);
int ent_add(u_int32_t, u_int32_t, u_char *, time_t, char *);
int ent_loop(ent_process);
void sorteinfo(void);
