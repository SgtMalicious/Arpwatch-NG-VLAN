#include <sys/types.h>

#include <netinet/in.h>

#include "gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#include "arpwatch.h"

/*
 * A faster replacement for inet_ntoa().
 */
char *intoa(u_int32_t addr)
{
	char *cp;
	u_int byte;
	int n;
	static char buf[sizeof(".xxx.xxx.xxx.xxx")];

#ifdef NTOHL
	NTOHL(addr);
#else
	addr = ntohl(addr);
#endif
	cp = &buf[sizeof buf];
	*--cp = '\0';

	n = 4;
	do {
		byte = addr & 0xff;
		*--cp = byte % 10 + '0';
		byte /= 10;
		if(byte > 0) {
			*--cp = byte % 10 + '0';
			byte /= 10;
			if(byte > 0)
				*--cp = byte + '0';
		}
		*--cp = '.';
		addr >>= 8;
	} while(--n > 0);

	return cp + 1;
}
