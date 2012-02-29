#include <sys/types.h>
#include <stdio.h>

/* strndup() may be useful, but is a GNU extension */
#ifndef HAVE_STRNDUP
char * strndup(const char *s, size_t n)
{
	size_t nAvail;
	char *p;

	if(!s) {
		goto out;
	}

	//  nAvail = min( strlen(s)+1, n+1 );
	nAvail=((strlen(s)+1) > (n+1)) ? n+1 : strlen(s)+1;
	if(!(p=malloc(nAvail))) {
		goto out;
	}
	memcpy(p, s, nAvail);
	p[nAvail - 1]=NULL;
	return p;

out:
        return NULL;
}
#endif

