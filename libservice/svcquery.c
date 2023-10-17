#include <u.h>
#include <libc.h>
#include "../include/service.h"

Ndbtuple *
svcquery(int fd, char *query, char **argv, int argc)
{
	/* Build out a tuple based on our search values */
	USED(fd); USED(query); USED(argv); USED(argc);	
	return nil;
}
