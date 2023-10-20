#include <u.h>
#include <libc.h>
#include "service.h"

void
svcfree(Service *s)
{
	Service *sn;
	
	for(; s; s = sn){
		sn = s->next;
		free(s);
	}
}
