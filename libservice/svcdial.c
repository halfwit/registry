#include <u.h>
#include <libc.h>
#include <bio.h>
#include <ndb.h>
#include "../include/service.h"

/* Connect to svcfs */
int
svcdial(char *netroot, char *dom)
{
    Ndbtuple *t, *nt;
	char *p;
	int rv;

	if(dom == nil)
		/* look for one relative to my machine */
		return dial(netmkaddr("$registry", nil, "16675"), nil, nil, nil);

	/* look up an auth server in an authentication domain */
	p = csgetvalue(netroot, "authdom", dom, "registry", &t);

	/* if that didn't work, just try the IP domain */
	if(p == nil)
		p = csgetvalue(netroot, "dom", dom, "registry", &t);

	/*
	 * if that didn't work, try p9registry.$dom.  this is very helpful if
	 * you can't edit /lib/ndb.
	 */
	if(p == nil) {
		p = smprint("p9registry.%s", dom);
		if(p == nil)
			return -1;
		t = ndbnew("registry", p);
	}
	free(p);

	/*
	 * allow multiple registry= attributes for backup auth servers,
	 * try each one in order.
	 */
	rv = -1;
	for(nt = t; nt != nil; nt = nt->entry) {
		if(strcmp(nt->attr, "registry") == 0) {
			rv = dial(netmkaddr(nt->val, nil, "16675"), nil, nil, nil);
			if(rv >= 0)
				break;
		}
	}
	ndbfree(t);

	return rv;
}
