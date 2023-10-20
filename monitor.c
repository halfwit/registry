#include <u.h>
#include <libc.h>
#include "libservice/service.h"

void monitor(char *,int, int, int);
void publish(Service *, char *);

static void
usage(void)
{
	fprint(2, "usage: %s [-o] [-r timeout] [-a authdom] [-s svcfs]\n", argv0);
	exits("usage");
}

void
main(int argc, char *argv[])
{
	char *svcfs;
	char *authdom;
	int style, fd, pollrate;

	svcfs = nil;
	authdom = nil;
	style = 1;
	pollrate = 30;

	ARGBEGIN{
	case 's':
		svcfs = EARGF(usage());
		break;
	case 'a':
		authdom = EARGF(usage());
		break;
	case 'o':
		style++;
		break;
	case 'r':
		pollrate = atoi(EARGF(usage()));
		break;
	default:
		usage();
	}ARGEND
	argv0 = "monitor";

	if(argc > 0)
		usage();
	if((fd = svcdial(svcfs, authdom)) < 0){
		fprint(2, "Unable to dial svcfs: %r\n");
		exits("error");
	}

	if(authdom != nil){
		monitor(authdom, fd, style, pollrate);
		exits(0);
	}
	monitor("9front", fd, style, pollrate);
	exits(0);

}

char *
clean(char *addr)
{
	char *c;
	if(strncmp(addr, "tcp!", 4) == 0)
		addr += 4;
	c = strchr(addr, '!');
	if(c != nil)
		*c='\0';
	return addr ;
}

void
monitor(char *authdom, int fd, int style, int rate)
{
	Service *svc, *s;
	char srv[MAXADDR];
	int i;

	for(;;){
		for(i=0; i < rate; i++)
			sleep(1000);
		svc = svcquery(fd, ".", nil, 0);
		for(s = svc; s; s = s->next){
			switch(style){
			case 1:
				sprint(srv, "/srv/%s.%s.%s", s->name, clean(s->address), authdom);
				break;
			case 2:
				sprint(srv, "/srv/%s.%s.%s", authdom, clean(s->address), s->name);
				break;
			}
			switch(s->status){
			case Sok:
				publish(s, srv);
				break;
			case Sdown:
				remove(srv);
				break;
			case Sreg:
				// No-op
				break;
			}
		}
		svcfree(svc);
	}
}

void
publish(Service *s, char *srv)
{
	char buf[128];
	int f, fd;
	char *dest;

	/* TODO: stat first and bail before we double dial/create */

	/* Dial */
	dest = netmkaddr(s->address, 0, "9fs");
	fd = dial(dest, 0, 0, 0);
	if(fd < 0)
		return;
	f = create(srv, OWRITE, 0666);
	if(f < 0)
		return;
	/* Publish fd from dial */
	sprint(buf, "%d", fd);
	write(f, buf, strlen(buf));
	close(f);
}
