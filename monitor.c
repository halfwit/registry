#include <u.h>
#include <libc.h>
#include "service.h"

void monitor(char*, char*, int, int);
void publish(Service *, char *);
void check(int, int);

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
	int style, pollrate;

	svcfs = nil;
	style = 1;
	authdom = "9front";
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

	monitor(svcfs, authdom, style, pollrate);
	exits(0);

}

char *
addr2hostname(char *addr)
{
	if(strncmp(addr, "tcp!", 4) == 0)
		return addr+4;
	return addr;
}

void
check(int fd, int style)
{
	char srv[MAXADDR];
	char *host;
	Service *svc, *s;
	print("Checking for /srv updates\n");
	svc = svcquery(fd, ".", nil, 0);
	if(svc == nil){
		fprint(2, "Error parsing service entries\n");
		return;
	}

	for(s = svc; s; s = s->next){
		host = addr2hostname(s->address);
		switch(style){
		case 1:
			sprint(srv, "/srv/%s.%s.%s", s->name, host, s->authdom);
			break;
		case 2:
			sprint(srv, "/srv/%s.%s.%s", s->authdom, host, s->name);
			break;
		}
		switch(s->status){
		case Sok:
			publish(s, srv);
			break;
		case Sdown:
			remove(srv);
			break;
		case Spersist:
		case Sreg:
		default:
			//
			break;
		}
	}
	svcfree(svc);
}

void
monitor(char *svcfs, char *authdom, int style, int rate)
{
	int i, fd;

	for(;;){
		if((fd = svcdial(svcfs, authdom)) < 0){
			fprint(2, "Unable to dial svcfs: %r\n");
			exits("error");
		}
		for(i=0; i < rate; i++)
			sleep(1000);
		check(fd, style);
		close(fd);
	}
}

void
publish(Service *s, char *srv)
{
	char buf[128];
	int f, fd;

	/* stat first and bail before we double dial/create */
	if((f = open(srv, OREAD)) > 0){
		close(f);
		return;
	}
	/* Dial */
	fd = dial(s->address, 0, 0, 0);
	if(fd < 0)
		goto Error;
	f = create(srv, OWRITE, 0666);
	if(f < 0)
		goto Error;
	/* Publish fd from dial */
	sprint(buf, "%d", fd);
	write(f, buf, strlen(buf));
	print("publish %s\n", srv);
	close(f);
	return;
Error:
	close(f);
	if(fd >= 0)
		close(fd);
	fprint(2, "Unable to publish service: %r\n");
	
}
