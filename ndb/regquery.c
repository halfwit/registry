#include <u.h>
#include <libc.h>
#include <bio.h>
#include <ctype.h>
#include <ndb.h>
#include "dns.h"
#include "ip.h"

void
usage(void)
{
	fprint(2, "usage: regquery [-s] [-f registry] query\n");
	exits("usage");
}

static void
queryregistry(int fd, char *line, int n)
{
	char buf[8192+1];

	seek(fd, 0, 0);
	write(fd, line, n);

	seek(fd, 0, 0);
	while((n = read(fd, buf, sizeof(buf)-1)) > 0)
		write(1, buf, n);
}

static void
query(int fd, char *q, int pipe2rc)
{
	char arg[260];

	if(strlen(q) > 255)
		sysfatal("query too long");

	sprint(arg, "%s %s", q, (pipe2rc) ? "svc":"scan");
	queryregistry(fd, arg, sizeof(arg));
}

void
main(int argc, char *argv[])
{
	int fd, pipe2rc = 0;
	char *rst  = "/net/registry";

	ARGBEGIN {
	case 's':
		pipe2rc++;
		break;
	case 'f':
		rst = EARGF(usage());
		break;
	default:
		usage();
	} ARGEND;

	if(argc != 1)
		usage();

	fd = open(rst, ORDWR);
	if(fd < 0)
		sysfatal("can't open %s: %r", rst);

	query(fd, argv[0], pipe2rc);
	exits(0);
}
