#include <bio.h>
#include <ndb.h>

typedef struct Service Service;

enum {
    NAMELEN = 28,
    NSVCS = 256,
    MAXDESC = 256,
    MAXADDR = 128,
	RS = 0x1e,
};

enum {
	Sok = 1,
	Sdown = 2,
	Sreg =3 ,
	Smax =4,
};

struct Service {
	char name[NAMELEN];
	char description[MAXDESC];
	char address[MAXADDR];
	uchar status;
	vlong uptime;
	Service *next; /* Used for queries */
};

int svctimefmt(Fmt *f);
int svcdial(char *netroot, char *authdom);
Service* svcquery(int fd, char *query, char **argv, int argc);
void svcfree(Service *);
