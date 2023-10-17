#include <bio.h>
#include <ndb.h>

typedef struct Service Service;

enum {
    NAMELEN = 28,
    NSVCS = 256,
    MAXDESC = 256,
    MAXADDR = 128,
};

enum {
	Sok,
	Sdown,
	Sreg,
	Smax,
};

struct Service {
    char name[NAMELEN];
    char description[MAXDESC];
    char address[MAXADDR];
    uchar status;
    vlong uptime;
};

int svcdial(char *netroot, char *authdom);
Nbdtuple *svcquery(int fd, char *query, char **argv, int argc);
