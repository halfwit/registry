#include <ndb.h>
typedef struct Service Service;

enum {
    NAMELEN = 28,
    NSVCS = 256,
    MAXDESC = 256,
    MAXADDR = 128,
};


struct Service {
    char name[NAMELEN];
    char description[MAXDESC];
    char address[MAXADDR];
    uchar status;
    vlong uptime;
};

int svcdial(char *netroot, char *authdom);
int svcquery(int fd, char *query, Ndbtuple *t);
