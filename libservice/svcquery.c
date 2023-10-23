#include <u.h>
#include <libc.h>
#include "service.h"

char *
readFile(char *dir, char *name, int len)
{
	int fd, n;
	char buf[MAXDESC+1], path[NAMELEN+25];

	sprint(path, "/mnt/services/%s/%s", dir, name);
	if((fd = open(path, OREAD)) < 0)
		return nil;
	n = readn(fd, buf, len);
	if(buf[n-1] == '\n' || buf[n-1] == RS)
		buf[n-1] = '\0';
	buf[n] = '\0';
	close(fd);
	return buf;
}

Service *
addService(Dir d)
{
	Service *svc;
	char *desc, *addr, *auth, *stat, *up;

	svc = malloc(sizeof *svc);
	memmove(svc->name, d.name, NAMELEN);
	svc->name[strlen(d.name)] = '\0';
	desc = readFile(d.name, "description", MAXDESC);
	memmove(svc->description, desc, strlen(desc));
	auth = readFile(d.name, "authdom", MAXAUTH);
	memmove(svc->authdom, auth, strlen(auth));
	addr = readFile(d.name, "address", MAXADDR);
	memmove(svc->address, addr, strlen(addr));
	svc->status = Sreg;
	stat = readFile(d.name, "status", 12);
	if(strncmp(stat, "ok", 2) == 0)
		svc->status = Sok;
	if(strncmp(stat, "down", 4) == 0)
		svc->status = Sdown;
	up = readFile(d.name, "uptime", 64); /* Way huge */
	svc->uptime = strtoll(up, nil, 10);

	return svc;
}

int
filter(Dir d, char *attr, char *value)
{
	char path[NAMELEN+25], buf[MAXDESC];
	int fd, length;

	length = strlen(value);
	sprint(path, "/mnt/services/%s/%s", d.name, attr);
	if((fd = open(path, OREAD)) < 0)
		return -1;
	if(readn(fd, buf, length) != length){
		close(fd);
		return -1;
	}
	if(strncmp(value, buf, length) != 0){
		close(fd);
		return -1;
	}
	return 0;
}

Service *
svcquery(int fd, char *query, char **argv, int argc)
{
	Service *svc, *bsvc;
	Dir *d;
	int dfd, i, n;

	bsvc = nil;

	/* Build out a tuple based on our search values */
	if(strlen(query) == 0)
		return nil;
	if(mount(fd, -1, "/mnt/services", MREPL, "") < 0)
		return nil;
	dfd = open("/mnt/services", OREAD);
	while((n = dirread(dfd, &d)) > 0){
		for(i=0; i < n; i++){
			if(argc == 2 && filter(d[i], argv[0], argv[1]) < 0)
				continue;
			if(strncmp(query, d[i].name, strlen(query)) == 0 || strcmp(query, ".") == 0){
				svc = addService(d[i]);
				svc->next = bsvc;
				bsvc = svc;
			}
		}
		free(d);	
	}
	unmount(0, "/mnt/services");
	return bsvc;
}
