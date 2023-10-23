#include <u.h>
#include <libc.h>
#include "service.h"

int
readFile(char *dir, char *name, char *buf, int len)
{
	int fd, n;
	char path[NAMELEN+25];

	sprint(path, "/mnt/services/%s/%s", dir, name);
	if((fd = open(path, OREAD)) < 0)
		return -1;
	n = readn(fd, buf, len);
	if(buf[n-1] == '\n' || buf[n-1] == RS)
		n--;
	buf[n] = '\0';
	close(fd);
	return n;
}

Service *
addService(Dir d)
{
	Service *svc;
	char data[MAXDESC]; 
	int n;

	svc = malloc(sizeof *svc);
	memset(svc, '\0', sizeof(svc));
	memmove(svc->name, d.name, NAMELEN);
	memset(data, '\0', MAXDESC);
	n = readFile(d.name, "description", data, MAXDESC);
	memmove(svc->description, data, n);
	n = readFile(d.name, "authdom", data, MAXAUTH);
	memmove(svc->authdom, data, n);
	n = readFile(d.name, "address", data, MAXADDR);
	memmove(svc->address, data, n);
	svc->status = Sreg;
	readFile(d.name, "status", data, 12);
	if(strncmp(data, "ok", 2) == 0)
		svc->status = Sok;
	if(strncmp(data, "down", 4) == 0)
		svc->status = Sdown;
	readFile(d.name, "uptime", data, 64); /* Way huge */
	svc->uptime = strtoll(data, nil, 10);
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
	d = nil;
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
	close(dfd);
	unmount(0, "/mnt/services");
	return bsvc;
}
