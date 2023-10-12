#include <u.h>
#include <libc.h>
#include <bio.h>
#include <ndb.h>
#include "dns.h"

static Ndb	*db;
static QLock	dblock;

int
openregistry(void)
{
	if(db != nil)
		return 0;

	db = ndbopen(dbfile);
	return db!=nil ? 0: -1;
}

static void
attach(Svc* svc, int persist)
{
	svc->perm = !!persist;

	if(registry != nil){
		svc->next = registry;
	}

	svc->next = registry;
	registry = svc;
}

static char*
detach(char *dial)
{
	Svc *c, *last = 0;
	char buf[Maxdial]; /* trns is capped at 16, port 8 */

	for(c = registry; c; c = c->next){
		snprint(buf, Maxdial, "%s!%s!%s", c->trns, c->host, c->port);
		if(strcmp(buf, dial)==0){
			if(last == 0)
				registry = c->next;
			else
				last->next = c->next;
			free(c);
			return 0;
		}
		last = c;
	}

	return "found no matching service";
}

static void
host2svc(Svc *svc, char *dial)
{
	int n;

	/* 
	 * entry host=tcp!mything!9fs
	 * for now, tokenize but we should allow short strings
     */
	n = strcspn(dial, "!");
	if(n < 1)
		strcpy(svc->trns, "tcp");
	else
		strecpy(svc->trns, svc->trns+n+1, dial);
	dial = dial + n + 1;

	n = strcspn(dial, "!");
	strecpy(svc->host, svc->host+n+1, dial);

	dial = dial + n + 1;
	if(sizeof(dial) < 1)
		strcpy(svc->port, "9fs");
	else if(sizeof(dial) > 8)
		/* If this starts happening, we should bump the number */
		strecpy(svc->port, svc->port + 8, dial);
	else
		strcpy(svc->port, dial);
}

static void
dbtuple2cache(Ndbtuple *t, int persist)
{
	Ndbtuple *et, *nt;
	Svc *svc;


	for(et = t; et; et = et->entry)
		if(strncmp(et->attr, "serv", 4)==0){
			svc = emalloc(sizeof(*svc));
			host2svc(svc, et->val);
			for(nt = et->entry; nt; nt = nt->entry)
				if(strcmp(nt->attr, "label")==0)
					strecpy(svc->labl, svc->labl+Maxmdns, nt->val);
				else if(strcmp(nt->attr, "auth")==0)
					strecpy(svc->auth, svc->auth+Maxauth, nt->val);
				else if(strcmp(nt->attr, "mtpt")==0)
					strecpy(svc->mtpt, svc->mtpt+Maxpath, nt->val);
			attach(svc, persist);
		};
}

static void
dbfile2cache(Ndb *db)
{
	Ndbtuple *t;

	if(debug)
		reglog("reading %s", db->file);
	Bseek(&db->b, 0, 0);
	while(t = ndbparse(db)){
		dbtuple2cache(t, 1);
		ndbfree(t);
	}


}

Svc*
rstr2svc(char *entry)
{
	Svc *svc;
	char *args[7];
	
	int i, n;

	n = tokenize(entry, args, 7);

	svc = emalloc(sizeof(*svc));
	host2svc(svc, estrdup(args[0]));

	for(i = 1; i < n - 1; i++)
		if(strcmp(args[i], "label")==0)	
			strecpy(svc->labl, svc->labl+Maxmdns, args[++i]);
		else if(strcmp(args[i], "auth")==0)
			strecpy(svc->auth, svc->auth+Maxauth, args[++i]);
		else if(strcmp(args[i], "mtpt")==0)
			strecpy(svc->mtpt, svc->mtpt+Maxpath, args[++i]);

	return svc;
}

char*
rstr2cache(char *entry, int persist)
{
	Svc *svc;

	svc = rstr2svc(entry);
	attach(svc, persist);
	return 0;
}

char*
rstrdtch(char *svc)
{
	return detach(svc);
}

/* e.g. update tcp!foo!9fs label newlabel */
char*
rstrupdt(char *entry)
{
	Svc *c, *svc = 0;
	char *args[7], buf[Maxdial];
	int i, n;

	n = tokenize(entry, args, 7);

	/* Find our service */
	for(c = registry; c; c = c->next){
		snprint(buf, Maxdial, "%s!%s!%s", c->trns, c->host, c->port);
		if(strcmp(buf, args[0])==0){
			svc = c;
			break;
		}
	}
	
	if(svc == 0)
		return "found no matching service";

	for(i = 1; i < n - 1; i++)
		if(strcmp(args[i], "label")==0)
			strecpy(svc->labl, svc->labl+Maxmdns, args[++i]);
		else if(strcmp(args[i], "auth")==0)
			strecpy(svc->auth, svc->auth+Maxauth, args[++i]);
		else if(strcmp(args[i], "mtpt")==0)
			strecpy(svc->mtpt, svc->mtpt+Maxpath, args[++i]);

	return 0;
}

void
reg2cache(void)
{
	Ndb *ndb;
	
	qlock(&dblock);
	if(openregistry() < 0){
		qunlock(&dblock);
		return;
	}
	
	if(debug)
		syslog(0, logfile, "building cache from db");
			
	for(ndb = db; ndb; ndb = ndb->next)
		dbfile2cache(ndb);

	qunlock(&dblock);
}
