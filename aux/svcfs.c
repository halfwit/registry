#include <u.h>
#include <libc.h>
#include <ctype.h>
#include <fcall.h>
#include "service.h"

typedef struct Fid Fid;
typedef struct Entry Entry;

enum {
	Qroot,
	Qsvc,
	Qaddr,
	Qstatus,
	Quptime,
	Qdesc,
	Qauth,
	Qpersist,
	Qmax,
};

struct Fid {
	int	fid;
	ulong	qtype;
	Entry *svc;
	int	busy;
	Fid	*next;
};

struct Entry {
	Service *svc;
	char	removed;
	int	ref;
	vlong	uptime;
	ulong	uniq;
	Entry *link;
};

char *qinfo[Qmax] = {
	[Qroot]		"services",
	[Qsvc]		".",
	[Qaddr]		"address",
	[Qstatus]	"status",
	[Quptime]	"uptime",
	[Qauth]		"authdom",
	[Qpersist]	"persist",
	[Qdesc]		"description",
};

char *status[Smax] = {
	[Sok] 	= "ok",
	[Sdown]	= "down",
	[Spersist] = "persist",
	[Sreg] = "registered",
};

Fid *fids;
Entry *services[NSVCS];
char	*svcfile;
int	readonly;
ulong	uniq;
Fcall   rhdr, thdr;
uchar	mdata[8192 + IOHDRSZ];
int	messagesize = sizeof mdata;

Entry	*findsvc(char*);
Entry	*installsvc(char*);
void	insertsvc(Entry*);
int	removesvc(Entry*);
int	readservices(void);
void	writeservices(void);
void	error(char*);
int	dostat(Entry*, ulong, void*, int);
void	watch(void);
void	io(int, int);
Qid	mkqid(Entry*, ulong);
ulong	hash(char*);
Fid	*findfid(int);
void	*emalloc(ulong);
char	*estrdup(char*);

char	*Auth(Fid*), *Attach(Fid*), *Version(Fid*),
	*Flush(Fid*), *Walk(Fid*), *Open(Fid*),
	*Create(Fid*), *Read(Fid*), *Write(Fid*),
	*Clunk(Fid*), *Remove(Fid*), *Stat(Fid*),
	*Wstat(Fid*);

char *(*fcalls[])(Fid*) = {
	[Tattach]	Attach,
	[Tauth]		Auth,
	[Tclunk]	Clunk,
	[Tcreate]	Create,
	[Tflush]	Flush,
	[Topen]		Open,
	[Tread]		Read,
	[Tremove]	Remove,
	[Tstat]		Stat,
	[Tversion]	Version,
	[Twalk]		Walk,
	[Twrite]	Write,
	[Twstat]	Wstat,
};

static void
usage(void)
{
	fprint(2, "usage: %s [-r] [-m mtpt] [svcfile]\n", argv0);
	exits("usage");
}

void
main(int argc, char *argv[])
{
	char *mntpt;
	int p[2], pid;

	mntpt = "/mnt/services";
	ARGBEGIN{
	case 'm':
		mntpt = EARGF(usage());
		break;
	case 'r':
		readonly = 1;
		break;
	default:
		usage();
		break;
	}ARGEND
	argv0 = "svcfs";

	svcfile = "/adm/services";
	if(argc > 1)
		usage();
	if(argc == 1)
		svcfile = argv[0];

	if(pipe(p) < 0)
		error("Can't make pipe: %r");

	readservices();
	if((pid = rfork(RFPROC|RFNOTEG|RFMEM)) == 0) {
		watch();
		exits(0);
	}

	switch(rfork(RFPROC|RFNAMEG|RFNOTEG|RFNOWAIT|RFENVG|RFFDG|RFMEM)){
	case 0:
		close(p[0]);
		io(p[1], p[1]);
		postnote(PNPROC, 1, "shutdown");
		postnote(PNPROC, pid, "shutdown");
		exits(0);
	case -1:
		error("fork");
	default:
		close(p[1]);
		if(mount(p[0], -1, mntpt, MREPL|MCREATE, "") == -1)
			error("can't mount: %r");
		exits(0);
	}
}

char *
Flush(Fid *f)
{
	USED(f);
	return 0;
}

char *
Auth(Fid *f)
{
	USED(f);
	return "svcfs: authentication not required";
}

char *
Attach(Fid *f)
{
	if(f->busy)
		Clunk(f);
	f->svc = nil;
	f->qtype = Qroot;
	f->busy = 1;
	thdr.qid = mkqid(f->svc, f->qtype);
	return 0;
}

char *
Version(Fid*)
{
	Fid *f;

	for(f = fids; f; f = f->next)
		if(f->busy)
			Clunk(f);
	if(rhdr.msize < 256)
		return "message size too small";
	if(rhdr.msize > sizeof mdata)
		thdr.msize = sizeof mdata;
	else
		thdr.msize = rhdr.msize;
	messagesize = thdr.msize;
	thdr.version = "9P2000";
	if(strncmp(rhdr.version, "9P", 2) != 0)
		thdr.version = "unknown";
	return 0;
}

char *
Walk(Fid *f)
{
	char *name, *err;
	int i, j, max;
	Fid *nf;
	ulong qtype;
	Entry *e;

	if(!f->busy)
		return "walk of unused fid";
	nf = nil;
	qtype = f->qtype;
	e = f->svc;
	if(rhdr.fid != rhdr.newfid){
		nf = findfid(rhdr.newfid);
		if(nf->busy)
			return "fid in use";
		f = nf;
	}
	err = nil;
	i = 0;
	if(rhdr.nwname > 0){
		for(; i<rhdr.nwname; i++){
			if(i >= MAXWELEM){
				err = "too many elements in path";
				break;
			}
			name = rhdr.wname[i];
			switch(qtype){
			case Qroot:
				if(strcmp(name, "..") == 0)
					goto Accept;
				e = findsvc(name);
				if(e == nil)
					goto Out;
				qtype = Qsvc;
			Accept:
				thdr.wqid[i] = mkqid(e, qtype);
				break;
			case Qsvc:
				if(strcmp(name, "..") == 0) {
					qtype = Qroot;
					e = nil;
					goto Accept;
				}
				max = Qmax;
				for(j = Qsvc + 1; j < Qmax; j++)
					if(strcmp(name, qinfo[j]) == 0){
						qtype = j;
						break;
					}	
				if(j < max)
					goto Accept;
				goto Out;
			default:
				err = "file is not a directory";
				goto Out;
			}
		}
		Out:
		if(i < rhdr.nwname && err == nil)
			err = "file not found";

	}
	if(err != nil)
		return err;
	if(rhdr.fid != rhdr.newfid && i == rhdr.nwname){
		nf->busy = 1;
		nf->qtype = qtype;
		nf->svc = e;
		if(e != nil)
			e->ref++;
	} else if(nf == nil && rhdr.nwname > 0){
		Clunk(f);
		f->busy = 1;
		f->qtype = qtype;
		f->svc = e;
		if(e != nil)
			e->ref++;
	}
	thdr.nwqid = i;
	return 0;		
}

char *
Clunk(Fid *f)
{
	f->busy = 0;
	if(f->svc != nil && --f->svc->ref == 0 && f->svc->removed) {
		free(f->svc);
	}
	f->svc = nil;
	return nil;
}

char *
Open(Fid *f)
{
	int mode;

	if(!f->busy)
		return "open of unused fid";
	mode = rhdr.mode;
	if(f->qtype == Qsvc && (mode & (OWRITE|OTRUNC)))
		return "Service already exists";
	thdr.qid = mkqid(f->svc, f->qtype);
	thdr.iounit = messagesize - IOHDRSZ;
	return 0;
}

char *
Create(Fid *f)
{
	char *name;
	long perm;

	if(!f->busy)
		return "create of unused fid";
	if(readonly)
		return "mounted readonly";
	name = rhdr.name;
	perm = rhdr.perm;
	if(f->svc != nil)
		return "permission denied";
	/* Allow creation of persist file */
	if(strcmp(name, "persist") == 0){
		f->svc->svc->status = Spersist;
		f->qtype = Qpersist;
		thdr.qid = mkqid(f->svc, f->qtype);
		thdr.iounit = messagesize - IOHDRSZ;
		writeservices();
		return 0;
	}
	if(!(perm & DMDIR))
		return "permission denied";
	if(strcmp(name, "") == 0)
		return "empty file name";
	if(strlen(name) >= NAMELEN)
		return "file name too long";
	if(findsvc(name) != nil)
		return "Service already exists";
	f->svc = installsvc(name);
	f->svc->ref++;
	f->qtype = Qsvc;

	thdr.qid = mkqid(f->svc, f->qtype);
	thdr.iounit = messagesize - IOHDRSZ;
	writeservices();
	return 0;
}

char *
Read(Fid *f)
{
	Entry *e;
	char *data;
	ulong off, n, m;
	int i, j, max;

	if(!f->busy)
		return "read of unused fid";
	n = rhdr.count;
	off = rhdr.offset;
	thdr.count = 0;
	data = thdr.data;
	switch(f->qtype){
	case Qroot:
		j = 0;
		for(i = 0; i < NSVCS; i++)
			for(e = services[i]; e != nil; j += m, e = e->link){
				m = dostat(e, Qsvc, data, n);
				if(m <= BIT16SZ)
					break;
				if(j < off)
					continue;
				data += m;
				n -= m;	
			}
		thdr.count = data - thdr.data;
		return 0;
	case Qsvc:
		max = Qmax;
		max -= Qsvc + 1;
		j = 0;
		for(i = 0; i < max; j += m, i++){
			if(i + Qsvc + 1 == Qpersist)
				continue;
			m = dostat(f->svc, i + Qsvc + 1, data, n);
			if( m <= BIT16SZ)
				break;
			if(j < off)
				continue;
			data += m;
			n -= m;
		}
		thdr.count = data - thdr.data;
		return 0;

	case Qstatus:
		sprint(data, "%s\n", status[f->svc->svc->status]);
	Readstr:
		m = strlen(data);
		if(off >= m)
			n = 0;
		else {
			data += off;
			m -= off;
			if(n > m)
				n = m;
		}
		if(data != thdr.data)
			memmove(thdr.data, data, n);
		thdr.count = n;
		return 0;
	case Qaddr:
		sprint(data, "%s\n", f->svc->svc->address);
		goto Readstr;
	case Qauth:
		sprint(data, "%s\n", f->svc->svc->authdom);
		goto Readstr;
	case Quptime:
		sprint(data, "%lld\n", f->svc->svc->uptime);
		goto Readstr;
	case Qdesc:
		sprint(data, "%s\n", f->svc->svc->description);
		goto Readstr;
	default:
		return "permission denied";
	}	
}

char *
Write(Fid *f)
{
	char *data;
	int n;

	if(!f->busy)
		return "write on unused fid";
	if(readonly)
		return "mounted readonly";
	n = rhdr.count;
	data = rhdr.data;
	switch(f->qtype) {
	case Qaddr:
		if(n > MAXADDR)
			return "address too big!";
		if(data[n-1] == '\n')
			n--;
		memmove(f->svc->svc->address, data, n);
		f->svc->svc->address[n] = '\0';
		thdr.count = n;
		break;
	case Qauth:
		if(n > MAXAUTH)
			return "address too big!";
		if(data[n-1] == '\n')
			n--;
		memmove(f->svc->svc->authdom, data, n);
		f->svc->svc->authdom[n] = '\0';
		thdr.count = n;
		break;
	case Qdesc:
		if(n > MAXDESC)
			return "description too long";
		if(data[n-1] == '\n')
			n--;
		memmove(f->svc->svc->description, data, n);
		f->svc->svc->description[n] = '\0';
		thdr.count = n;
		break;
	case Qroot:
	case Qsvc:
	case Quptime:
	case Qstatus:
	case Qpersist:
	default:
		return "permission denied";
	}
	writeservices();
	return 0;
}

char *
Remove(Fid *f)
{
	if(!f->busy)
		return "remove on unused fd";
	if(readonly){
		Clunk(f);
		return "mounted readonly";
	}
	if(f->qtype == Qsvc)
		removesvc(f->svc);
	else {
		Clunk(f);
		return "permission denied";
	}
	Clunk(f);
	writeservices();
	return 0;
}

char *
Stat(Fid *f)
{
	static uchar statbuf[1024];
	
	if(!f->busy)
		return "stat on unused fd";
	thdr.nstat = dostat(f->svc, f->qtype, statbuf, sizeof statbuf);
	if(thdr.nstat <= BIT16SZ)
		return "stat buffer too small";
	thdr.stat = statbuf;
	return 0;
}

char *
Wstat(Fid *f)
{
	Dir d;
	int n;
	char buf[1024];

	if(!f->busy || f->qtype != Qsvc || f->qtype != Qpersist)
		return "permission denied";
	if(readonly)
		return "mounted read-only";
	if(rhdr.nstat > sizeof buf)
		return "wstat buffer too big";
	if(convM2D(rhdr.stat, rhdr.nstat, &d, buf) == 0)
		return "bad stat buffer";
	n = strlen(d.name);
	if(n == 0 || n > NAMELEN)
		return "bad service name";
	if(findsvc(d.name))
		return "Service already exists";
	if(!removesvc(f->svc))
		return "service already removed";
	free(f->svc->svc->name);
	memmove(f->svc->svc->name, d.name, NAMELEN);
	insertsvc(f->svc);
	writeservices();
	return 0;
}

Qid
mkqid(Entry *e, ulong qtype)
{
	Qid q;

	q.vers = 0;
	q.path = qtype;
	if(e)
		q.path |= e->uniq * 0x100;
	if(qtype == Qsvc || qtype == Qroot)
		q.type = QTDIR;
	else
		q.type = QTFILE;
	return q;
}

int
dostat(Entry *e, ulong qtype, void *p, int n)
{
	Dir d;

	if(qtype == Qsvc)
		d.name = e->svc->name;
	else
		d.name = qinfo[qtype];
	d.uid = d.gid = d.muid = "none";
	d.qid = mkqid(e, qtype);
	if(d.qid.type & QTDIR)
		d.mode = 0777|DMDIR;
	else
		d.mode = 0666;
	d.atime = d.mtime = time(0);
	d.length = 0;
	return convD2M(&d, p, n);	
}

void
writeservices(void)
{
	int entrylen;
	int fd, ns, i;
	Entry *e;
	uchar *p, *buf;
	ns = 0;

	if(readonly){
		fprint(2, "attempted to write services to disk in a readonly system\n");
		return;
	}

	entrylen = NAMELEN + MAXADDR + MAXAUTH + MAXDESC;
	/* Count our services */
	for(i = 0; i < NSVCS; i++)
		for(e = services[i]; e != nil; e = e->link)
			ns++;

	/* Make a buffer large enough to hold each line */
	buf = emalloc(ns * entrylen);
	memset(buf, RS, entrylen);
	p = buf;
	for(i = 0; i < NSVCS; i++)
		for(e = services[i]; e !=nil; e = e->link){
			strncpy((char *)p, e->svc->name, NAMELEN);
			p += NAMELEN;
			strncpy((char *)p, e->svc->address, MAXADDR);
			p += MAXADDR;
			strncpy((char *)p, e->svc->authdom, MAXAUTH);
			p += MAXAUTH;
			strncpy((char *)p, e->svc->description, MAXDESC);
			p += MAXDESC;
		}
	fd = create(svcfile, OWRITE, 0660);
	if(fd < 0){
		fprint(2, "svcfs: can't write %s: %r\n", svcfile);
		free(buf);
		return;
	}
	if(write(fd, buf, p - buf) != (p - buf))
		fprint(2, "svcfs: can't write %s: %r\n", svcfile);
	close(fd);
	free(buf);
}

int
svcok(char *svc, int nu)
{
	int i, n, rv;
	Rune r;
	char buf[NAMELEN+1];

	memset(buf, 0, sizeof buf);
	memmove(buf, svc, NAMELEN);

	if(buf[NAMELEN-1] != 0){
		fprint(2, "svcfs: %d: no termination\n", nu);
		return -1;
	}

	rv = 0;
	for(i = 0; buf[i]; i += n){
		n = chartorune(&r, buf+i);
		if(r == Runeerror){
			rv = -1;
		} else if(r == RS) { /* Scrub our spacer out */
			buf[i] = 0;
		} else if(isascii(r) && iscntrl(r) || r == ' ' || r == '/')
			rv = -1;
	}

	if(i == 0){
		fprint(2, "svcfs: %d: nil name\n", nu);
		return -1;
	}
	if(rv == -1)
		fprint(2, "svcfs: %d: bad syntax\n", nu);
	return rv;
}

char *
scrub(uchar *ep, int len)
{
	int i, n;
	Rune r;
	char *buf;

	buf = emalloc(len);
	memset(buf, 0, sizeof buf);
	memmove(buf, ep, len);

	for(i = 0; buf[i]; i += n){
		n = chartorune(&r, buf+i);
		if(r == Runeerror)
			return "error";
		if(r == RS)
			buf[i] = 0;
	}
	if(i == 0){
		return "empty";
	}
	return buf;
}

int
readservices(void)
{
	int fd, i, n, ns, entrylen;
	uchar *buf, *ep;
	Entry *svc;
	Dir *d;

	/* Read our file into buf */
	fd = open(svcfile, OREAD);
	if(fd < 0){
		fprint(2, "svcfs: can't read %s: %r\n", svcfile);
		return 0;
	}
	d = dirfstat(fd);
	if(d == nil){
		close(fd);
		return 0;
	}
	buf = emalloc(d->length);
	n = readn(fd, buf, d->length);
	close(fd);
	free(d);
	if(n != d->length){
		free(buf);
		return 0;
	}
	ep = buf;
	entrylen = NAMELEN + MAXDESC + MAXADDR + MAXAUTH;
	n = n / entrylen;
	ns = 0;
	for(i = 0; i < n; ep += entrylen, i++){
		svc = findsvc((char *)ep);
		if(svc == nil)
			svc = installsvc((char *)ep);
		memmove(svc->svc->address, scrub(ep+NAMELEN, MAXADDR), MAXADDR);
		memmove(svc->svc->authdom, scrub(ep+NAMELEN+MAXADDR, MAXAUTH), MAXAUTH);
		memmove(svc->svc->description, scrub(ep+NAMELEN+MAXADDR+MAXAUTH, MAXDESC), MAXDESC);
		ns++;
	}
	free(buf);

	print("%d services read in\n", ns);
	return 1;
}

Entry *
installsvc(char *name)
{
	Entry *e;
	Service *svc;
	int h;

	h = hash(name);
	e = emalloc(sizeof *e);
	svc = emalloc(sizeof *svc);
	memmove(svc->name, name, NAMELEN);
	memmove(svc->description, "No description provided", MAXDESC);
	memmove(svc->authdom, "9front", MAXAUTH);
	memmove(svc->address, "none", MAXADDR);
	svc->status = Sreg;
	e->removed = 0;
	e->ref = 0;
	e->uniq = uniq++;
	e->svc = svc;
	e->link = services[h];
	services[h] = e;
	return e;
}

Entry *
findsvc(char *name)
{
	Entry *e;

	for(e = services[hash(name)]; e != nil; e = e->link)
		if(strcmp(name, e->svc->name) == 0)
			return e;
	return nil;
}

int
removesvc(Entry *e)
{
	Entry *s, **last;
	char *name;

	e->removed = 1;
	name = e->svc->name;
	last = &services[hash(name)];
	for(s = *last; s != nil; s = *last){
		if(strcmp(name, s->svc->name) == 0) {
			*last = s->link;
			return 1;
		}
		last = &s->link;
	}

	return 0;
}

void
insertsvc(Entry *e)
{
	int h;

	e->removed = 0;
	h = hash(e->svc->name);
	e->link = services[h];
	services[h] = e;
}

ulong
hash(char *s)
{
	ulong h;

	h = 0;
	while(*s)
		h = (h << 1) ^ *s++;
	return h % NSVCS;
}

Fid *
findfid(int fid)
{
	Fid *f, *ff;


	ff = nil;
	for(f = fids; f; f = f->next)
		if(f->fid == fid)
			return f;
		else if(!ff && !f->busy)
			ff = f;
	if(ff != nil){
		ff->fid = fid;
		return ff;
	}

	f = emalloc(sizeof *f);
	f->fid = fid;
	f->busy = 0;
	f->svc = nil;
	f->next = fids;
	fids = f;
	return f;
}

void
io(int in, int out)
{
	char *err;
	int n;

	while((n = read9pmsg(in, mdata, messagesize)) != 0){
		if(n < 0)
			error("mount read: %r");
		if(convM2S(mdata, n, &rhdr) != n)
			error("convM2S format error: %r");
		thdr.data = (char*)mdata + IOHDRSZ;
		thdr.fid = rhdr.fid;
		if(!fcalls[rhdr.type])
			err = "bad fcall request";
		else
			err = (*fcalls[rhdr.type])(findfid(rhdr.fid));
		thdr.tag = rhdr.tag;
		thdr.type = rhdr.type + 1;
		if(err){
			thdr.type = Rerror;
			thdr.ename = err;
		}
		n = convS2M(&thdr, mdata, messagesize);
		if(write(out, mdata, n) != n)
			error("mount write");
	}
}

int
alive(Entry *svc)
{
	int fd;

	if(svc->svc->status == Spersist)
		return 2;
	if(strcmp(svc->svc->address, "none") == 0)
		return 2;
	fd = dial(svc->svc->address, nil, nil, nil);
	if(fd < 0){
		if(svc->svc->status == Sreg)
			return 2;
		return -1;
	}
	close(fd);
	if(svc->svc->status != Sok)
		return 0;
	return 1;
}

void
watch(void)
{
	/* Status, uptime */
	Entry *svc;
	int i;
	int seconds;
	vlong start;

	seconds = 30;
	for(;;) {
		start = nsec();
		for(i = 0; i < seconds; i++)
			sleep(1000);
		for(i = 0; i < NSVCS; i++)
			for(svc = services[i]; svc != nil; svc = svc->link){
				switch(alive(svc)){
				case -1: 
					/* Offline */
					svc->svc->status = Sdown;
					break;
				case 0:
					/* Coming online */
					svc->svc->status = Sok;
					svc->svc->uptime = 0;
					break;
				case 1:
					svc->svc->status = Sok;
					svc->svc->uptime += ((nsec() - start) / 1000000000LL);
					break;
				default:
					/* Still in setup or is persist, do not overwrite */
					break;
				}
			}
	}
}

void *
emalloc(ulong n)
{
	void *p;

	if((p = malloc(n)) != nil){
		memset(p, 0, n);
		return p;
	}
	error("out of memory!");
	return nil;
}

char *
estrdup(char *s)
{
	char *d;
	int n;

	n = strlen(s)+1;
	d = emalloc(n);
	memmove(d, s, n);
	return d;
}

void
error(char *s)
{
	fprint(2, "svcfs: %s\n", s);
	exits(s);
}
