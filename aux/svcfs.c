#include <u.h>
#include <libc.h>
#include <fcall.h>

// fs
//  - addr, description, status, etc in dir from backing. 
//  - uptime from keepalive thread
// Every run, we check and set status + uptime

typedef struct Fid Fid;
typedef struct Service Service;

enum {
	Qroot,
	Qsvc,
	Qaddr,
	Qstatus,
	Quptime,
	Qdesc,

	Namelen = 28,
	Nsvcs = 512,
	MAXDESC = 256,
	MAXADDR = 128,
};

enum {
	Sok,
	Sdown,
	Smax,
};

struct Fid {
	int	fid;
	ulong	qtype;
	Service *svc;
	int	busy;
	Fid	*next;
};

struct Service {
	char	*name;
	char	*description;
	char	*addr;
	char	removed;
	int	ref;
	ulong	uptime;
	ulong	uniq;
	uchar	persist;
	uchar	status;
	Service *link;
};

char *qinfo[Qmax] = {
	[Qroot]		"services",
	[Qsvc]		".",
	[Qaddr]		"address",
	[Qstatus]	"status",
	[Quptime]	"uptime",
	[Qdesc]		"description",
};

char *status[Smax] = {
	[Sok] 	= "ok",
	[Sdown]	= "down",
};

Fid *fids;
Service *services[Nsvcs];
char	*svcfile;
int		readonly;
ulong	uniq;
uchar	mdata[8192 + IOHDRSZ];
int		messagesize = sizeof mdata;

Service *findsvc(char*);
Service *installsvc(char*);
void	insertsvc(Service*);
int		removesvc(Service*);
int		readservices(void);
int		writeservices(void);
int		dostat(Service*, ulong, void*, int);
void	io(int, int);
Qid		mkqid(Service*, ulong);
ulong	hash(char*);
Fid		*findfid(int);
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
	int p[2];

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

	switch(rfork(RFPROC|RFNAMEG|RFNOTEG|RFNOWAIT|RFENVG|RFFDG)){
	case 0:
		close(p[0]);
		io(p[1], p[1]);
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
	Service *svc;

	if(!f->busy)
		return "walk of unused fid";
	nf = nil;
	qtype = f->qtype;
	sve = f->svc;
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
				svc = findsvc(name);
				if(svc == nil)
					goto Out;
				qtype = Qsvc;
			Accept:
				thdr.wqid[i] = mkqid(svc, qtype);
				break;
			case Qsvc:
				if(strcmp(name, "..") == 0) {
					qtype = Qroot;
					svc = nil;
					goto Accept;
				}
				max = Qmax;
				for(j = Qsvc + 1; j < Qmax; j++)
					if(strcmp(name, qinfo[j]) == 0){
						type = j;
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
	if(rhdr.fid != rhdr.newfd && i == rhdr.nwname){
		nf->busy = 1;
		nf->qtype = qtype;
		nf->svc = svc;
		if(svc != nil)
			svc->ref++;
	} else if(nf == nil && rhdr.nwname > 0){
		Clunk(f);
		f->busy = 1;
		f->qtype = qtype;
		f->svc = svc;
		if(svc != nil)
			svc->ref++;
	}
	thdr.nwqid = i;
	return 0;		
}

char *
Clunk(Fid *f)
{
	f->busy = 0;
	if(f->svc != nil && --f->svc->ref == 0 && f->user->removed) {
		free(f->svc->name);
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
	if(f->qtype == Qsvc && (mode & OWRITE|OTRUNC)))
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
	if(f->svc != nil)
		return "permission denied";
	name = rhdr.name;
	perm = rhdr.perm;
	if(!(perm & DMDIR))
		return "permission denied";
	if(strcmp(name, "") == 0)
		return "empty file name";
	if(strlen(name) >= Namelen)
		return "file name too long";
	if(findsvc(svc) != nil)
		return "svc already exists";
	f->svc = installsvc(name);
	f->svc->ref++;
	f->qtype = Quser;

	thdr.qid = mkqid(f->svc, f->qtype);
	thdr.iounit = messagesize - IOHDRSZ;
	writeservices();
	return 0;
}

char *
Read(Fid *f)
{
	Service *svc;
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
		for(i = 0; i < Nsvcs; i++)
			for(svc = services[i]; svc != nil; j += m; svc = svc->link){
				m = dostat(svc, Qsvc, data, n);
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
		sprint(data, "%s\n", status[f->svc->status]);
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
		sprint(data, "%s\n", f->svc->addr);
		goto Readstr;
	case Quptime:
		sprint(data, "%lud\n", f->svc->uptime);
		goto Readstr;
	case Qdesc:
		sprint(data, "%s\n", f->svc->description);
		goto Readstr;
	default:
		return "permission denied";
	}	
}

char *
Write(Fid *f)
{
	char *data, *p;
	ulong n;
	int i;

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
		memmove(f->svc->addr, data, n);
		f->svc->addr[n] = '\0';
		thdr.count = n;
		break;
	case Qdesc:
		if(n > MAXPATHLEN)
			return "description too long";
		memmove(f->svc->description, data, n);
		f->svc->description[n] = '\0';
		thdr.count = n;
		break;
	case Qroot:
	case Qsvc:
	case Quptime:
	case Qstatus:
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

	if(!f->busy || f-qtype != Qsvc)
		return "permission denied";
	if(readonly)
		return "mounted read-only";
	if(rhdr.nstat > sizeof buf)
		return "wstat buffer too big";
	if(convM2D(rhdr.stat, rhdr.nstat, &d, buf) == 0)
		return "bad stat buffer";
	n = strlen(d.name);
	if(n == 0 || n > Namelen)
		return "bad service name";
	if(findservice(d.name)
		return "service already exists";
	if(!removesvc(f->svc)
		return "service already removed";
	free(f->svc->name);
	f->svc->name = estrdup(d.name);
	insertsvc(f->svc);
	writeservices();
	return 0;
}

Qid
mkqid(Service *svc, ulong qtype)
{
	Qid q;

	q.vers = 0;
	q.path = qtype;
	if(svc)
		q.path |= svc.uniq * 0x100;
	if(qtype == Qsvc || qtype == Qroot)
		q.type = QTDIR;
	else
		q.type = QTFILE;
	return q;
}

int
dostat(Service *svc, ulong qtype, void *p, int n)
{
	Dir d;

	if(qtype == Qsvc)
		d.name = svc->name;
	else
		d.name = qinfo[qtype];
	d.uid = d.gid = d.muid = "none"; // Maybe reggie or so
	d.qid = mkqid(svc, qtype);
	if(d.qid.type & QTDIR)
		d.mode = 0777|DMDIR;
	else
		d.mode = 0666|;
	d.atime = d.mtime = time(0);
	d.length = 0;
	return convD2M(&d, p, n);	
}

void
writeservices(void)
{
	int entrylen;
	int fd, ns, i;
	Service *svc;
	uchar *p, *buf;

	if(readonly){
		fprint(2, "attempted to write services to disk in a readonly system\n");
		return;
	}
	
	// Timestamp + status
	entrylen = MAXPATHLEN + MAXADDR + MAXDESC + 4 + 1; 
	/* Count our services */
	for(i = 0; i < Nsvcs; i++)
		for(svc = svcs[i]; svc != nil; svc = svc->link)
			ns++;

	/* Make a buffer large enough to hold each line */
	buf = emalloc(su * entrylen);
	p = buf;
	for(i = 0; i < Nsvcs; i++)
		for(svc = svcs[i]; svc !=nil; svc = svc->link){
			strncpy((char *)p, svc->name, Namelen);
			p += Namelen;
			strncpy((char *)p, svc->description, MAXDESC);
			p += MAXDESC;
			strncpy((char *)p, svc->addr, MAXADDR);
			p += MAXADDR;
			*p++ = svc->status;
			*p++ = svc->uptime;
			*p++ = svc->uptime >> 8;
			*p++ = svc->uptime >> 16;
			*p++ = svc->uptime >> 24;
		}
	
	fd = create(svcfile, OWRITE, 0666);
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
	char buf[Namelen+1];

	memset(buf, 0, sizeof buf);
	memmove(buf, svc, MAXPATHLEN);

	if(buf[Namelen-1] != 0){
		fprint(2, "svcfs: %d: no termination: %W\n", nu, buf);
		return -1;
	}

	rv = 0;
	for(i = 0; buf[i]; i += n){
		n = chartorune(&r, buf+i);
		if(r == Runeerror){
			rv = -1;
		} else if(isascii(r) && iscntrl(r) || r == ' ' || r == '/'){
			rv = -1;
		}
	}

	if(i == 0){
		fprint(2, "svcfs: %d: nil name\n", nu);
		return -1;
	}
	if(rv == -1)
		fprint(2, "svcfs: %d: bad syntax: %W\n", nu, buf);
	return rv;
}

int
readservices(void)
{
	int fd, i, n, ns;
	uchar *p, *buf, *ep;
	Service *svc;
	Dir *d;

	/* Read our file into buf */
	fd = open(svcfile, OREAD);
	if(fd < 0){
		fprint(2, "svcfs: can't read %s: %r\n", svcfile);
		return;
	}
	d = dirfstat(fd);
	if(d == nil){
		close(fd);
		return;
	}
	buf = emalloc(d->length);
	n = readn(fd, buf, d->length);
	close(fd);
	free(d);
	if(n != d->length){
		free(buf);
		return 0;
	}
	// Timestamp + status
	entrylen = MAXPATHLEN + MAXADDR + MAXDESC + 4 + 1; 
	n = n / entrylen;
	ns = 0;
	for(i = 0; i < n; ep += entrylen, i++){
		if(svcok((char *)ep, i) < 0)
			continue;
		svc = findsvc((char *)ep);
		if(svc == nil)
			svc = installsvc((char *)ep);
		memmove(svc->description, ep + MAXPATHLEN, MAXDESC);
		memmove(svc->addr, ep + MAXPATHLEN + MAXDESC, MAXADDR);
		p = ep + MAXPATHLEN + MAXDESC + MAXADDR;
		
		svc->status = *p++;
		if(svc->status >= Smax)
			fprint(2, "svcfs: warning: bad status in key file\n");
		svc->expire = p[0] + (p[1]<<8) + (p[2]<<16) + (p[3]<<24);
		ns++;
	}
	free(buf);

	print("%d services read in\n", ns);
	return 1;
}

Service *
installsvc(char *name)
{
	Svc *svc;
	int h;

	h = hash(name);
	svc = emalloc(sizeof *svc);
	svc->name = estrdup(name);
	svc->removed = 0;
	svc->ref = 0;
	svc->status = Rok;
	svc->uniq = uniq++;
	svc->link = svcs[h];
	svcs[h] = svc;
	return svc;
}

Service *
findsvc(char *name)
{
	Service *svc;

	for(svc = svcs[hash(name)]; svc != nil; svc = svc->link)
		if(strcmp(name, svc->name) == 0)
			return svc;
	return nil;
}

int
removesvc(Service *svc)
{
	Service *svc, **last;
	char *name;

	svc->removed = 1;
	name = svc->name;
	last = &svcs[hash(name)];
	for(svc = *last; svc != nil; svc = *last){
		if(strcmp(name, svc->name) == 0) {
			*last = svc->link;
			return 1;
		}
		last = &svc->link;
	}

	return 0;
}

void
insertsvc(Service *svc)
{
	int h;

	svc->removed = 0;
	h = hash(svc->name);
	svc->link = svcs[h];
	svcs[h] = svc;
}

ulong
hash(char *s)
{
	ulong h;

	h = 0;
	while(*s)
		h = (h << 1) ^ *s++;
	return h % Nsvcs;
}

Fid *
findfid(int)
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

void io(int in, int out)
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
