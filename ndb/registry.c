#include <u.h>
#include <libc.h>
#include <auth.h>
#include <fcall.h>
#include <bio.h>
#include <ip.h>
#include "dns.h"

enum
{
	Maxrequest=		1024,
	Maxreply=		8192,
	Maxrecords=		192,
	Maxfdata=		8192,

	Qdir=			0,
	Qreg=			1,
};

typedef struct Mfile	Mfile;
typedef struct Job	Job;
typedef struct Records  Records;

struct Mfile
{
	Mfile	*next;

	char	*user;
	Qid	qid;
	int	fid;
	int	bare;

	char	reply[Maxreply];
	ushort	rr[Maxrecords]; /* offset of record */
	ushort	nrr;		/* number of records */	
};

/*
 *  active requests
 */
struct Job
{
	Job	*next;
	int	flushed;
	Fcall	request;
	Fcall	reply;
};
Lock	joblock;
Job	*joblist;

struct {
	Lock;
	Mfile	*inuse;		/* active mfile's */
} mfalloc;

Svc	*registry;
int	vers;
int	debug;
char	*dbfile = "/lib/ndb/registry";
char	*reguser;
char	mtpt[Maxpath];
int	rfd[Maxremote];
int	mfd[2];
char	*logfile = "registry";

void	rversion(Job*);
void	rflush(Job*);
void	rattach(Job*, Mfile*);
char*	rwalk(Job*, Mfile*);
void	ropen(Job*, Mfile*);
void	rcreate(Job*, Mfile*);
void	rread(Job*, Mfile*);
void	rwrite(Job*, Mfile*);
void	rclunk(Job*, Mfile*);
void	rremove(Job*, Mfile*);
void	rstat(Job*, Mfile*);
void	rwstat(Job*, Mfile*);
void	rauth(Job*);
void	mountinit(char*, char*);
void	setext(char*, int, char*);
void	io(void);

static char*	resolve(char*, ...);
static char*	addsvc(char*);
static char*	rmsvc(char*);
static char*	updatesvc(char*);
static void	refresh(void);
static void	regdump(char*);
static void	sendmsg(Job*, char*);

static int	scanfmt(Fmt*);
static int	srvfmt(Fmt*);
static int	dumpfmt(Fmt*);

static char* query(Job*, Mfile*, char*, int);
static char* resolvequery(Job*, Mfile*, char*, int);

void
usage(void)
{
	fprint(2, "usage: %s [-xrd] [-f ndb-file]\n", argv0);
	exits("usage");
}

void
main(int argc, char* argv[])
{
	char servefile[Maxpath], ext[Maxpath];
	Dir *dir;
	ext[0] = 0;

	setnetmtpt(mtpt, sizeof mtpt, nil);

	ARGBEGIN{
	case 'd':
		debug = 1;
		break;
	case 'f':
		dbfile = EARGF(usage());
		break;
	case 'x':
		setnetmtpt(mtpt, sizeof mtpt, EARGF(usage()));
		setext(ext, sizeof ext, mtpt);
		break;
	} ARGEND;
	if(argc != 0)
		usage();
    


	rfork(RFREND|RFNOTEG);

	fmtinstall('F', fcallfmt);
	fmtinstall('G', srvfmt);
	fmtinstall('N', scanfmt);
	fmtinstall('D', dumpfmt);

	reglog("starting registry on %s", mtpt);

	if(openregistry())
		sysfatal("unable to open db file");

	reguser = estrdup(getuser());
	seprint(servefile, servefile+Maxpath, "#s/registry%s", ext);
	
	dir = dirstat(servefile);
	if (dir)
		sysfatal("%s exists; another registry instance is running", servefile);
	free(dir);

	mountinit(servefile, mtpt);
	reg2cache();
	io();

	_exits(0);
}

void
setext(char *ext, int n, char *p)
{
	int i, c;

	n--;
	for(i = 0; i < n; i++){
		c = p[i];
		if(c == 0)
			break;
		if(c == '/')
			c = '_';
		ext[i] = c;
	}
	ext[i] = 0;
}

void
mountinit(char *service, char *mtpt)
{
	int f;
	int p[2];
	char buf[32];

	if(pipe(p) < 0)
		sysfatal("pipe failed: %r");

	/*
	 *  make a /srv/registry
	 */
	if((f = create(service, OWRITE|ORCLOSE, 0666)) < 0)
		sysfatal("create %s failed: %r", service);
	snprint(buf, sizeof buf, "%d", p[1]);
	if(write(f, buf, strlen(buf)) != strlen(buf))
		sysfatal("write %s failed: %r", service);

	/* copy namespace to avoid a deadlock */
	switch(rfork(RFFDG|RFPROC|RFNAMEG)){
	case 0:			/* child: start main proc */
		close(p[1]);
		procsetname("%s", mtpt);
		break;
	case -1:
		sysfatal("fork failed: %r");
	default:		/* parent: make /srv/registry, mount it, exit */
		close(p[0]);

		/*
		 *  put ourselves into the file system
		 */
		if(mount(p[1], -1, mtpt, MAFTER, "") < 0)
			fprint(2, "registry mount failed: %r\n");
		_exits(0);
	}
	mfd[0] = mfd[1] = p[0];
}

Mfile*
newfid(int fid, int needunused)
{
	Mfile *mf;

	lock(&mfalloc);
	for(mf = mfalloc.inuse; mf != nil; mf = mf->next)
		if(mf->fid == fid){
			unlock(&mfalloc);
			if(needunused)
				return nil;
			return mf;
		}
	mf = emalloc(sizeof(*mf));
	mf->fid = fid;
	mf->qid.vers = vers;
	mf->qid.type = QTDIR;
	mf->qid.path = 0LL;
	mf->user = estrdup(reguser);
	mf->next = mfalloc.inuse;
	mfalloc.inuse = mf;
	mf->bare = 1;
	unlock(&mfalloc);
	return mf;
}

void
freefid(Mfile *mf)
{
	Mfile **l;

	lock(&mfalloc);
	for(l = &mfalloc.inuse; *l != nil; l = &(*l)->next)
		if(*l == mf){
			*l = mf->next;
			free(mf->user);
			memset(mf, 0, sizeof *mf);	/* cause trouble */
			free(mf);
			unlock(&mfalloc);
			return;
		}
	unlock(&mfalloc);
	sysfatal("freeing unused fid");
}

Mfile*
copyfid(Mfile *mf, int fid)
{
	Mfile *nmf;

	nmf = newfid(fid, 1);
	if(nmf == nil)
		return nil;
	nmf->fid = fid;
	free(nmf->user);
	nmf->user = estrdup(mf->user);
	nmf->qid.type = mf->qid.type;
	nmf->qid.path = mf->qid.path;
	nmf->qid.vers = vers++;
	return nmf;
}

Job*
newjob(void)
{
	Job *job;

	job = emalloc(sizeof *job);
	lock(&joblock);
	job->next = joblist;
	joblist = job;
	job->request.tag = -1;
	unlock(&joblock);
	return job;
}

void
freejob(Job *job)
{
	Job **l;

	lock(&joblock);
	for(l = &joblist; *l; l = &(*l)->next)
		if(*l == job){
			*l = job->next;
			memset(job, 0, sizeof *job);	/* cause trouble */
			free(job);
			break;
		}
	unlock(&joblock);
}

void
flushjob(int tag)
{
	Job *job;

	lock(&joblock);
	for(job = joblist; job; job = job->next)
		if(job->request.tag == tag && job->request.type != Tflush){
			job->flushed = 1;
			break;
		}
	unlock(&joblock);
}

void
io(void)
{
	long n;
	Mfile *mf;
	uchar mdata[IOHDRSZ + Maxfdata];
	Job *job;

	while((n = read9pmsg(mfd[0], mdata, sizeof mdata)) != 0){
		if(n < 0){
			syslog(1, logfile, "error reading 9P from %s: %r", mtpt);
			break;
		}

		job = newjob();
		if(convM2S(mdata, n, &job->request) != n){
			reglog("format error %ux %ux %ux %ux %ux",
				mdata[0], mdata[1], mdata[2], mdata[3], mdata[4]);
			freejob(job);
			break;
		}
		mf = newfid(job->request.fid, 0);
		if(debug)
			reglog("%F", &job->request);

		switch(job->request.type){
		default:
			warning("unknown request type %d", job->request.type);
			break;
		case Tversion:
			rversion(job);
			break;
		case Tauth:
			rauth(job);
			break;
		case Tflush:
			rflush(job);
			break;
		case Tattach:
			rattach(job, mf);
			break;
		case Twalk:
			rwalk(job, mf);
			break;
		case Topen:
			ropen(job, mf);
			break;
		case Tcreate:
			rcreate(job, mf);
			break;
		case Tread:
			rread(job, mf);
			break;
		case Twrite:
			rwrite(job, mf);
			break;
		case Tclunk:
			rclunk(job, mf);
			break;
		case Tremove:
			rremove(job, mf);
			break;
		case Tstat:
			rstat(job, mf);
			break;
		case Twstat:
			rwstat(job, mf);
			break;
		}

		freejob(job);
	}
}

void
rversion(Job *job)
{
	if(job->request.msize > IOHDRSZ + Maxfdata)
		job->reply.msize = IOHDRSZ + Maxfdata;
	else
		job->reply.msize = job->request.msize;
	job->reply.version = "9P2000";
	if(strncmp(job->request.version, "9P", 2) != 0)
		job->reply.version = "unknown";
	sendmsg(job, nil);
}

void
rauth(Job *job)
{
	sendmsg(job, "registry: authentication not required");
}

void
rflush(Job *job)
{
	flushjob(job->request.oldtag);
	sendmsg(job, 0);
}

void
rattach(Job *job, Mfile *mf)
{
	if(mf->user != nil)
		free(mf->user);
	mf->user = estrdup(job->request.uname);
	mf->qid.vers = vers++;
	mf->qid.type = QTDIR;
	mf->qid.path = 0LL;
	job->reply.qid = mf->qid;
	sendmsg(job, 0);
}

char*
rwalk(Job *job, Mfile *mf)
{
	int i, nelems;
	char *err;
	char **elems;
	Mfile *nmf;
	Qid qid;

	err = 0;
	nmf = nil;
	elems = job->request.wname;
	nelems = job->request.nwname;
	job->reply.nwqid = 0;

	if(job->request.newfid != job->request.fid){
		/* clone fid */
		nmf = copyfid(mf, job->request.newfid);
		if(nmf == nil){
			err = "clone bad newfid";
			goto send;
		}
		mf = nmf;
	}
	/* else nmf will be nil */

	qid = mf->qid;
	if(nelems > 0){
		/* walk fid */
		for(i=0; i<nelems && i<MAXWELEM; i++){
			if((qid.type & QTDIR) == 0){
				err = "not a directory";
				break;
			}
			if(strcmp(elems[i], "..") == 0 || strcmp(elems[i], ".") == 0){
				qid.type = QTDIR;
				qid.path = Qdir;
    Found:
				job->reply.wqid[i] = qid;
				job->reply.nwqid++;
				continue;
			}
			if(strcmp(elems[i], "registry") == 0){
				qid.type = QTFILE;
				qid.path = Qreg;
				goto Found;
			}
			err = "file does not exist";
			break;
		}
	}

    send:
	if(nmf != nil && (err!=nil || job->reply.nwqid<nelems))
		freefid(nmf);
	if(err == nil)
		mf->qid = qid;
	sendmsg(job, err);
	return err;
}

void
ropen(Job *job, Mfile *mf)
{
	int mode;
	char *err;

	err = 0;
	mode = job->request.mode;
	if(mf->qid.type & QTDIR)
		if(mode)
			err = "permission denied";
	job->reply.qid = mf->qid;
	job->reply.iounit = 0;
	sendmsg(job, err);
}

void
rcreate(Job *job, Mfile *mf)
{
	USED(mf);
	sendmsg(job, "creation permission denied");
}

void rclunk(Job *job, Mfile *mf)
{
	freefid(mf);
	sendmsg(job, 0);
}

void
rremove(Job *job, Mfile *mf)
{
	USED(mf);
	sendmsg(job, "remove permission denied");
}

void 
rread(Job *job, Mfile *mf)
{
	int i, n;
	long clock;
	ulong cnt;
	vlong off;
	char *err;
	uchar buf[Maxfdata];
	Dir dir;

	n = 0;
	err = nil;
	off = job->request.offset;
	cnt = job->request.count;
	*buf = '\0';
	job->reply.data = (char*)buf;
	if(mf->qid.type & QTDIR){
		clock = time(nil);
		if(off == 0){
			memset(&dir, 0, sizeof dir);
			dir.name = "registry";
			dir.qid.type = QTFILE;
			dir.qid.vers = vers;
			dir.qid.path = Qreg;
			dir.mode = 0666;
			dir.length = 0;
			dir.uid = dir.gid = dir.muid = mf->user;
			dir.atime = dir.mtime = clock;
			n = convD2M(&dir, buf, sizeof buf);
		}
	} else if (off < 0)
		err = "negative read offset";
	else {
		if(mf->bare)
			query(job, mf, "all", 0);
		for(i = 1; i < mf->nrr; i++)
			if(mf->rr[i] > off)
				break;
		if(i <= mf->nrr){
			if(off + cnt > mf->rr[i])
				n = mf->rr[i] - off;
			else
				n = cnt;
			assert(n >= 0);
			job->reply.data = mf->reply + off;
		}
	}
	job->reply.count = n;
	sendmsg(job, err);	
}

void 
rwrite(Job *job, Mfile *mf)
{
	int send, pipe2rc;
	ulong cnt;	
	char *err, *atype;
	char errbuf[ERRMAX];
	
	err = nil;
	cnt = job->request.count;
	send = 1;
	if(mf->qid.type & QTDIR)
		err = "can't write directory";
	else if (job->request.offset != 0)
		err = "writing at non-zero offset";
	else if (cnt >= Maxrequest)
		err = "request too long";
	else
		send = 0;
	if(send)
		goto send;

	job->request.data[cnt] = 0;
	if(cnt > 0 && job->request.data[cnt-1] == '\n')
		job->request.data[cnt-1] = 0;

	if(strcmp(mf->user, "none") == 0 || strcmp(mf->user, reguser) != 0)
		goto query; /* We don't want remote clients to modify our local */

	/*
	 * special commands
	 */
	send = 1;
	if(strcmp(job->request.data, "debug")==0)
		debug ^= 1;
	else if(strcmp(job->request.data, "dump")==0)
		regdump("/lib/ndb/regdump");
	else if (strcmp(job->request.data, "refresh")==0)
		refresh();
	else if (strncmp(job->request.data, "add ", 4)==0)
		err = addsvc(job->request.data + 4);
	else if (strncmp(job->request.data, "rm ", 3)==0)
		err = rmsvc(job->request.data + 3);
	else if (strncmp(job->request.data, "update ", 7)==0)
		err = updatesvc(job->request.data + 7);
	else
		send = 0;
	if (send)
		goto send;

query:
	/*
	 *	kill previous reply
	 */
	mf->nrr = 0;
	mf->rr[0] = 0;
	pipe2rc = 0;
	
	atype = strchr(job->request.data, ' ');
	if(atype == 0){
		snprint(errbuf, sizeof errbuf, "illegal request %s", job->request.data);
		err = errbuf;
		goto send;
	} else
		*atype++ = 0;

	if(strcmp(atype, "svc") == 0)
		pipe2rc++;
	else if(strcmp(atype, "scan") != 0){
		snprint(errbuf, sizeof errbuf, "unknown query %s", atype);
		err = errbuf;
		goto send;
	}

	err = query(job, mf,job->request.data, pipe2rc);
send:
	mf->bare = 0;
	job->reply.count = cnt;
	sendmsg(job, err);
}

void
rstat(Job *job, Mfile *mf)
{
	Dir dir;
	uchar buf[IOHDRSZ+Maxfdata];
	
	memset(&dir, 0, sizeof dir);
	if(mf->qid.type & QTDIR){
		dir.name = ".";
		dir.mode = DMDIR|0555;
	}else{
		dir.name = "registry";
		dir.mode = 0666;
	}
	dir.qid = mf->qid;
	dir.length = 0;
	dir.uid = dir.gid = dir.muid = mf->user;
	dir.atime = dir.mtime = time(nil);
	job->reply.nstat = convD2M(&dir, buf, sizeof buf);
	job->reply.stat = buf;
	sendmsg(job, 0);
}

void
rwstat(Job *job, Mfile *mf)
{
	USED(mf);
	sendmsg(job, "wstat permission denied");
}

static char *
resolvequery(Job *job, Mfile *mf, char *p, int pipe2rc)
{
	int match, i;
	int n;
	Svc *c;

	char cmd[256];
	char buf[8192+1];

	lock(&joblock);
	if(!job->flushed){
		match = n = 0;
		mf->nrr = 0;

		snprint(cmd, sizeof(cmd), "%s %s", p, ((pipe2rc)?"svc":"scan"));

		for(i = 0; i < Maxremote && !match && rfd[i] > 1; i++){
			seek(rfd[i], 0, 0);
			write(rfd[i], cmd, sizeof cmd);

			seek(rfd[i], 0, 0);
			while(read(rfd[i], buf, sizeof(buf)-1) > 0){	
				match = 1;
				c = rstr2svc(buf);
				mf->rr[mf->nrr++] = n;
				if(pipe2rc)
					n += snprint(mf->reply+n, Maxreply-n, "%G", c);
				else
					n += snprint(mf->reply+n, Maxreply-n, "%N", c);
				free(c);
			}
		}
	}
	unlock(&joblock);

	return 0;
}

static char *
query(Job *job, Mfile *mf, char *p, int pipe2rc)
{
	int n;

	Svc *c;
	lock(&joblock);
	if(!job->flushed){
		n = 0;
		mf->nrr = 0;
		for(c = registry; c && n < Maxreply; c = c->next)
			if((strncmp(p, c->labl, strlen(p))==0) || (strcmp(p, "all")==0)){
				mf->rr[mf->nrr++] = n;
				if(pipe2rc)
					n += snprint(mf->reply+n, Maxreply-n, "%G", c);
				else
					n += snprint(mf->reply+n, Maxreply-n, "%N", c);
			}
		mf->rr[mf->nrr] = n;
	}
	unlock(&joblock);
	return nil;
}

static void
sendmsg(Job *job, char *err)
{
	int n;
	uchar mdata[IOHDRSZ+Maxfdata];
	char ename[ERRMAX];

	if(err){
		job->reply.type = Rerror;
		snprint(ename, sizeof ename, "registry: %s", err);
		job->reply.ename = ename;
	}else
		job->reply.type = job->request.type+1;
	job->reply.tag = job->request.tag;
	n = convS2M(&job->reply, mdata, sizeof mdata);
	if(n == 0){
		warning("sendmsg convS2M of %F returns 0", &job->reply);
		abort();
	}
	lock(&joblock);
	if(job->flushed == 0)
		if(write(mfd[1], mdata, n)!=n)
			sysfatal("mount write");
	unlock(&joblock);
	if(debug)
		reglog("%F %d", &job->reply, n);
}

static void
regdump(char *file)
{
	Svc *rp;
	int fd;

	fd = create(file, OWRITE, 0666);
	if(fd < 0)
		return;
	lock(&mfalloc);
	for(rp = registry; rp; rp = rp->next)
		fprint(fd, "%D\n\n", rp);
	unlock(&mfalloc);
	close(fd);
}

static void
refresh(void)
{	
	Svc *c;
	char dial[Maxdial];

	for(c = registry; c; c = c->next){
		/* Don't remove the ones we've added since startup */
		if(!c->perm)
			continue;
		snprint(dial, Maxdial, "%s!%s!%s", c->trns, c->host, c->port);
		rmsvc(dial);
		/* Reset so we don't have messy loops */
		c = registry;
	}
	reg2cache();
}

static char *
resolve(char *cmd, ...)
{
	int n;
	char fullcmd[256];
	char buf[8192+1];
	va_list arg;
	
	va_start(arg, cmd);
	vseprint(fullcmd, fullcmd+sizeof(fullcmd), cmd, arg);
	va_end(arg);

	/* We only operate on our local rfd */
	seek(rfd[0], 0, 0);
	write(rfd[0], fullcmd, sizeof fullcmd);

	seek(rfd[0], 0, 0);
	while((n = read(rfd[0], buf, sizeof(buf)-1)) > 0){
		buf[n++] = '\n';
		write(1, buf, n);
	}
	return buf;
}

static char *
addsvc(char *args)
{
	if(debug)
		reglog("Adding entry: %s", args);

	return rstr2cache(args, 0);
}

static char *
rmsvc(char *args)
{
	if(debug)
		reglog("Removing entry: %s", args);
	return rstrdtch(args);
}

static char *
updatesvc(char *args)
{
	if(debug)
		reglog("Updating entry: %s", args);
	return rstrupdt(args);
}

void
warning(char *fmt, ...)
{
	char regerr[256];
	va_list arg;

	va_start(arg, fmt);
	vseprint(regerr, regerr+sizeof(regerr), fmt, arg);
	va_end(arg);
	syslog(1, logfile, regerr);
}

void
reglog(char *fmt, ...)
{
	char regerr[256];
	va_list arg;
	
	va_start(arg, fmt);
	vseprint(regerr, regerr+sizeof(regerr), fmt, arg);
	va_end(arg);
	syslog(0, logfile, regerr);
}

void*
emalloc(int size)
{
	void *x;

	x = malloc(size);
	if(x == nil)
		sysfatal("out of memory");
	memset(x, 0, size);
	return x;
}

char*
estrdup(char *s)
{
	int size;
	char *p;

	size = strlen(s);
	p = malloc(size+1);
	if(p == nil)
		sysfatal("out of memory");
	memmove(p, s, size);
	p[size] = 0;
	return p;
}

static int
srvfmt(Fmt *f)
{
	Svc *r;
	char mf[Maxpath+1], auth[7];
	
	r = va_arg(f->args, Svc*);
	mf[0] = 0;
	auth[0] = 0;
		
	if(strcmp(r->mtpt, "")!= 0)
		snprint(mf, sizeof(r->mtpt)+1, " %s", r->mtpt);

	if(strcmp(r->auth, "none")==0)
		snprint(auth, 4, "srv");
	else
		snprint(auth, 7, "srvtls");

	return fmtprint(f, "%s!%s!%s\n",
		r->trns, r->host, r->port);
}

static int
scanfmt(Fmt *f)
{
	Svc *r;
	char mf[Maxpath+6]; /* pad for our tuple attrs */

	mf[0] = 0;
	r = va_arg(f->args, Svc*);
	if(strcmp(r->mtpt, "")!=0)
		snprint(mf, sizeof(r->mtpt)+6, " mtpt=%s", r->mtpt);
	return fmtprint(f, "service=%s!%s!%s label='%s' auth=%s%s\n",
		r->trns, r->host, r->port, r->labl, r->auth, mf);
}

static int
dumpfmt(Fmt *f)
{
	Svc *r;
	char mf[Maxpath+7]; /* pad for our tuple attrs */

	r = va_arg(f->args, Svc*);
	if(r->mtpt != 0)
		snprint(mf, sizeof(r->mtpt) + 7, "\n\tmtpt=%s", r->mtpt);
	return fmtprint(f, "service=%s!%s!%s\n\tlabel=%s\n\tauth=%s%s",
		r->trns, r->host, r->port, r->labl, r->auth, mf);
}

