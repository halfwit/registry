#include <u.h>
#include <libc.h>
#include "service.h"

int
svctimefmt(Fmt *f)
{
	vlong u, d, h, m, s;

	/* Untested at the moment */
	u = va_arg(f->args, vlong);
	d = u / 86400;
	h = u % 3600; // Give remaining hours
	m = h % 60;
	s = m % 60;
	/* Print whole integer values for each */
	return fmtprint(f, "\'%d days, %d hours, %d minutes, %d seconds\'", (int)d, (int)h, (int)m, (int)s);
}
