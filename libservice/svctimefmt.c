#include <u.h>
#include <libc.h>
#include "service.h"

int
svctimefmt(Fmt *f)
{
	vlong u, d, h, m;

	/* Untested at the moment */
	u = va_arg(f->args, vlong);
	d = u / 86400;
	h = u % 86400 / 3600;
	m = u % 3600 / 60;
	/* Print whole integer values for each */
	return fmtprint(f, "\'%d days, %d hours, %d minutes\'", (int)d, (int)h, (int)m);
}
