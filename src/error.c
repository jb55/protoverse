
#include "error.h"

#include <stdlib.h>
#include <stdarg.h>

void note_error_(struct cursor *errs, struct cursor *p, const char *fmt, ...)
{
	static char buf[512];
	struct error err;

	va_list ap;
	va_start(ap, fmt);
	vsprintf(buf, fmt, ap);
	va_end(ap);

	err.msg = (char*)errs->p;
	err.pos = p->p - p->start;

	if (!cursor_push_error(errs, &err)) {
		fprintf(stderr, "arena OOM when recording error, ");
		fprintf(stderr, "cur->p at %ld, remaining %ld, strlen %ld\n",
				p->p - p->start, p->end - p->p, strlen(buf));
		return;
	}
}

