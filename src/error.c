
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

	err.msg = buf;
	err.pos = p ? p->p - p->start : 0;

	if (!cursor_push_error(errs, &err)) {
		fprintf(stderr, "arena OOM when recording error, ");
		fprintf(stderr, "errs->p at %ld, remaining %ld, strlen %ld\n",
				errs->p - errs->start, errs->end - errs->p, strlen(buf));
		return;
	}
}

