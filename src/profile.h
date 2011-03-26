#ifndef PROFILE_H
# define PROFILE_H

# include "macros.h"
# include "atomic.h"
# include "hook.h"

class IgProfTrace;

HIDDEN int
igprof_panic(const char *file, int line, const char *func, const char *expr);

HIDDEN void
igprof_debug(const char *format, ...);

HIDDEN const char *
igprof_options(void);

HIDDEN bool
igprof_init(const char *id, void (*threadinit)(void),
	    bool perthread, double clockres = 0.);

HIDDEN bool
igprof_enable(bool globally);

HIDDEN bool
igprof_disable(bool globally);

HIDDEN IgProfTrace *
igprof_buffer(void);

#endif // PROFILE_H
