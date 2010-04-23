#include "IgTrace.h"
#include "IgTraceAtomic.h"
#include "IgHookTrace.h"
#include <sys/types.h>
#include <sys/time.h>
#include <cstdlib>
#include <cstdio>
#include <cstdarg>
#include <cerrno>
#include <cstring>
#include <unistd.h>

#ifdef __APPLE__
# include <crt_externs.h>
# define program_invocation_name **_NSGetArgv()
#endif

/// Structure for tracking filters.
struct IgTraceFilter
{
    IgTraceFilter	*nextFilter;
    char		*extraInfo;
    char		*functionName;
    char		*libraryName;
};

// Data for this profiler module
static IgTraceAtomic	s_enabled	= 0;
static bool		s_initialized	= false;
static bool		s_activated	= false;
static volatile int	s_quitting	= 0;
static IgTraceFilter	*s_filters	= 0;

/** Initialise the tracing core itself.  Prepares the the program
    for tracing.  Automatically triggered to run on library load.
    All trace modules should invoke this method before doing their
    own initialisation.

    Returns @c true if tracing is activated in this process.  */
bool
IgTrace::initialize (void)
{
    if (! s_initialized)
    {
	s_initialized = true;

	const char *options = IgTrace::options ();
	if (! options || ! *options)
	{
	    IgTrace::debug ("$IGTRACE not set, not tracing this process\n");
	    return s_activated = false;
	}
        while (options && *options)
        {
	    while (*options == ' ' || *options == ',')
	        ++options;

	    if (! strncmp (options, "igtrace:reject='", 16))
	    {
	        options += 16;

	        const char *info = options;
	        int infolen = 0;
	        while (*options && *options != '\'' && *options != ':')
		    ++options, ++infolen;
	        if (*options == ':')
		    ++options;

	        const char *func = options;
	        int funclen = 0;
	        while (*options && *options != '\'' && *options != ':')
		    ++options, ++funclen;
	        if (*options == ':')
		    ++options;

	        const char *lib = options;
	        int liblen = 0;
	        while (*options && *options != '\'' && *options != ':')
		    ++options, ++liblen;

	        IgTraceFilter *f = new IgTraceFilter;
	        f->nextFilter = 0;
	        f->extraInfo     = (infolen ? strndup (info, infolen) : 0);
	        f->functionName  = (funclen ? strndup (func, funclen) : 0);
	        f->libraryName   = (liblen  ? strndup (lib,  liblen)  : 0);

	        IgTraceFilter **chain = &s_filters;
	        while (*chain)
		    chain = &(*chain)->nextFilter;
    
	        *chain = f;

	        while (*options && *options != '\'')
		    ++options;
	    }
	    else
	        options++;

	    while (*options && *options != ',' && *options != ' ')
	        options++;
        }

	const char *target = getenv ("IGTRACE_TARGET");
	if (target && ! strstr (program_invocation_name, target))
	{
	    IgTrace::debug ("Current process not selected for tracing:"
		       	    " process '%s' does not match '%s'\n",
		       	    program_invocation_name, target);
	    return s_activated = false;
    	}

	IgTrace::debug ("Activated in %s\n", program_invocation_name);
	IgTrace::debug ("Options: %s\n", IgTrace::options ());
	s_activated = true;
	s_enabled = 1;
    }

    if (! s_activated)
	return false;

    return true;
}

/** Check if the profiler is currently enabled.  This function should
    be called by asynchronous signal handlers to check whether they
    should record profile data -- not for the actual running where
    the value of the flag has little useful value, but to make sure
    no data is gathered after the system has started to close down.  */
bool
IgTrace::enabled (void)
{
    return s_enabled > 0;
}

/** Enable the profiling system.  This is safe to call from anywhere,
    but note that profiling system will only be enabled, not unlocked.
    Use #IgTraceLock instead if you need to manage exclusive access.
    
    Returns @c true if the profiler is enabled after the call. */
bool
IgTrace::enable (void)
{
    IgTraceAtomic newval = IgTraceAtomicInc (&s_enabled);
    return newval > 0;
}

/** Disable the profiling system.  This is safe to call from anywhere,
    but note that profiling system will only be disabled, not locked.
    Use #IgTraceLock instead if you need to manage exclusive access.
    
    Returns @c true if the profiler was enabled before the call.  */
bool
IgTrace::disable (void)
{
    IgTraceAtomic newval = IgTraceAtomicDec (&s_enabled);
    return newval >= 0;
}

/** Get user-provided profiling options.  */
const char *
IgTrace::options (void)
{
     static const char *s_options = getenv ("IGTRACE");
     return s_options;
}

/** Internal assertion helper routine.  */
int
IgTrace::panic (const char *file, int line, const char *func, const char *expr)
{
    IgTrace::disable ();

#if __linux
    fprintf (stderr, "%s: ", program_invocation_name);
#endif
    fprintf (stderr, "%s:%d: %s: assertion failure: %s\n", file, line, func, expr);

    void *trace [128];
    int levels = IgHookTrace::stacktrace (trace, 128);
    for (int i = 2; i < levels; ++i)
    {
	const char	*sym = 0;
	const char	*lib = 0;
	long		offset = 0;
	long		liboffset = 0;
	IgHookTrace::symbol (trace [i], sym, lib, offset, liboffset);
	fprintf (stderr, "  %p %s %s %ld [%s %s %ld]\n",
		 trace [i], sym, (offset < 0 ? "-" : "+"),
		 labs(offset), lib, (liboffset < 0 ? "-" : "+"),
		 labs(liboffset));
    }

    // abort ();
    IgTrace::enable ();
    return 1;
}

/** Internal printf()-like debugging utility.  Produces output if
    $IGTRACE_DEBUGGING environment variable is set to any value.  */
void
IgTrace::debug (const char *format, ...)
{
    static const char *debugging = getenv ("IGTRACE_DEBUGGING");
    if (debugging)
    {
	timeval tv;
	gettimeofday (&tv, 0);
	fprintf (stderr, "*** IgTrace(%lu, %.3f): ",
		 (unsigned long) getpid(),
		 tv.tv_sec + 1e-6*tv.tv_usec);

	va_list args;
	va_start (args, format);
	vfprintf (stderr, format, args);
	va_end (args);
    }
}

/** Return program name. */
const char *
IgTrace::program (void)
{
    return program_invocation_name;
}

/** Walk the stack evaluating filters.  */
bool
IgTrace::filter (const char *info, void *stack [], int depth)
{
    bool pass = true;
    IgTraceFilter *f = s_filters;
    while (f && pass)
    {
	if (info && f->extraInfo && strstr (info, f->extraInfo))
	    pass = false;

	for (int i = 0; i < depth && pass; ++i)
	{
	    bool	passthis = true;
	    const char	*sym = 0;
	    const char	*lib = 0;
	    long	junk = 0;
	    
            if (! IgHookTrace::symbol (stack[i], sym, lib, junk, junk))
		continue;

	    if (passthis && sym && f->functionName && strstr (sym, f->functionName))
		passthis = false;

	    if (passthis && lib && f->libraryName && strstr (lib, f->libraryName))
		passthis = false;

	    if (! passthis)
		pass = false;
	}

	f = f->nextFilter;
    }

    return pass;
}

//////////////////////////////////////////////////////////////////////
static bool autoboot = IgTrace::initialize ();
