#include "IgTrace.h"
#include "IgHook.h"
#include "IgHookTrace.h"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <pthread.h>
#include <unistd.h>

class IgTraceMem
{
public:
    static void initialize (void);
};

// Traps for this profiler module
IGTRACE_DUAL_HOOK (1, void *, domalloc, _main, _libc,
		   (size_t n), (n),
  		   "malloc", 0, "libc.so.6")

// Data for this trace module
static bool s_initialized = false;

/** Initialise memory tracing.  */
void
IgTraceMem::initialize (void)
{
    if (s_initialized) return;
    s_initialized = true;

    const char	*options = IgTrace::options ();
    bool	enable = false;

    while (options && *options)
    {
	while (*options == ' ' || *options == ',')
	    ++options;

        if (! strncmp (options, "mem", 3))
	{
	    options += 3;
	    enable = true;
	}
	else
	    options++;

	while (*options && *options != ',' && *options != ' ')
	    options++;
    }

    if (! enable)
	return;

    if (! IgTrace::initialize ())
	return;

    IgTrace::disable ();
    IgHook::hook (domalloc_hook_main.raw);
#if __linux__
    if (domalloc_hook_main.raw.chain) IgHook::hook (domalloc_hook_libc.raw);
#endif

    IgTrace::debug ("Tracing memory allocations\n");
    IgTrace::enable ();
}

//////////////////////////////////////////////////////////////////////
// Traps for this trace module.
static void *
domalloc (IgHook::SafeData<igtrace_domalloc_t> &hook, size_t size)
{
    bool enabled = IgTrace::disable ();
    void *result = (*hook.chain) (size);
 
    if (enabled)
    {
        void *stack [800];
        int depth = IgHookTrace::stacktrace (stack, sizeof (stack)/sizeof(stack[0]));

        // If the filters pass, walk the stack to print out information.
        if (IgTrace::filter (0, stack, depth))
        {
	    char buf [1024];
	    write (2, buf, sprintf (buf,
				    "*** MALLOC %ld bytes => %p, by %.500s [thread %lu pid %ld]\n",
				    (unsigned long) size, result, IgTrace::program(),
				    (unsigned long) pthread_self (), (long) getpid ()));
        }
    }
 
    IgTrace::enable ();
    return result;
}

//////////////////////////////////////////////////////////////////////
static bool autoboot = (IgTraceMem::initialize (), true);
