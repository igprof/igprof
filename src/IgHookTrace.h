#ifndef IG_HOOK_IG_HOOK_TRACE_H
# define IG_HOOK_IG_HOOK_TRACE_H

class IgHookTrace
{
public:
    static int		stacktrace (void **addresses, int nmax);
    static void *	tosymbol (void *address);
    static bool		symbol (void *address, const char *&sym,
		    		const char *&lib, int &offset,
				int &liboffset);
};

#endif // IG_HOOK_IG_HOOK_TRACE_H
