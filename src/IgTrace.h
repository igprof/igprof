#ifndef IG_TRACE_IG_TRACE_H
# define IG_TRACE_IG_TRACE_H

# include "IgHook.h"
# include "IgTraceMacros.h"

/** Core tracing implementation.  Implements utilities needed
    to implement actual trace modules. */
class IgTrace
{
public:
    static int			panic (const char *file, int line,
	    			       const char *func, const char *expr);
    static void			debug (const char *format, ...);
    static const char *		options (void);
    static const char *		program (void);
    static bool			filter (const char *info, void *stack [], int depth);

    static bool			initialize (void);
    static bool			enabled (void);
    static bool			enable (void);
    static bool			disable (void);
};

#endif // IG_TRACE_IG_TRACE_H
