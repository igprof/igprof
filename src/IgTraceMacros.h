#ifndef IG_TRACE_IG_TRACE_MACROS_H
# define IG_TRACE_IG_TRACE_MACROS_H

#define IGTRACE_MERGE2(a,b)		a##b
#define IGTRACE_MERGE3(a,b,c)		a##b##c

#define IGTRACE_ARGS0()			/* empty */
#define IGTRACE_ARGS1(a)		a
#define IGTRACE_ARGS2(a,b)		a,b
#define IGTRACE_ARGS3(a,b,c)		a,b,c
#define IGTRACE_ARGS4(a,b,c,d)		a,b,c,d
#define IGTRACE_ARGS5(a,b,c,d,e)	a,b,c,d,e
#define IGTRACE_ARGS6(a,b,c,d,e,f)	a,b,c,d,e,f

#define IGTRACE_ARGSREST0()		/* empty */
#define IGTRACE_ARGSREST1(a)		,a
#define IGTRACE_ARGSREST2(a,b)		,a,b
#define IGTRACE_ARGSREST3(a,b,c)	,a,b,c
#define IGTRACE_ARGSREST4(a,b,c,d)	,a,b,c,d
#define IGTRACE_ARGSREST5(a,b,c,d,e)	,a,b,c,d,e
#define IGTRACE_ARGSREST6(a,b,c,d,e,f)	,a,b,c,d,e,f

#define IGTRACE_DUAL_HOOK(n, ret, dofun, id1, id2, args, argnames, fun, v, lib)	\
    IGTRACE_LIBHOOK(n, ret, dofun, id1, args, argnames, fun, 0, 0)		\
    IGTRACE_LIBHOOK(n, ret, dofun, id2, args, argnames, fun, v, lib)
    
#define IGTRACE_HOOK(n, ret, dofun, id, args, argnames, fun)			\
    IGTRACE_LIBHOOK(n, ret, dofun, id, args, argnames, fun, 0, 0)

#define IGTRACE_LIBHOOK(n, ret, dofun, id, args, argnames, fun, v, lib)		\
    typedef ret igtrace_##dofun##_t (IGTRACE_MERGE2(IGTRACE_ARGS,n) args);		\
    static ret dofun (IgHook::SafeData<igtrace_##dofun##_t> &hook		\
		      IGTRACE_MERGE2(IGTRACE_ARGSREST,n) args);			\
    static ret IGTRACE_MERGE3(dofun,_stub_,id)(IGTRACE_MERGE2(IGTRACE_ARGS,n) args);\
    static IgHook::TypedData<ret(IGTRACE_MERGE2(IGTRACE_ARGS,n) args)> IGTRACE_MERGE3(dofun,_hook,id) \
      = { { 0, fun, v, lib, &IGTRACE_MERGE3(dofun,_stub_,id), 0, 0, 0 } };\
    static ret IGTRACE_MERGE3(dofun,_stub_,id) (IGTRACE_MERGE2(IGTRACE_ARGS,n) args) \
      { return dofun (IGTRACE_MERGE3(dofun,_hook,id).typed			\
		      IGTRACE_MERGE2(IGTRACE_ARGSREST,n) argnames); }

#if IGTRACE_DEBUG
# define IGTRACE_ASSERT(expr) \
    ((void)((expr) ? 1 : IgTrace::panic(__FILE__,__LINE__,__PRETTY_FUNCTION__,#expr)))
#else
# define IGTRACE_ASSERT(expr)
#endif

// #define IGTRACE_VERBOSE 1
#if IGTRACE_VERBOSE
# define IGTRACE_TRACE(expr) do { IgTrace::debug expr; } while (0)
#else
# define IGTRACE_TRACE(expr) do { ; } while (0)
#endif

#endif // IG_TRACE_IG_TRACE_MACROS_H
