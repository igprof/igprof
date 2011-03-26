#ifndef MACROS_H
# define MACROS_H

#define UNUSED       __attribute__((unused))
#define HIDDEN       __attribute__((visibility("hidden")))
#define VISIBLE      __attribute__((visibility("default")))
#define LIKELY(x)    __builtin_expect(bool(x), true)
#define UNLIKELY(x)  __builtin_expect(bool(x), false)

#define MERGE2(a,b)              a##b
#define MERGE3(a,b,c)            a##b##c

#define ARGS0()                  /* empty */
#define ARGS1(a)                 a
#define ARGS2(a,b)               a,b
#define ARGS3(a,b,c)             a,b,c
#define ARGS4(a,b,c,d)           a,b,c,d
#define ARGS5(a,b,c,d,e)         a,b,c,d,e
#define ARGS6(a,b,c,d,e,f)       a,b,c,d,e,f
#define ARGS7(a,b,c,d,e,f,g)     a,b,c,d,e,f,g

#define ARGSREST0()              /* empty */
#define ARGSREST1(a)             ,a
#define ARGSREST2(a,b)           ,a,b
#define ARGSREST3(a,b,c)         ,a,b,c
#define ARGSREST4(a,b,c,d)       ,a,b,c,d
#define ARGSREST5(a,b,c,d,e)     ,a,b,c,d,e
#define ARGSREST6(a,b,c,d,e,f)   ,a,b,c,d,e,f
#define ARGSREST7(a,b,c,d,e,f,g) ,a,b,c,d,e,f,g

#define DUAL_HOOK(n, ret, dofun, id1, id2, args, argnames, fun, v, lib)	\
  LIBHOOK(n, ret, dofun, id1, args, argnames, fun, 0, 0)		\
  LIBHOOK(n, ret, dofun, id2, args, argnames, fun, v, lib)

#define HOOK(n, ret, dofun, id, args, argnames, fun)			\
  LIBHOOK(n, ret, dofun, id, args, argnames, fun, 0, 0)

#define LIBHOOK(n, ret, dofun, id, args, argnames, fun, v, lib)		\
  typedef ret igprof_##dofun##_t (MERGE2(ARGS,n) args);			\
  static ret dofun(IgHook::SafeData<igprof_##dofun##_t> &hook		\
		   MERGE2(ARGSREST,n) args);				\
  static ret MERGE3(dofun,_stub_,id)(MERGE2(ARGS,n) args);		\
  static IgHook::TypedData<ret(MERGE2(ARGS,n) args)> MERGE3(dofun,_hook,id) \
  = { { 0, fun, v, lib, &MERGE3(dofun,_stub_,id), 0, 0, 0 } };		\
  static ret MERGE3(dofun,_stub_,id) (MERGE2(ARGS,n) args)		\
  { return dofun(MERGE3(dofun,_hook,id).typed				\
		 MERGE2(ARGSREST,n) argnames); }

#if DEBUG
# define ASSERT(expr)							\
  ((void)((expr) ? 1 : igprof_panic(__FILE__,__LINE__,__PRETTY_FUNCTION__,#expr)))
#else
# define ASSERT(expr)
#endif

// #define VERBOSE 1
#if VERBOSE
# define TRACE(expr) do { igprof_debug expr; } while (0)
#else
# define TRACE(expr) do { ; } while (0)
#endif

#define RDTSC(v)							\
  do { unsigned lo, hi;							\
    __asm__ volatile("rdtsc" : "=a" (lo), "=d" (hi));			\
    (v) = ((uint64_t) lo) | ((uint64_t) hi << 32);			\
  } while (0)

#endif // MACROS_H
