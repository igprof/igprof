#ifndef IG_PROF_IG_PROF_H
# define IG_PROF_IG_PROF_H

# include "IgProfMacros.h"
# include "IgHook.h"

class IgProfTrace;

/** Core profiling implementation.  Implements utilities needed
    to implement actual profiler modules as well as final dumps. */
class IgProf
{
public:
  static int		panic(const char *file, int line,
			      const char *func, const char *expr);
  static void		debug(const char *format, ...);
  static const char *	options(void);

  static bool		initialize(int *moduleid,
				   void (*threadinit)(void),
				   bool perthread);

  static void		initThread(void);
  static void		exitThread(bool final);
  static bool		isMultiThreaded(void);

  static bool		enabled(bool globally);
  static bool		enable(bool globally);
  static bool		disable(bool globally);
  static IgProfTrace *	buffer(int moduleid);
  static void *		tracecache(void);
};

#endif // IG_PROF_IG_PROF_H
