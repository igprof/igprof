#include "IgProf.h"
#include "IgProfTrace.h"
#include "IgHook.h"
#include "IgHookTrace.h"
#include <cstdlib>
#include <cstring>
#include <signal.h>
#include <sys/time.h>

#ifdef __APPLE__
typedef sig_t sighandler_t;
#endif

// -------------------------------------------------------------------
// Traps for this profiler module
IGPROF_LIBHOOK(3, int, dopthread_sigmask, _main,
	       (int how, sigset_t *newmask, sigset_t *oldmask),
	       (how, newmask, oldmask),
	       "pthread_sigmask", 0, 0)
IGPROF_LIBHOOK(3, int, dosigaction, _main,
	       (int signum, const struct sigaction *act, struct sigaction *oact),
	       (signum, act, oact),
	       "sigaction", 0, 0)

// Data for this profiler module
static IgProfTrace::CounterDef	s_ct_ticks	= { "PERF_TICKS", IgProfTrace::TICK, -1 };
static bool			s_initialized	= false;
static int			s_signal	= SIGPROF;
static int			s_itimer	= ITIMER_PROF;
static int			s_moduleid	= -1;

/** Performance profiler signal handler, SIGPROF or SIGALRM depending
    on the current profiler mode.  Record a tick for the current
    program location.  Assumes the signal handler is registered for
    the correct thread.  Skip ticks when this profiler is not
    enabled.  */
static void
profileSignalHandler(int /* nsig */, siginfo_t * /* info */, void * /* ctx */)
{
  void *addresses [IgProfTrace::MAX_DEPTH];
  bool enabled = IgProf::disable(false);
  if (enabled)
  {
    if (IgProfTrace *buf = IgProf::buffer(s_moduleid))
    {
      int depth = IgHookTrace::stacktrace(addresses, IgProfTrace::MAX_DEPTH);
      IgProfTrace::Record entry = { IgProfTrace::COUNT, &s_ct_ticks, 1, 1, 0 };

      // Drop two bottom frames, three top ones (stacktrace, me, signal frame).
      buf->push(addresses+3, depth-3, &entry, 1);
    }
  }
  IgProf::enable(false);
}

/** Enable profiling timer.  You should have called
    #enableSignalHandler() before calling this function.
    This needs to be executed in every thread to be profiled. */
static void
enableTimer(void)
{
  itimerval interval = { { 0, 5000 }, { 0, 5000 } };
  setitimer(s_itimer, &interval, 0);
}

/** Enable profiling signal handler.  */
static void
enableSignalHandler(void)
{
  sigset_t profset;
  sigemptyset(&profset);
  sigaddset(&profset, s_signal);
  if (IgProf::isMultiThreaded())
    pthread_sigmask(SIG_UNBLOCK, &profset, 0);
  else
    sigprocmask(SIG_UNBLOCK, &profset, 0);

  struct sigaction sa;
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = (sighandler_t) &profileSignalHandler;
  sa.sa_flags = SA_RESTART | SA_SIGINFO;
  sigaction(s_signal, &sa, 0);
}

/** Thread setup function.  */
static void
threadInit(void)
{
  // Enable profiling in this thread.
  enableSignalHandler();
  enableTimer();
}

// -------------------------------------------------------------------
/** Possibly start performance profiler.  */
static void
initialize(void)
{
  if (s_initialized) return;
  s_initialized = true;

  const char	*options = IgProf::options();
  bool		enable = false;

  while (options && *options)
  {
    while (*options == ' ' || *options == ',')
      ++options;

    if (! strncmp(options, "perf", 4))
    {
      enable = true;
      options += 4;
      while (*options)
      {
	if (! strncmp(options, ":real", 5))
	{
	  s_signal = SIGALRM;
	  s_itimer = ITIMER_REAL;
	  options += 5;
	}
	else if (! strncmp(options, ":user", 5))
	{
	  s_signal = SIGVTALRM;
	  s_itimer = ITIMER_VIRTUAL;
	  options += 5;
	}
	else if (! strncmp(options, ":process", 7))
	{
	  s_signal = SIGPROF;
	  s_itimer = ITIMER_PROF;
	  options += 7;
	}
	else
	  break;
      }
    }
    else
      options++;

    while (*options && *options != ',' && *options != ' ')
      options++;
  }

  if (! enable)
    return;

  if (! IgProf::initialize(&s_moduleid, &threadInit, true))
    return;

  IgProf::disable(true);
  if (s_itimer == ITIMER_REAL)
    IgProf::debug("Perf: measuring real time\n");
  else if (s_itimer == ITIMER_VIRTUAL)
    IgProf::debug("Perf: profiling user time\n");
  else if (s_itimer == ITIMER_PROF)
    IgProf::debug("Perf: profiling process time\n");

  // Enable profiler.
  IgHook::hook(dopthread_sigmask_hook_main.raw);
  IgHook::hook(dosigaction_hook_main.raw);
  IgProf::debug("Performance profiler enabled\n");

  enableSignalHandler();
  enableTimer();
  IgProf::enable(true);
}

// -------------------------------------------------------------------
// Trap fiddling with thread signal masks
static int
dopthread_sigmask(IgHook::SafeData<igprof_dopthread_sigmask_t> &hook,
		  int how, sigset_t *newmask,  sigset_t *oldmask)
{
  struct sigaction cursig;
  struct itimerval curtimer;
  if (newmask
      && (how == SIG_BLOCK || how == SIG_SETMASK)
      && sigismember(newmask, s_signal)
      && sigaction(s_signal, 0, &cursig) == 0
      && cursig.sa_handler
      && getitimer(s_itimer, &curtimer) == 0
      && (curtimer.it_interval.tv_sec || curtimer.it_interval.tv_usec))
  {
    IgProf::debug("pthread_sigmask(): prevented profiling signal"
		  " %d from being blocked in thread 0x%lx"
		  " [handler 0x%lx, interval %.0f us]\n",
		  s_signal, (unsigned long) pthread_self(),
		  (unsigned long) cursig.sa_handler,
		  1e6 * curtimer.it_interval.tv_sec
		   + curtimer.it_interval.tv_usec);
    sigdelset(newmask, s_signal);
  }

  return hook.chain(how, newmask, oldmask);
}

// Trap fiddling with the profiling signal.
static int
dosigaction(IgHook::SafeData<igprof_dosigaction_t> &hook,
	    int signum, const struct sigaction *act, struct sigaction *oact)
{
  struct sigaction sa;
  if (signum == s_signal
      && act
      && act->sa_handler != (sighandler_t) &profileSignalHandler)
  {
    IgProf::debug("sigaction(): prevented profiling signal"
		  " %d from being overridden in thread 0x%lx\n",
		  s_signal, (unsigned long) pthread_self());
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = (sighandler_t) &profileSignalHandler;
    sa.sa_flags = SA_RESTART | SA_SIGINFO;
    act = &sa;
  }

  return hook.chain(signum, act, oact);
}

// -------------------------------------------------------------------
static bool autoboot = (initialize(), true);
