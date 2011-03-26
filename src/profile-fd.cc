#include "profile.h"
#include "profile-trace.h"
#include "hook.h"
#include "walk-syms.h"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cerrno>
#include <sys/socket.h>
#include <pthread.h>

// -------------------------------------------------------------------
// Traps for this profiling module
DUAL_HOOK(3, int, doopen, _main, _libc,
          (const char *fn, int flags, int mode), (fn, flags, mode),
          "open", 0, "libc.so.6")
DUAL_HOOK(3, int, doopen64, _main, _libc,
          (const char *fn, int flags, int mode), (fn, flags, mode),
          "__open64", 0, "libc.so.6")
DUAL_HOOK(1, int, doclose, _main, _libc,
          (int fd), (fd),
          "close", 0, "libc.so.6")
DUAL_HOOK(1, int, dodup, _main, _libc,
          (int fd), (fd),
          "dup", 0, "libc.so.6")
DUAL_HOOK(2, int, dodup2, _main, _libc,
          (int fd, int newfd), (fd, newfd),
          "dup2", 0, "libc.so.6")
DUAL_HOOK(3, int, dosocket, _main, _libc,
          (int domain, int type, int proto), (domain, type, proto),
          "socket", 0, "libc.so.6")
DUAL_HOOK(3, int, doaccept, _main, _libc,
          (int fd, sockaddr *addr, socklen_t *len), (fd, addr, len),
          "accept", 0, "libc.so.6")

// Data for this profiling module
static IgProfTrace::CounterDef  s_ct_used       = { "FD_USED", IgProfTrace::TICK, -1 };
static IgProfTrace::CounterDef  s_ct_live       = { "FD_LIVE", IgProfTrace::TICK, -1 };
static bool                     s_initialized   = false;

/** Record file descriptor.  Increments counters in the tree. */
static void __attribute__((noinline))
add (int fd)
{
  uint64_t tstart, tend;
  IgProfTrace *buf = igprof_buffer();
  if (! buf)
    return;

  RDTSC(tstart);

  void                  *addresses[IgProfTrace::MAX_DEPTH];
  int                   depth = IgHookTrace::stacktrace(addresses, IgProfTrace::MAX_DEPTH);
  IgProfTrace::Record   entries [2];

  RDTSC(tend);

  entries[0].type = IgProfTrace::COUNT;
  entries[0].def = &s_ct_used;
  entries[0].amount = 1;
  entries[0].ticks = 1;

  entries[1].type = IgProfTrace::COUNT | IgProfTrace::ACQUIRE;
  entries[1].def = &s_ct_live;
  entries[1].amount = 1;
  entries[1].ticks = 1;
  entries[1].resource = fd;

  // Drop two bottom frames, four top ones (stacktrace, me, two for hook).
  buf->push(addresses+4, depth-4, entries, 2,
	    IgProfTrace::statFrom(depth, tstart, tend));
}

/** Remove knowledge about the file descriptor.  If we are tracking
    leaks, removes the descriptor from the live map and subtracts
    from the live descriptor counters.  */
static void
remove (int fd)
{
  IgProfTrace *buf = igprof_buffer();
  if (! buf)
    return;

  IgProfTrace::PerfStat perf = { 0, 0, 0, 0, 0, 0, 0 };
  IgProfTrace::Record entry
    = { IgProfTrace::RELEASE, &s_ct_live, 0, 0, fd };
  buf->push(0, 0, &entry, 1, perf);
}

// -------------------------------------------------------------------
/** Initialise file descriptor profiling.  Traps various system
    calls to keep track of usage, and if requested, leaks.  */
static void
initialize(void)
{
  if (s_initialized) return;
  s_initialized = true;

  const char    *options = igprof_options();
  bool          enable = false;

  while (options && *options)
  {
    while (*options == ' ' || *options == ',')
      ++options;

    if (! strncmp(options, "fd", 2))
    {
      enable = true;
      options += 2;
    }
    else
      options++;

    while (*options && *options != ',' && *options != ' ')
      options++;
  }

  if (! enable)
    return;

  if (! igprof_init("file descriptor profiler", 0, false))
    return;

  igprof_disable(true);
  IgHook::hook(doopen_hook_main.raw);
  IgHook::hook(doopen64_hook_main.raw);
  IgHook::hook(doclose_hook_main.raw);
  IgHook::hook(dodup_hook_main.raw);
  IgHook::hook(dodup2_hook_main.raw);
  IgHook::hook(dosocket_hook_main.raw);
  IgHook::hook(doaccept_hook_main.raw);
#if __linux
  if (doopen_hook_main.raw.chain)   IgHook::hook(doopen_hook_libc.raw);
  if (doopen64_hook_main.raw.chain) IgHook::hook(doopen64_hook_libc.raw);
  if (doclose_hook_main.raw.chain)  IgHook::hook(doclose_hook_libc.raw);
  if (dodup_hook_main.raw.chain)    IgHook::hook(dodup_hook_libc.raw);
  if (dodup2_hook_main.raw.chain)   IgHook::hook(dodup2_hook_libc.raw);
  if (dosocket_hook_main.raw.chain) IgHook::hook(dosocket_hook_libc.raw);
  if (doaccept_hook_main.raw.chain) IgHook::hook(doaccept_hook_libc.raw);
#endif
  igprof_debug("File descriptor profiler enabled\n");
  igprof_enable(true);
}

// -------------------------------------------------------------------
// Trapped system calls.  Track live file descriptor usage.
static int
doopen(IgHook::SafeData<igprof_doopen_t> &hook, const char *fn, int flags, int mode)
{
  bool enabled = igprof_disable(false);
  int result = (*hook.chain)(fn, flags, mode);
  int err = errno;

  if (enabled && result != -1)
    add(result);

  errno = err;
  igprof_enable(false);
  return result;
}

static int
doopen64(IgHook::SafeData<igprof_doopen64_t> &hook, const char *fn, int flags, int mode)
{
  bool enabled = igprof_disable(false);
  int result = (*hook.chain)(fn, flags, mode);
  int err = errno;

  if (enabled && result != -1)
    add(result);

  errno = err;
  igprof_enable(false);
  return result;
}

static int
doclose(IgHook::SafeData<igprof_doclose_t> &hook, int fd)
{
  igprof_disable(false);
  int result = (*hook.chain)(fd);
  int err = errno;

  if (result != -1)
    remove(fd);

  errno = err;
  igprof_enable(false);
  return result;
}


static int
dodup(IgHook::SafeData<igprof_dodup_t> &hook, int fd)
{
  bool enabled = igprof_disable(false);
  int result = (*hook.chain)(fd);
  int err = errno;

  if (enabled && result != -1)
    add(result);

  errno = err;
  igprof_enable(false);
  return result;
}

static int
dodup2(IgHook::SafeData<igprof_dodup2_t> &hook, int fd, int newfd)
{
  bool enabled = igprof_disable(false);
  int result = (*hook.chain)(fd, newfd);
  int err = errno;

  if (result != -1)
  {
    remove(fd);
    if (enabled)
      add(newfd);
  }

  errno = err;
  igprof_enable(false);
  return result;
}

static int
dosocket(IgHook::SafeData<igprof_dosocket_t> &hook, int domain, int type, int proto)
{
  bool enabled = igprof_disable(false);
  int result = (*hook.chain)(domain, type, proto);
  int err = errno;

  if (enabled && result != -1)
    add(result);

  errno = err;
  igprof_enable(false);
  return result;
}

static int
doaccept(IgHook::SafeData<igprof_doaccept_t> &hook,
         int fd, struct sockaddr *addr, socklen_t *len)
{
  bool enabled = igprof_disable(false);
  int result = (*hook.chain)(fd, addr, len);
  int err = errno;

  if (enabled && result != -1)
    add(result);

  errno = err;
  igprof_enable(false);
  return result;
}

// -------------------------------------------------------------------
static bool autoboot = (initialize(), true);
