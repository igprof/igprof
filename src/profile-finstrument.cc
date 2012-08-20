#include "profile.h"
#include <cstdio>
#include <cstring>
#include "profile-trace.h"
#include "walk-syms.h"

static void do_enter();
static IgHook::TypedData<void()> do_enter_hook = { { 0, "__cyg_profile_func_enter",
       0, 0, &do_enter, 0, 0, 0 } };

static void do_exit();
static IgHook::TypedData<void()> do_exit_hook = { { 0, "__cyg_profile_func_exit",
       0, 0, &do_exit, 0, 0, 0 } };

static bool s_initialized = false;
static IgProfTrace::CounterDef  s_ct_time      = { "CALL_TIME",    IgProfTrace::TICK, -1 };
static IgProfTrace::CounterDef  s_ct_calls     = { "CALL_COUNT",   IgProfTrace::TICK, -1 };
//Maximum amount of threads
const int MAX_THREADS = 10;
//enter time stack for functions in each treads
uint64_t times[MAX_THREADS][IgProfTrace::MAX_DEPTH];
//enter counter
int callCount[MAX_THREADS];
//times spent in child functions
uint64_t child[MAX_THREADS][IgProfTrace::MAX_DEPTH];
//mutex lock for getIdNumber function
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
//Threads array, threadIDs are stored here. Index is the idNumber of the thread
int threads[MAX_THREADS];
//Returns thread idNumber. If the thread is not saved yet. Adds threadID into threads array
//and position in array becomes idNumber
static int
getIdNumber(int threadID)
{
  int idNumber = 0;
  pthread_mutex_lock(&lock);
  while (idNumber < MAX_THREADS)
  {
    if (threads[idNumber] == 0)
      threads[idNumber] = threadID;
    if (threadID == threads[idNumber])
    {
      pthread_mutex_unlock(&lock);
      return idNumber;
    }
    ++idNumber;
  }
  pthread_mutex_unlock(&lock);
  return -1;
}

static void
initialize(void)
{
  if (s_initialized) return;
  s_initialized = true;
  
  const char* options = igprof_options();
  bool enable = false;

  
  while (options && *options)
  {
    while (*options == ' ' || *options == ',')
      ++options;
    if (! strncmp(options, "finst", 5))
    {
      options = options + 5;
      enable = true; 
    }
    else
      options++;

    while (*options && *options != ',' && *options != ' ')
      options++;
  }
  if (! enable)
    return;

  if (! igprof_init("finstrument-profiler", 0, false))
    return;

  IgHook::hook(do_enter_hook.raw);
  IgHook::hook(do_exit_hook.raw);

  igprof_disable_globally();
  igprof_debug("gcc finstrument-profiler\n");
  igprof_debug("finstrument-profiler enabled\n");
  igprof_enable_globally();
}

// dummy functions which will be hooked
extern "C" void __cyg_profile_func_enter(void *func UNUSED, void *caller UNUSED)
{
}
extern "C" void __cyg_profile_func_exit(void *func UNUSED, void *caller UNUSED)
{
}
// save TSC value at before entering the real function
static void 
do_enter ()
{
  int threadID = pthread_self();
  int idNumber = getIdNumber(threadID);
  if (idNumber == -1)
  {
    igprof_debug("An error occured in getIdNumber()");
    return;
  }
  uint64_t tstart;
  ++callCount[idNumber];
  child[idNumber][callCount[idNumber]-1] = 0;
  RDTSC(tstart);
  times[idNumber][callCount[idNumber]-1] = -tstart; 
}

//stop timer and tick counter
static void 
do_exit ()
{
    uint64_t tstop,texit;
    RDTSC(tstop);
    int threadID = pthread_self();
    int idNumber = getIdNumber(threadID);
    if (idNumber == -1)
    {
      igprof_debug("An error occured in getIdNumber()");
      return;
    }
    --callCount[idNumber];
    //diff = time spent in the function subtracted by time spent on childs
    uint64_t diff = times[idNumber][callCount[idNumber]] - child[idNumber][callCount[idNumber]] + tstop;
    void *addresses[IgProfTrace::MAX_DEPTH];
    IgProfTrace *buf = igprof_buffer();
    IgProfTrace::Stack *frame;
    int depth;

    if (UNLIKELY(! buf))
      return;

    depth = IgHookTrace::stacktrace(addresses, IgProfTrace::MAX_DEPTH);

    buf->lock(); 
    frame = buf->push(addresses+1, depth-1);
    buf->tick(frame, &s_ct_time, diff, 1);
    buf->tick(frame, &s_ct_calls, 1, 1);
    buf->unlock();
    //if function is child, add time spent on child array for parent
    if (callCount > 0)
    {
      RDTSC(texit);
      child[idNumber][callCount[idNumber]-1] += child[idNumber][callCount[idNumber]] + diff + (texit - tstop);
    }
}

static bool autoboot = (initialize(), true);
