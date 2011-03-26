#ifndef IG_PROF_IG_PROF_TRACE_H
# define IG_PROF_IG_PROF_TRACE_H

# include "macros.h"
# include "buffer.h"
# include "profile.h"
# include <pthread.h>
# include <limits.h>
# include <stdint.h>

/** A resizeable profiler trace buffer.

    Each trace buffer tracks stack traces and their linked profiling
    counter values.  The buffer also counts resources linked with the
    counters: tracking which call stack acquired which yet-unreleased
    resource and the size of the resource.

    The buffer owner is responsible for arranging correct handling of
    the buffer in presence of multiple threads.  Buffers that do not
    track resources can be made thread-local and access need not be
    guarded.  Resource-accounting buffers must be shared among all the
    threads able to acquire or release the resource -- the resource
    records are entered into the buffer in the order of the profile
    events, but there is no other concept of time and therefore it
    would not be possible to merge buffers from multiple threads into
    a canonical time order later on.  In the rare situation the
    resources are thread-local the buffer can be thread-local too,
    otherwise the caller must ensure atomic access to the buffer.

    Technically a trace buffer consists of a header and a collection
    of fixed-size memory pools for the data, and possibly some pools
    for hash tables.  The stack trace and resource counter information
    is stored starting in one of the arrays.  If the buffer tracks
    resource information, a resource hash points to resource records.
    The trace buffer grows by allocating more memory pool as needed.

    The stack trace is represented as a tree of nodes keyed by call
    address.  Each stack frame has a singly linked list of children,
    the addresses called from that stack frame.  A frame also has a
    singly linked list of profiling counters associated with the call
    tree.  Each counter may point to a list of resources known to be
    live within that buffer; the resources linked with the counter
    form a singly linked list.  The root of the stack trace is a null
    frame: one with zero call address.

    The resource hash table provides quick access to the most recent
    record on each profiled resource.  Each hash bin points to a
    resource; the resources in the same bin form a singly linked list,
    a list separate from the singly linked list for resources by
    counter.  A live resource points back to the counter owning that
    resource, permitting that counter to be decremented when the
    resource is released.

    The memory is allocated and the pool otherwise managed by using
    raw operating system pritimives: anonymous memory mappings.  The
    buffer avoids calling any non-trivial library calls.  The buffer
    implementation is safe for use in asynchronous signals provided
    the caller avoids re-enter the same buffer from nested
    signals.  */
class IgProfTrace : protected IgProfBuffer
{
public:
  struct PerfStat;
  struct StackCache;
  struct Stack;
  struct CounterDef;
  struct Counter;
  struct Resource;
  struct Record;

  /// Deepest supported stack depth.
  static const int MAX_DEPTH = 800;

  /// A value that might be an address, usually memory resource.
  typedef uintptr_t Address;

  /// A large-sized accumulated value for counters.
  typedef uintmax_t Value;

  /// Performance statistics for tracing.
  struct PerfStat
  {
    uint64_t    ntraces;        //< Number of traces.
    uint64_t    sumDepth;       //< sum(trace_depth).
    uint64_t    sum2Depth;      //< sum(trace_depth^2).
    uint64_t    sumTicks;       //< sum(ticks_for_trace).
    uint64_t    sum2Ticks;      //< sum(ticks_for_trace^2).
    uint64_t    sumTPerD;       //< sum((ticks << 4) / depth).
    uint64_t    sum2TPerD;      //< sum(((ticks << 4) / depth)^2).

    PerfStat &operator+=(const PerfStat &other);
  };

  /// Structure for call stack cache at the end.
  struct StackCache
  {
    void        *address;       //< Instruction pointer value.
    Stack       *frame;         //< Address of corresponding stack node.
  };

  /// Stack trace node.
  struct Stack
  {
    void        *address;       //< Instruction pointer value.
#if IGPROF_DEBUG
    Stack       *parent;        //< The calling stack frame, or null for the root.
#endif
    Stack       *sibling;       //< The next child frame of the same parent.
    Stack       *children;      //< The first child of this call frame.
    Counter     *counters;      //< The first counter for this call frame, or null.
  };

  /// Counter type.
  enum CounterType
  {
    TICK,                       //< Ticked cumulative counter.
    TICK_PEAK,                  //< Ticked and keep also the peak value.
    MAX                         //< Maximum-value counter.
  };

  /// Counter definition.
  struct CounterDef
  {
    const char  *name;          //< The name of the counter, for output.
    CounterType type;           //< The behaviour type of the counter.
    int         id;             //< Reference ID for output.
  };

  /// Counter value.
  struct Counter
  {
    Value       ticks;          //< The number of times the counter was increased.
    Value       value;          //< The accumulated counter value.
    Value       peak;           //< The maximum value of the counter at any time.
    CounterDef  *def;           //< The definition of this counter.
    Stack       *frame;         //< The stack node owning the counter.
    Counter     *next;          //< The next counter in the stack frame's chain.
    Resource    *resources;     //< The live resources linked to this counter.
  };

  /* Each resource is in two singly linked lists: the hash bin chain
     and the live resources ("leaks") attached to a counter.  Updating
     a resource always updates both linked lists.

     When a resource is acquired, the resource hash table is searched
     for a previously existing record.  If none exists, the resource
     is entered into the first free resource position, either taking
     one from the free list or allocating a new one.  Otherwise the
     existing resource is freed as described below and the search is
     repeated; it is assumed the profiler missed the release of the
     resource.  The counter values are then updated.

     When a resource is released and known in the trace buffer, the
     record is removed from both the counter and resource hash chain
     lists, and put on the free list (the "nextlive" chains the free
     list).  If the resource is not known in the trace buffer it is
     ignored, on the assumption the profiler missed the resource
     acquisition, for example because it wasn't active at the time.  */

  /// Data for a resource.
  struct Resource
  {
    Address     resource;       //< Resource identity.
    Value       size;           //< Size of the resource.
    Resource    *nexthash;      //< Next resource in same hash bin.
    Resource    *prevlive;      //< Previous live resource in the same counter.
    Resource    *nextlive;      //< Next live resource in the same counter.
    Counter     *counter;       //< Counter tracking this resource.
    CounterDef  *def;           //< Cached counter definition reference.
  };

  /// Bitmask of properties the record covers.
  typedef unsigned int RecordType;
  static const RecordType COUNT         = 1;
  static const RecordType ACQUIRE       = 2;
  static const RecordType RELEASE       = 4;

  /// Structure used by callers to record values.
  struct Record
  {
    RecordType  type;           //< Type of the record.
    CounterDef  *def;           //< Counter to modify.
    Value       amount;         //< The total amount to add.
    Value       ticks;          //< The number of increments.
    Address     resource;       //< Resource identity for #ACQUIRE and #RELEASE.
  };

  IgProfTrace(void);
  ~IgProfTrace(void);

  void                  push(void **stack, int depth, Record *recs, int nrecs, const PerfStat &s);
  void                  mergeFrom(IgProfTrace &other);
  Stack *               stackRoot(void) const;
  const PerfStat &      perfStats(void) const;
  static PerfStat       statFrom(int depth, uint64_t tstart, uint64_t tend);

  void                  lock(void);
  void                  unlock(void);

private:
  Stack *               childStackNode(Stack *parent, void *address);
  Counter *             initCounter(Counter *&link, CounterDef *def, Stack *frame);
  bool                  findResource(Record &rec,
                                     Resource **&rlink,
                                     Resource *&res,
                                     CounterDef *def);
  void                  releaseResource(Resource **rlink, Resource *res);
  void                  releaseResource(Record &rec);
  void                  acquireResource(Record &rec, Counter *ctr);
  void                  dopush(void **stack, int depth, Record *recs, int nrecs);
  void                  mergeFrom(int depth, Stack *frame, void **callstack, Record *recs);

  void                  debugDump(void);
  static void           debugDumpStack(Stack *s, int depth);

  pthread_mutex_t       mutex_;         //< Concurrency protection.
  void                  **poolfirst_;   //< Pointer to first memory pool.
  void                  **poolcur_;     //< Pointer to current memory pool.
  Resource              **restable_;    //< Start of the resources hash.
  StackCache            *callcache_;    //< Start of address cache.
  Resource              *resfree_;      //< Resource free list.
  Stack                 *stack_;        //< Stack root.
  PerfStat		perfStats_;	//< Performance stats.

  // Unavailable copy constructor, assignment operator
  IgProfTrace(IgProfTrace &);
  IgProfTrace &operator=(IgProfTrace &);
};

inline IgProfTrace::Stack *
IgProfTrace::stackRoot (void) const
{ return stack_; }

inline IgProfTrace::PerfStat &
IgProfTrace::PerfStat::operator+=(const PerfStat &other)
{
  ntraces   += other.ntraces;
  sumDepth  += other.sumDepth;
  sum2Depth += other.sum2Depth;
  sumTicks  += other.sumTicks;
  sum2Ticks += other.sum2Ticks;
  sumTPerD  += other.sumTPerD;
  sum2TPerD += other.sum2TPerD;
  return *this;
}

inline IgProfTrace::PerfStat
IgProfTrace::statFrom(int depth, uint64_t tstart, uint64_t tend)
{
  PerfStat result;
  uint64_t dep       = depth;
  uint64_t nticks    = tend - tstart;
  uint64_t tperd     = (nticks << 4) / dep;
  result.ntraces   = 1;
  result.sumDepth  = dep;
  result.sum2Depth = dep * dep;
  result.sumTicks  = nticks;
  result.sum2Ticks = nticks * nticks;
  result.sumTPerD  = tperd;
  result.sum2TPerD = tperd * tperd;
  return result;
}

inline const IgProfTrace::PerfStat &
IgProfTrace::perfStats(void) const
{ return perfStats_; }

#endif // IG_PROF_IG_PROF_TRACE_H
