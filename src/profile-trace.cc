#include "profile-trace.h"
#include "walk-syms.h"
#include <memory.h>
#include <stdio.h>
#include <inttypes.h>

static IgProfTrace::Counter FREED;
static const unsigned int RESOURCE_HASH = 1024*1024;

/** Initialise a trace buffer.  */
IgProfTrace::IgProfTrace(void)
  : restable_(0),
    callcache_(0),
    resfree_(0),
    stack_(0)
{
  pthread_mutex_init(&mutex_, 0);

  // Allocate a separate slab of memory the resource hash table.  This
  // has to be big for large memory applications, so it's ok to
  // allocate it separately.  Note the memory obtained here starts out
  // as zeroed out.
  restable_ = (Resource **) allocateRaw(RESOURCE_HASH*sizeof(Resource *));

  // Allocate the call cache next.
  callcache_ = (StackCache *) allocateSpace(MAX_DEPTH*sizeof(StackCache));

  // Allocate the stack root node.
  stack_ = allocate<Stack>();

  // The resource free list starts out empty.
  ASSERT(! resfree_);

  // Initialise performance stats.
  perfStats_.ntraces   = 0;
  perfStats_.sumDepth  = 0;
  perfStats_.sum2Depth = 0;
  perfStats_.sumTicks  = 0;
  perfStats_.sum2Ticks = 0;
  perfStats_.sumTPerD  = 0;
  perfStats_.sum2TPerD = 0;
}

IgProfTrace::~IgProfTrace(void)
{
  if (restable_)
    unallocateRaw(restable_, RESOURCE_HASH*sizeof(Resource *));
}

IgProfTrace::Stack *
IgProfTrace::childStackNode(Stack *parent, void *address)
{
  // Search for the child's call address in the child stack frames.
  Stack **kid = &parent->children;
  while (*kid)
  {
    Stack *k = *kid;
    if (k->address == address)
      return k;

    if ((char *) k->address > (char *) address)
      break;

    kid = &k->sibling;
  }

  // Didn't find it, add a new child in address-sorted order.
  Stack *next = *kid;
  Stack *k = *kid = allocate<Stack>();
  k->address = address;
#if DEBUG
  k->parent = parent;
#endif
  k->sibling = next;
  k->children = 0;
  k->counters = 0;

  return k;
}

inline IgProfTrace::Counter *
IgProfTrace::initCounter(Counter *&link, CounterDef *def, Stack *frame)
{
  Counter *ctr = allocate<Counter>();
  ctr->ticks = 0;
  ctr->value = 0;
  ctr->peak = 0;
  ctr->def = def;
  ctr->frame = frame;
  ctr->next = 0;
  ctr->resources = 0;
  link = ctr;
  return ctr;
}

inline bool
IgProfTrace::findResource(Address resource,
                          Resource **&rlink,
                          Resource *&res,
                          CounterDef *def)
{
  // Locate the resource in the hash table.
  rlink = &restable_[hash(address) & (RESOURCE_HASH-1)];

  while (Resource *r = *rlink)
  {
    if (r->resource == resource && r->def == def)
    {
      res = r;
      return true;
    }
    if (r->resource > resource)
      return false;
    rlink = &r->nexthash;
  }

  return false;
}

inline void
IgProfTrace::releaseResource(Resource **rlink, Resource *res)
{
  ASSERT(res);
  ASSERT(rlink);
  ASSERT(res->counter);
  ASSERT(res->counter != &FREED);
  ASSERT(res->counter->resources);
  ASSERT(*rlink == res);

  // Deduct the resource from the counter.
  Counter *ctr = res->counter;
  ASSERT(ctr->value >= res->size);
  ASSERT(ctr->ticks > 0);
  ctr->value -= res->size;
  ctr->ticks--;

  // Unchain from hash and counter lists.
  *rlink = res->nexthash;

  if (Resource *prev = res->prevlive)
  {
    ASSERT(prev->nextlive == res);
    prev->nextlive = res->nextlive;
  }
  else
  {
    ASSERT(ctr->resources == res);
    ctr->resources = res->nextlive;
  }

  if (Resource *next = res->nextlive)
  {
    ASSERT(next->prevlive == res);
    next->prevlive = res->prevlive;
  }

  // Put it on free list.
  memset (res, 0, sizeof (*res));
  res->nextlive = resfree_;
  res->counter = &FREED;
  resfree_ = res;
}

/** Locate stack frame record for a call tree. */
IgProfTrace::Stack *
IgProfTrace::push(void **stack, int depth)
{
  // Make sure we operate on non-negative depth.  This allows callers
  // to do strip off call tree layers without checking for sufficient
  // depth themselves.
  if (depth < 0)
    depth = 0;

  // Look up call stack in the cache.
  StackCache    *cache = callcache_;
  Stack         *frame = stack_;

  for (int i = 0, valid = 1; i < depth && i < MAX_DEPTH; ++i)
  {
    void *address = stack[depth-i-1];
    if (valid && cache[i].address == address)
      frame = cache[i].frame;
    else
    {
      // Look up this call stack child, then cache result.
      frame = childStackNode(frame, address);
      cache [i].address = address;
      cache [i].frame = frame;
      valid = 0;
    }
  }

  return frame;
}

IgProfTrace::Counter *
IgProfTrace::tick(Stack *frame, CounterDef *def, Value amount, Value ticks)
{
  ASSERT(frame);
  ASSERT(def);

  // Locate and possibly initialise the counter.
  Counter **ctr = 0;
  Counter *c = 0;
  ctr = &frame->counters;
  while (*ctr && (*ctr)->def != def)
    ctr = &(*ctr)->next;

  // If not found, add it.
  c = *ctr;
  if (! c || c->def != def)
    c = initCounter(*ctr, def, frame);

  // Tick the counter.
  if (def->type == TICK)
  {
    c->value += amount;
    if (c->value > c->peak)
      c->peak = c->value;
  }
  else if (def->type == MAX && c->value < amount)
    c->value = amount;

  c->ticks += ticks;

  // Return the counter for acquire() calls.
  return c;
}

void
IgProfTrace::acquire(Counter *ctr, Address resource, Value size)
{
  ASSERT(ctr);

  // Locate the resource in the hash table.
  Resource  **rlink;
  Resource  *res = 0;
  if (findResource(resource, rlink, res, ctr->def))
  {
    igprof_debug("New %s resource 0x%lx of %ju bytes was never freed in %p\n",
                 ctr->def->name, resource, res->size, (void *)this);
#if DEBUG
    int depth = 0;
    for (Stack *s = ctr->frame; s; s = s->parent)
    {
      const char  *sym = 0;
      const char  *lib = 0;
      long        offset = 0;
      long        liboffset = 0;

      IgHookTrace::symbol(s->address, sym, lib, offset, liboffset);
      igprof_debug("  [%u] %10p %s + %d [%s + %d]\n", ++depth, s->address,
                   sym ? sym : "?", offset, lib ? lib : "?", liboffset);
    }
#endif

    // Release the resource, then proceed as if we hadn't found it.
    releaseResource(rlink, res);
  }

  // It wasn't found, insert into the lists as per class documentation.
  if ((res = resfree_))
    resfree_ = res->nextlive;
  else
    res = allocate<Resource>();
  res->resource = resource;
  res->size = amount;
  res->nexthash = *rlink;
  res->prevlive = 0;
  res->nextlive = ctr->resources;
  res->counter = ctr;
  res->def = ctr->def;
  ctr->resources = *rlink = res;
  if (res->nextlive)
    res->nextlive->prevlive = res;
}

// Handle resource release.  There is no call stack involved here.
void
IgProfTrace::release(Address resource, CounterDef *def)
{
  // Locate the resource in the hash table.
  Resource  **rlink;
  Resource  *res = 0;
  if (! findResource(resource, rlink, res, def))
    // Not found, we missed the allocation, ignore this release.
    return;
  else
    // Found, actually release it.
    releaseResource(rlink, res);
}

void
IgProfTrace::mergeFrom(IgProfTrace &other)
{
  pthread_mutex_lock(&mutex_);
  pthread_mutex_lock(&other.mutex_);

  // Scan stack tree and insert each call stack, including resources.
  void *callstack[MAX_DEPTH+1];
  callstack[MAX_DEPTH] = stack_->address; // null really
  mergeFrom(0, other.stack_, &callstack[MAX_DEPTH]);
  perfStats_ += other.perfStats_;

  pthread_mutex_unlock(&other.mutex_);
  pthread_mutex_unlock(&mutex_);
}

void
IgProfTrace::mergeFrom(int depth, Stack *frame, void **callstack)
{
  // Process counters at this call stack level.
  Stack *myframe = push(callstack, depth);
  for (Counter *c = frame->counters; c; c = c->next)
  {
    if (c->ticks && ! c->resources)
      tick(myframe, c->def, c->value, c->ticks);
    else if (c->ticks)
      for (Resource *r = c->resources; r; r = r->nextlive)
      {
        Counter *ctr = tick(myframe, c->def, r->size, 1);
	acquire(ctr, r->resource, r->size);
      }

    // Adjust the peak counter if necessary.
    if (c->def->type == TICK && c->peak > c->value)
      tick(myframe, c->def, c->peak - c->value, 0);
  }

  // Merge the children.
  for (frame = frame->children; frame; frame = frame->sibling)
  {
    ASSERT(depth < MAX_DEPTH);
    callstack[-1] = frame->address;
    mergeFrom(depth+1, frame, &callstack[-1]);
  }
}

#define INDENT(d) for (int i = 0; i < d; ++i) fputc (' ', stderr)

void
IgProfTrace::debugDumpStack(Stack *s, int depth)
{
  INDENT(2*depth);
  fprintf(stderr, "STACK %d frame=%p addr=%p next=%p kids=%p\n",
          depth, (void *)s, (void *)s->address,
          (void *)s->sibling, (void *)s->children);

  for (Counter *c = s->counters; c; c = c->next)
  {
    INDENT(2*depth+1);
    __extension__
    fprintf(stderr, "COUNTER ctr=%p %s %ju %ju %ju\n",
            (void *)c, c->def->name, c->ticks, c->value, c->peak);

    for (Resource *r = c->resources; r; r = r->nextlive)
    {
      INDENT(2*depth+2);
      __extension__
      fprintf(stderr, "RESOURCE res=%p (prev=%p next=%p) %ju %ju\n",
              (void *)r, (void *)r->prevlive, (void *)r->nextlive,
              (uintmax_t)r->resource, r->size);
    }
  }

  for (Stack *kid = s->children; kid; kid = kid->sibling)
    debugDumpStack(kid, depth+1);
}

void
IgProfTrace::debugDump(void)
{
  fprintf (stderr, "TRACE BUFFER %p:\n", (void *)this);
  fprintf (stderr, " RESTABLE:  %p\n", (void *)restable_);
  fprintf (stderr, " CALLCACHE: %p\n", (void *)callcache_);

  debugDumpStack(stack_, 0);
  // debugDumpResources();
}
