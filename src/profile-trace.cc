#include "profile-trace.h"
#include "walk-syms.h"
#include <memory.h>
#include <stdio.h>
#include <inttypes.h>

static const size_t MAX_HASH_PROBES = 32;
static IgProfTrace::Counter FREED;

/** Initialise a trace buffer.  */
IgProfTrace::IgProfTrace(void)
  : hashLogSize_(20),
    hashUsed_(0),
    restable_(0),
    callcache_(0),
    resfree_(0),
    stack_(0)
{
  pthread_mutex_init(&mutex_, 0);

  // Allocate a separate slab of memory the resource hash table.  This
  // has to be big for large memory applications, so it's ok to
  // allocate it separately.  Note the memory obtained here starts out
  // as zeroed out.
  restable_ = (HResource *) allocateRaw((1u << hashLogSize_)*sizeof(HResource));

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
    unallocateRaw(restable_, (1u << hashLogSize_) * sizeof(HResource));
}

void
IgProfTrace::expandResourceHash(void)
{
  HResource *newTable;
  size_t i, j, slot;
  size_t oldSize = (1u << hashLogSize_);
  size_t newLogSize = hashLogSize_;
  size_t newSize;

TRY_AGAIN:
  newLogSize += 2;
  newSize = (1u << newLogSize);
  newTable = (HResource *) allocateRaw(newSize * sizeof(HResource));
  __extension__
    igprof_debug("expanding resource hash table for %p"
		 " from 2^%ju to 2^%ju, %ju used\n",
		 (void *) this, (uintmax_t) hashLogSize_,
		 (uintmax_t) newLogSize, (uintmax_t) hashUsed_);
  for (i = 0; i < oldSize; ++i)
  {
    if (! restable_[i].record)
      continue;

    slot = hash(restable_[i].resource, 8);
    for (j = 0; true; ++slot)
    {
      slot &= newSize-1;
      if (LIKELY(! newTable[slot].record))
      {
	newTable[slot] = restable_[i];
	restable_[i].record->hashslot = &newTable[slot];
	break;
      }

      if (UNLIKELY(++j == MAX_HASH_PROBES))
      {
	__extension__
	  igprof_debug("rehash of 0x%jx[%ju -> %ju] failed,"
		       " re-expanding another time\n",
		       (uintmax_t) restable_[i].resource,
		       (uintmax_t) i, (uintmax_t) slot);
        unallocateRaw(newTable, newSize * sizeof(HResource));
        goto TRY_AGAIN;
      }
    }
  }

  unallocateRaw(restable_, oldSize * sizeof(HResource));
  hashLogSize_ = newLogSize;
  restable_ = newTable;
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
  for (int i = 0; i < MAX_COUNTERS; ++i)
    k->counters[i] = 0;
  return k;
}

inline IgProfTrace::HResource *
IgProfTrace::findResource(Address resource)
{
  // Locate the resource in the hash table.
  HResource *hr;
  HResource *free = 0;
  size_t slot = hash(resource, 8);
  size_t size = (1u << hashLogSize_);
  for (size_t i = 0; i < MAX_HASH_PROBES; ++i, ++slot)
  {
    hr = &restable_[slot & (size-1)];
    if (hr->resource == resource)
      return hr;
    else if (! free && ! hr->record)
      free = hr;
  }

  return free;
}

inline void
IgProfTrace::releaseResource(HResource *hres)
{
  ASSERT(hres);
  ASSERT(hres->resource);
  ASSERT(hashUsed_);

  Resource *res = hres->record;
  ASSERT(res);
  ASSERT(res->counter);
  ASSERT(res->counter != &FREED);
  ASSERT(res->counter->resources);

  // Deduct the resource from the counter.
  Counter *ctr = res->counter;
  ASSERT(ctr->value >= res->size);
  ASSERT(ctr->ticks > 0);
  ctr->value -= res->size;
  ctr->ticks--;

  // Unchain from hash and counter lists.
  hres->resource = 0;
  hres->record = 0;

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
  memset(res, 0, sizeof(*res));
  res->nextlive = resfree_;
  res->counter = &FREED;
  resfree_ = res;
  --hashUsed_;
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
      cache[i].address = address;
      cache[i].frame = frame;
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
  Counter *c = 0;
  Counter **ctr = &frame->counters[0];
  for (int i = 0; i < MAX_COUNTERS; ++i, ++ctr)
  {
    if (! *ctr)
    {
      *ctr = c = allocate<Counter>();
      c->def = def;
      c->ticks = 0;
      c->value = 0;
      c->peak = 0;
      c->resources = 0;
#if DEBUG
      c->frame = frame;
#endif
      break;
    }

    ASSERT((*ctr)->def);
    if ((*ctr)->def == def)
    {
      c = *ctr;
      break;
    }
  }

  ASSERT(c);

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

// Handle resource acquisition.
void
IgProfTrace::acquire(Counter *ctr, Address resource, Value size)
{
  ASSERT(ctr);

  // Locate the resource in the hash table.
  HResource *hres = findResource(resource);
  ASSERT(! hres || ! hres->record || hres->resource == resource);

  // If it's already allocated, release the resource then
  // proceed as if we hadn't found it.
  if (UNLIKELY(hres && hres->record))
  {
    igprof_debug("new %s resource 0x%lx of %ju bytes was never freed in %p\n",
                 ctr->def->name, resource, hres->record->size, (void *)this);
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
    releaseResource(hres);
  }

  // Find a free hash table entry - may require hash resize.
  while (UNLIKELY(! hres))
  {
    expandResourceHash();
    hres = findResource(resource);
  }

  ASSERT(! hres->record);

  // Insert into the hash and lists.
  Resource *res = resfree_;
  if (LIKELY(res != 0))
    resfree_ = res->nextlive;
  else
    res = allocate<Resource>();
  hres->resource = resource;
  hres->record = res;
  res->hashslot = hres;
  res->prevlive = 0;
  res->nextlive = ctr->resources;
  res->counter = ctr;
  res->size = size;
  ctr->resources = res;
  if (res->nextlive)
    res->nextlive->prevlive = res;
  ++hashUsed_;
}

// Handle resource release.  There is no call stack involved here.
void
IgProfTrace::release(Address resource)
{
  // Locate the resource in the hash table.
  HResource *hres = findResource(resource);
  ASSERT(! hres || ! hres->record || hres->resource == resource);

  // If not found, we missed the allocation, ignore this release.
  if (LIKELY(hres && hres->record))
    releaseResource(hres);
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
  Counter **ptr = &frame->counters[0];
  for (int i = 0; i < MAX_COUNTERS && *ptr; ++i, ++ptr)
  {
    Counter *c = *ptr;
    if (c->ticks && ! c->resources)
      tick(myframe, c->def, c->value, c->ticks);
    else if (c->ticks)
      for (Resource *r = c->resources; r; r = r->nextlive)
      {
        Counter *ctr = tick(myframe, c->def, r->size, 1);
	acquire(ctr, r->hashslot->resource, r->size);
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

#define INDENT(d) for (int i = 0; i < d; ++i) fputc(' ', stderr)

void
IgProfTrace::debugDumpStack(Stack *s, int depth)
{
  INDENT(2*depth);
  fprintf(stderr, "STACK %d frame=%p addr=%p next=%p kids=%p\n",
          depth, (void *)s, (void *)s->address,
          (void *)s->sibling, (void *)s->children);

  Counter **ptr = &s->counters[0];
  for (int i = 0; i < MAX_COUNTERS && *ptr; ++i, ++ptr)
  {
    Counter *c = *ptr;
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
		(uintmax_t)r->hashslot->resource, r->size);
    }
  }

  for (Stack *kid = s->children; kid; kid = kid->sibling)
    debugDumpStack(kid, depth+1);
}

void
IgProfTrace::debugDump(void)
{
  fprintf(stderr, "TRACE BUFFER %p:\n", (void *)this);
  fprintf(stderr, " RESTABLE:  %p\n", (void *)restable_);
  fprintf(stderr, " CALLCACHE: %p\n", (void *)callcache_);

  debugDumpStack(stack_, 0);
  // debugDumpResources();
}
