#include "hook.h"
#include "profile.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <cerrno>
#include <cassert>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/time.h>

#if __APPLE__
#include <mach/mach.h>
#endif

#if __i386__
# define TRAMPOLINE_JUMP        5       // jump to hook/old code
# define TRAMPOLINE_SAVED       10      // 5+margin for saved prologue
#elif __x86_64__
# define TRAMPOLINE_JUMP        32      // jump to hook/old code
# define TRAMPOLINE_SAVED       10      // 5+margin for saved prologue
#elif __ppc__
# define TRAMPOLINE_JUMP        16      // jump to hook/old code
# define TRAMPOLINE_SAVED       4       // one prologue instruction to save
#else
# error sorry this platform is not supported
#endif

#define TRAMPOLINE_SIZE (TRAMPOLINE_JUMP+TRAMPOLINE_SAVED+TRAMPOLINE_JUMP)

#if !defined MAP_ANONYMOUS && defined MAP_ANON
# define MAP_ANONYMOUS MAP_ANON
#endif

#if !__linux
# define dlvsym(h,fn,v) dlsym(h,fn)
#endif

/** Allocate a trampoline area into @a ptr.  Returns error code on
    failure, success otherwise.  The memory is allocated into an
    address suitable for single-instruction branches (see @c direct
    argument to #redirect()) if the architecture so requires.  */
static IgHook::Status
allocate(void *&ptr, void *target UNUSED)
{
  // FIXME: a page per trampoline is a bit excessive...
  unsigned int pagesize = getpagesize();
#if __APPLE__ && __ppc__
  // Allocate at end of memory so the address sign extends -- "ba"
  // can only take 24-bit immediate offset plus two zero bits
  // stripped off at the right end.  It can be either in the low 25
  // bits which can be crowded, or 26-bit address that sign extends
  // -- i.e. in high memory.  Thus the top six bits of the address
  // are required to be 1, i.e. 0xfe000000 .. 0xffffffff.

  // Ask for a page in a specific place.  Note that this uses Mach's
  // vm_allocate, not mmap(), as mmap() + MAP_FIXED will happily map
  // over an existing memory mapping, and there does not seem to be
  // a convenient (unix-only) API to query whether the memory region
  // is already taken.
  vm_address_t limit = 0xfeffffff;
  vm_address_t address = 0xfe000000;
  kern_return_t retcode;
  do retcode = vm_allocate(mach_task_self(), &address, pagesize, FALSE);
  while (retcode != KERN_SUCCESS && (address += pagesize) < limit);
  void *addr = (address < limit ? (void *) address : MAP_FAILED);
#elif __linux__ && __x86_64__
  // Find a memory page we can allocate in the same 32-bit section.
  // JMP instruction doesn't have an 8-byte address version, and in
  // any case we don't want to use that long instruction sequence:
  // we'd have to use at least 10-12 bytes of the function prefix,
  // which frequently isn't location independent so we'd have to
  // parse and rewrite the code if we copied it.
  unsigned long address = (unsigned long) target;
  unsigned long baseaddr = (address & 0xffffffff00000000);
  unsigned long freepage = address + 1;

  FILE *maps = fopen("/proc/self/maps", "r");
  if (maps)
  {
    while (! feof(maps))
    {
      char range[128];
      range[0] = 0;

      for (size_t i = 0; i < sizeof(range)-1; ++i)
      {
	int c = fgetc(maps);
	if (c == EOF || c == ' ' || c == '\n')
	  break;

	range[i] = c;
	range[i+1] = 0;
      }

      unsigned long low, high;
      if (sscanf(range, "%lx-%lx", &low, &high) != 2)
	continue;

      if ((low & 0xffffffff00000000) == baseaddr
	  && freepage >= low
	  && freepage < high)
	freepage = high;
    }

    fclose(maps);
  }

  if ((freepage & 0xffffffff00000000) != baseaddr)
  {
    ptr = 0;
    return IgHook::ErrAllocateTrampoline;
  }

  void *addr = mmap((void *) freepage, pagesize,
		    PROT_READ | PROT_WRITE | PROT_EXEC,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
#else
  // Just ask for a page.  Let system position it, so we don't unmap
  // or remap over address space accidentally.
  void *addr = mmap(0, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
  if (addr != MAP_FAILED)
  {
    unsigned int *page = (unsigned int *) addr;
    *page = pagesize;
    ptr = ++page;
    return IgHook::Success;
  }
  else
  {
    ptr = 0;
    return IgHook::ErrAllocateTrampoline;
  }
}

/** Release a trampoline previously created by #allocate(). */
static void
release(void *ptr)
{
  unsigned int *page = (unsigned int *) ptr;
  --page;
  munmap(page, *page);
}

/** Change memory protection for code at @a address.  Sets @a address
    to readable and executable, plus writable if @a writable is true.
    Call this function with @a writable = true before messing with
    existing code segments, and with @a writable = false after code
    has been edited.  */
static IgHook::Status
protect(void *address, bool writable)
{
  assert(sizeof(address) <= sizeof(unsigned long));

  int pagesize = getpagesize();
  address = (void *) (((unsigned long) address) & ~(pagesize-1));
#if __APPLE__
  // (http://lists.apple.com/archives/Darwin-kernel/2005/Feb/msg00045.html)
  // The dynamic loader (dyld) loads pages into unmodifiable system-wide
  // shared map.  The first time we touch a page we need to make a
  // writable process-local copy of the page; on subsequent uses we
  // can just go ahead and flip the page writable.  We can't give
  // executable permissions on the page however.
  mach_port_t self = mach_task_self();
  vm_address_t vmaddr = (vm_address_t) address;
  vm_prot_t protection = VM_PROT_READ | VM_PROT_WRITE;
  kern_return_t retcode = vm_protect(self, vmaddr, pagesize, false, protection);;
  if (writable && retcode != KERN_SUCCESS)
  {
    protection = VM_PROT_READ | VM_PROT_COPY;
    retcode = vm_protect(self, vmaddr, pagesize, FALSE, protection);
  }
  if (retcode != KERN_SUCCESS)
  {
    igprof_debug("vm_protect(%p, %d, %d) failed: %d\n",
		 address, pagesize, protection, retcode);
    return IgHook::ErrMemoryProtection;
  }
#else
  int protection = PROT_READ | PROT_EXEC | (writable ? PROT_WRITE : 0);
  if (mprotect(address, pagesize, protection))
  {
    igprof_debug("mprotect(%p, %d, %d) failed: %d\n",
		 address, pagesize, protection, errno);
    return IgHook::ErrMemoryProtection;
  }
#endif

  return IgHook::Success;
}

/** Flush data and instruction caches.  Called when we are finished with
    modifying code in place to ensure the copies have made it to memory
    and processor will use the new versions.  */
static void
flush(void *address)
{
  msync(address, TRAMPOLINE_SIZE, MS_INVALIDATE);
}

/** Adjust @a ptr by @a n bytes.  Returns the modified @a ptr.  */
static void *
skip(void *&ptr, int n)
{ ptr = (unsigned char *) ptr + n; return ptr; }

//////////////////////////////////////////////////////////////////////
/** Find @a fn and assign it's address into @a sym.  If @a lib is
    non-null, the library is dynamically loaded and looked up in that
    library.  Otherwise looks for the symbol in already loaded
    libraries, or failing that, in the main program itself.  On
    failure returns error code, otherwise sets @a sym and returns
    success. */
static IgHook::Status
lookup(const char *fn, const char *v, const char *lib, void *&sym)
{
  sym = 0;

  if (lib)
  {
    void *handle = dlopen(lib, RTLD_LAZY | RTLD_GLOBAL);
    if (! handle)
    {
      igprof_debug("dlopen('%s'): %s\n", lib, dlerror());
      return IgHook::ErrLibraryNotFound;
    }

    sym = v ? dlvsym(handle, fn, v) : dlsym(handle, fn);
    if (! sym)
    {
      igprof_debug("dlsym('%s', '%s'): %s\n", lib, fn, dlerror());
      return IgHook::ErrSymbolNotFoundInLibrary;
    }
  }
  else
  {
    void *program = dlopen(0, RTLD_LAZY | RTLD_GLOBAL);
    sym = v ? dlvsym(program, fn, v) : dlsym(program, fn);
    dlclose(program);
    if (! sym) sym = v ? dlvsym(program, fn, v) : dlsym(RTLD_NEXT, fn);
    if (! sym)
    {
      igprof_debug("dlsym(self, '%s'): %s\n", fn, dlerror());
      return IgHook::ErrSymbolNotFoundInSelf;
    }
  }

  return IgHook::Success;
}

/** Parse function prologue at @a address.  Returns the number of
    instructions understood that need to be moved out to insert a jump
    to the trampoline, or -1 if a sufficiently long safe sequence was
    not found.  */
static int
parse(const char *func, void *address, unsigned *patches)
{
  int n = 0;

#if __i386__
  unsigned char *insns = (unsigned char *) address;
  if (insns[0] == 0xe9)
  {
    igprof_debug("%s (%p): hook trampoline already installed, ignoring\n",
		 func, address);
    return -1;
  }

  while (n < 5)
  {
    if (insns[0] >= 0x50 && insns[0] <= 0x57) /* push %e*x */
      ++n, ++insns;

    else if (insns[0] == 0x89 && insns[1] == 0xe5) /* mov %esp, %ebp */
      n += 2, insns += 2;

    else if (insns[0] == 0x89 && insns[1] == 0xda) /* mov %ebx, %edx */
      n += 2, insns += 2;

    else if (insns[0] == 0x83 && insns[1] == 0xec) /* sub $0x*, %esp */
      n += 3, insns += 3;

    else if (insns[0] == 0x81 && insns[1] == 0xec) /* sub $0x*, %esp (32-bit) */
      n += 6, insns += 6;

    else if (insns[0] == 0x8b && insns[2] == 0x24) /* mov 0x4(%esp,1),%e*x */
      n += 4, insns += 4;

    else if (insns[0] == 0x8d && insns[1] == 0x55) /* lea $0x*(%ebp),%edx */
      n += 3, insns += 3;

    else if (insns[0] >= 0xb8 && insns[0] <= 0xbf) /* mov $0xNN,%e*x */
      n += 5, insns += 5;

    else if (insns[0] == 0xff && insns[1] == 0x25) /* jmp *addr */
      n += 6, insns += 6;

    else if (insns[0] == 0x65 && insns[1] == 0x83 && insns[2] == 0x3d)
      n += 8, insns += 8;                          /* cmpl $0x*,%gs:0x* */

    else if (insns[0] == 0xe8) /* call +offset (32-bit) */
      *patches++ = n+1, n += 5, insns += 5;

    else
    {
      igprof_debug("%s (%p) + 0x%x: unrecognised prologue (found 0x%x)\n",
		   func, address, insns - (unsigned char *) address, *insns);
      return -1;
    }
  }
#elif __x86_64__
  unsigned char *insns = (unsigned char *) address;
  if (insns[0] == 0xe9)
  {
    unsigned long target = (unsigned long) insns + *(int *)(insns+1) + 5;
    if ((target & 0xfff) == 0x004)
    {
      igprof_debug("%s (%p): hook trampoline already installed, ignoring\n",
		   func, address);
      return -1;
    }
    else
      igprof_debug("%s (%p): jump instruction found, but not a hook target\n",
		   func, address);
  }

  while (n < 5)
  {
    if (insns[0] == 0xf && insns[1] == 0x5)         /* syscall */
      n += 2, insns += 2;

    else if (insns[0] == 0x41 && (insns[1] >= 0x54 && insns[1] <= 0x57))
      n += 2, insns += 2;                         /* push %r* */

    else if (insns[0] == 0x41 && insns[1] == 0x89 && insns[2] == 0xfc)
      n += 3, insns += 3;                         /* mov %edi,%r12d */

    else if (insns[0] == 0x41 && insns[1] == 0xb9)  /* mov $0x*,%r9d */
      n += 6, insns += 6;

    else if (insns[0] == 0x48 && insns[1] == 0x85 && insns[2] == 0xf6)
      n += 3, insns += 3;                         /* test  %rsi,%rsi */

    else if (insns[0] == 0x48 && insns[1] == 0x63 && insns[2] == 0xf7)
      n += 3, insns += 3;                         /* movslq %edi,%rsi */

    else if ((insns[0] == 0x48 || insns[0] == 0x4c) /* mov %r*,$0x*(%rsp) */
	     && insns[1] == 0x89 && insns[3] == 0x24)
      n += 5, insns += 5;

    else if (insns[0] == 0x48 && insns[1] == 0x8b   /* mov $0x*(%rip),%r* */
	     && (insns[2] == 0x3d || insns[2] == 0x05))
      *patches++ = 0x700 + n+3, n += 7, insns += 7;

    else if (insns[0] == 0x48 && insns[1] == 0xc7 && insns[2] == 0xc0)
      n += 7, insns += 7;                         /* mov $0x*,%rax */

    else if (insns[0] == 0x48 && insns[1] == 0x81 && insns[2] == 0xec)
      n += 7, insns += 7;                         /* sub $0x*,%rsp */

    else if (insns[0] == 0x48 && insns[1] == 0x83 && insns[2] == 0xec)
      n += 4, insns += 4;                         /* sub $0x*,%rsp */

    else if (insns[0] == 0x48 && insns[1] == 0x8d && insns[2] == 0x05)
      *patches++ = 0x700 + n+3, n += 7, insns += 7; /* lea $0x*(%rip),%rax */

    else if (insns[0] == 0x48 && insns[1] == 0x89)
      n += 3, insns += 3;                         /* mov %r*,%r* */

    else if (insns[0] == 0x49 && insns[1] == 0x89)
      n += 3, insns += 3;                         /* mov %r*,%r* */

    else if (insns[0] == 0x4c && insns[1] == 0x8b   /* mov $0x*(%rip),%r* */
	     && insns[2] == 0x0d)
      *patches++ = 0x700 + n+3, n += 7, insns += 7;

    else if (insns[0] == 0x4c && insns[1] == 0x8d && insns[2] == 0x3d)
      *patches++ = 0x700 + n+3, n += 7, insns += 7; /* lea $0x*(%rip),%r15 */

    else if (insns[0] == 0x55 || insns[0] == 0x53)
      n += 1, insns += 1;                         /* push %rbp / %rbx */

    else if (insns[0] == 0x83 && insns[1] == 0xf8)  /* cmp $0x*,%eax */
      n += 3, insns += 3;

    else if (insns[0] == 0x89 && insns[1] == 0xfd)
      n += 2, insns += 2;                         /* mov %edi,%ebp */

    else if (insns[0] == 0x8d && insns[1] == 0x47)
      n += 3, insns += 3;                         /* lea $0x*(%rdi),%eax */

    else if (insns[0] == 0xb8)                      /* mov $0x*,%eax */
      n += 5, insns += 5;

    else if (insns[0] == 0xe9)                      /* jmpq (32-bit offset) */
      *patches++ = 0x500 + n+1, n += 5, insns += 5;

    else
    {
      igprof_debug("%s (%p) + 0x%x: unrecognised prologue (found 0x%x 0x%x 0x%x 0x%x)\n",
		   func, address, insns - (unsigned char *) address,
		   insns[0], insns[1], insns[2], insns[3]);
      return -1;
    }
  }
#elif __ppc__
  // FIXME: check for various branch-relative etc. instructions
  assert(sizeof (unsigned int) == 4);
  unsigned int *insns = (unsigned int *) address;
  unsigned int instr = *insns;
  if ((instr & 0xfc1fffff) == 0x7c0903a6) // check it's not mfctr
  {
    igprof_debug("%s (%p): mfctr can't be instrumented\n", func, address);
    return -1;
  }

  n = 4;
#endif

  *patches = 0;
  return n;
}

/** Insert escape jump from address @a from to address @a to.  Caller
    must ensure offset for @a to is suitable for a single branch
    instruction with limited number of bits for immediate argument on
    architectures where only a single instruction is replaced in the
    prologue.  */
static int
redirect(void *&from, void *to, IgHook::JumpDirection direction UNUSED)
{
#if __i386__
  // NB: jump offsets are calculated from *after* the jump instruction
  unsigned char *start = (unsigned char *) from;
  unsigned char *insns = (unsigned char *) from;
  unsigned long diff = (unsigned long) to - ((unsigned long) from + 5);
  *insns++ = 0xe9;
  *insns++ = diff & 0xff;
  *insns++ = (diff >> 8) & 0xff;
  *insns++ = (diff >> 16) & 0xff;
  *insns++ = (diff >> 24) & 0xff;
  from = insns;
  return insns - start;

#elif __x86_64__
  // This is essentially similar to i386 mode however there is no
  // "large model" jmp instruction.  We have to load the address
  // to a register and then jump indirectly via the register.
  // The ABI reserves r11 register for scratch pad use like this.
  unsigned char *start = (unsigned char *) from;
  unsigned char *insns = (unsigned char *) from;
  unsigned long addrloc;
  unsigned long diff;

  switch (direction)
  {
  case IgHook::JumpToTrampoline:
    // The jump to the trampoline is like i386, with 32-bit offset.
    diff = (unsigned long) to - ((unsigned long) from + 5);
    *insns++ = 0xe9;
    *insns++ = diff & 0xff;
    *insns++ = (diff >> 8) & 0xff;
    *insns++ = (diff >> 16) & 0xff;
    *insns++ = (diff >> 24) & 0xff;
    break;

  case IgHook::JumpFromTrampoline:
    addrloc = ((unsigned long) insns + 9 + 15) & 0xfffffffffffffff0;
    *insns++ = 0x4c; // 0-6: movq N(%rip),%r11
    *insns++ = 0x8b;
    *insns++ = 0x1d;
    *insns++ = addrloc - (unsigned long) start - 7; // N
    *insns++ = 0x00;
    *insns++ = 0x00;
    *insns++ = 0x00;
    *insns++ = 0x41; // 7-9: jmp *%r11
    *insns++ = 0xff;
    *insns++ = 0xe3;
    while ((unsigned long) insns < addrloc)
      *insns++ = 0x90; // (gap): nop

    *(unsigned long *)insns = (unsigned long) to;
    insns += 8;
    break;
  }
  from = insns;
  return insns - start;

#elif __ppc__
  // The low six bits are "ba" instruction (opcode 18 = 0x12),
  // then immediate address with the low two bits stripped off,
  // and top two bits are "01" (no link, absolute).  This only
  // works if the address is appropriate.  The 24-bit immediate
  // address is sign extended to 32 bits, so either it must be
  // in the low 23-bit address space, or in the high area.
  unsigned int *start = (unsigned int *) from;
  unsigned int *insns = (unsigned int *) from;

  assert(sizeof (unsigned int) == 4);
  assert(! ((unsigned int) to & 0x3));
  // *insns++ = 0x40000012 | (((unsigned int) to >> 2) << 5); // ba to
  *insns++ = 0x48000002 | ((unsigned int) to & 0x3ffffff);
  from = insns;
  return (insns - start) * 4;
#endif
}

/** Insert into address @a from the first part of a jump to address @a
    to.  Th instruction sequence can be longer than that allowed by
    #redirect(), and thus @a to can be an arbitrary address.  The
    function returns the number of bytes inserted.  It also updates @a
    from to the next address after the jump.  The caller can then
    insert other instructions to be executed just before the jump, and
    should then call #postreentry() to insert the actual jump
    code.  */
static int
prereentry(void *&from, void *to)
{
#if __ppc__
  // Set ctr using r0 as a temporary register.  The assumption here
  // is that this instruction sequence comes as immediate target of
  // a call in the re-entry part of the trampoline, meaning that we
  // are allowed to trash r0 (it's a volatile register so caller
  // must have saved it).  The instruction copied from the original
  // prologue comes after this one and must not trash ctr (parse()
  // ensures that) but may trash r0 after us.
  assert(sizeof(to) == sizeof(unsigned int));
  assert(sizeof(unsigned int) == 4);
  unsigned int *start = (unsigned int *) from;
  unsigned int *insns = (unsigned int *) from;
  *insns++ = 0x3c000000 | (((unsigned int) to & 0xffff0000) >> 16); // lis r0,addrhi
  *insns++ = 0x60000000 | (((unsigned int) to & 0x0000ffff) >> 0);  // ori r0,r0,addrlo
  *insns++ = 0x7c0903a6; // mtctr r0
  from = insns;
  return (insns - start) * 4;
#else
  // nothing to do
  (void) from;
  (void) to;
  return 0;
#endif
}

/** Insert into address @a from the final jump to address @a to.  */
static int
postreentry(void *&from, void *to)
{
#if __i386__ || __x86_64__
  // Real jump
  return redirect(from, to, IgHook::JumpFromTrampoline);
#elif __ppc__
  // ctr was set in prereentry(), jump into it
  assert(sizeof(unsigned int) == 4);
  unsigned int *start = (unsigned int *) from;
  unsigned int *insns = (unsigned int *) from;
  *insns++ = 0x4e800420; // bctr
  from = insns;
  return (insns - start) * 4;
#endif
}

/** Prepare a hook trampoline into @a address.  The first part of the
    trampoline is an unconditional jump instruction (not a call!) into
    the @a replacement function.  The second part is a copy of @a
    prologue bytes of preamble in the original function @a old,
    patched for PC-relative addressing according to @a patches,
    followed by another unconditional jump to the rest of the original
    function.  If @a chain is non-null, it will be set to point to
    this second part of the trampoline so @a replacement can call the
    uninstrumented original function.  */
static void
prepare(void *address,
	void *replacement, void **chain,
	void *old, int prologue, unsigned *patches UNUSED)
{
  // First part: unconditional jump to replacement
  prereentry(address, replacement);
  postreentry(address, replacement);

  // Second part: old function prologue + jump to post-prolugue code
  if (chain) *chain = address;
  prereentry(address, ((unsigned char *) old) + prologue);
#if __x86_64__
  void *start = address;
#endif
  memcpy(address, old, prologue);

#if __i386__
  // Patch i386 relative 'call' instructions found in prologue.
  // In practice there can be at most one patch since it's five
  // byte <0xe8, nn, nn, nn, nn> instruction. So if there is one
  // it must be the last instruction. Convert it to a push + jump
  // <0xff 0x35 nn nn nn nn> <0xe9 nn nn nn nn> to simulate call
  // coming from the original site - this is important in case
  // it's PIC __i686.get_pc_thunk.* call. Note both call and
  // jump instructions are relative to the address immediately
  // after the intruction. Obviously if we apply a patch, the
  // postreentry() created below will not be used.
  if (patches && *patches)
  {
    assert((unsigned) prologue == *patches + 4);

    // Compute addresses: original destination, where to patch.
    unsigned char *insns = (unsigned char *) address + *patches - 1;
    unsigned long retaddr = (unsigned long) old + *patches + 4;
    unsigned long offset = * (unsigned *) ((unsigned char *) old + *patches);
    unsigned long dest = retaddr + offset;

    // push <old-return-address>
    *insns++ = 0x68;
    *insns++ = retaddr & 0xff;
    *insns++ = (retaddr >> 8) & 0xff;
    *insns++ = (retaddr >> 16) & 0xff;
    *insns++ = (retaddr >> 24) & 0xff;

    // jmpq <delta-to-original-destination>
    unsigned long diff = dest - ((unsigned long) insns + 5);
    *insns++ = 0xe9;
    *insns++ = diff & 0xff;
    *insns++ = (diff >> 8) & 0xff;
    *insns++ = (diff >> 16) & 0xff;
    *insns++ = (diff >> 24) & 0xff;
  }
  else
  {
    skip(address, prologue);
    skip(old, prologue);
    postreentry(address, old);
  }
#else
  skip(address, prologue);
  skip(old, prologue);
  postreentry(address, old);
#endif

#if __x86_64__
  // Patch up PC-relative addresses. The patch values are of formed
  // Y << 8 + X, where X is offset into the instruction series
  // and Y is the delta to subtract: the instruction series length.
  for ( ; patches && *patches; ++patches)
  {
    unsigned patch = *patches;
    unsigned offset = patch & 0xff;
    unsigned delta = patch >> 8;
    *((unsigned *)((unsigned char *)start + offset))
      += (unsigned char *)old - (unsigned char *)start - delta;
  }
#endif
}

/** Link original function at @a address to @a trampoline.  The size
    of the previously parsed prologue is @a prologue bytes.  Replaces
    the initial sequence of function at @a address with a jump to @a
    trampoline.  If the jump instruction is less than @a prologue, the
    rest is filled up with "nop" instructions.  */
static void
patch(void *address, void *trampoline, int prologue)
{
  // FIXME: Not atomic, freeze all other threads!
  unsigned char *insns = (unsigned char *) address;
  int i = redirect(address, trampoline, IgHook::JumpToTrampoline);
  for ( ; i < prologue; ++i)
  {
#if __i386__ || __x86_64__
    insns[i] = 0x90; // nop
#else
    // can't happen!
    igprof_abort();
#endif
  }
}

IgHook::Status
IgHook::hook(const char *function,
	     const char *version,
	     const char *library,
	     void *replacement,
	     int options /* = 0 */,
	     void **chain /* = 0 */,
	     void **original /* = 0 */,
	     void **trampoline)
{
  // For future compatibility -- call vs. jump, counting etc.
  if (options != 0)
    return ErrBadOptions;

  // Zero out variables
  if (chain) *chain = 0;
  if (original) *original = 0;
  if (trampoline) *trampoline = 0;

  // Lookup function
  Status s;
  void *sym = 0;
  if ((s = lookup(function, version, library, sym)) != Success)
    return s;

  if (original) *original = sym;

  // See if we understand it
  unsigned patches[TRAMPOLINE_SIZE];
  int prologue = parse(function, sym, patches);
  if (prologue < 0)
    return ErrPrologueNotRecognised;
  else if (prologue > TRAMPOLINE_SAVED)
    return ErrPrologueTooLarge;

  // Prepare trampoline
  void *tramp = 0;
  if ((s = allocate(tramp, sym)) != Success)
    return s;

  if (trampoline)
    *trampoline = tramp;

  if (version)
    igprof_debug("%s/%s (%p): instrumenting %d bytes into %p\n",
		 function, version, sym, prologue, tramp);
  else
    igprof_debug("%s (%p): instrumenting %d bytes into %p\n",
		 function, sym, prologue, tramp);

  prepare(tramp, replacement, chain, sym, prologue, patches);

  // Attach trampoline
  if ((s = protect(sym, true)) != Success)
  {
    release(tramp);
    return s;
  }

  patch(sym, tramp, prologue);

  // Restore privileges and flush caches
  // No: protect(tramp, false); -- segvs on linux, full page might not been allocated?
  protect(sym, false);
  flush(tramp);
  flush(sym);

  return Success;
}
