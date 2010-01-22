#include "IgHookTrace.h"
#include <cstdlib>
#include <cstdio>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#if __linux
# include <execinfo.h>
# include <ucontext.h>
# include <sys/syscall.h>
# if __x86_64__
#  define UNW_LOCAL_ONLY
#  include <libunwind.h>
# endif
#endif
#if __APPLE__
extern "C" void _sigtramp (void);
#endif

#if !defined MAP_ANONYMOUS && defined MAP_ANON
# define MAP_ANONYMOUS MAP_ANON
#endif

#if 0 && __x86_64__ && __linux
// Linux x86-64 does not use regular call frames, like IA-32 does for
// example, and it would be a very difficult job to decipher the call
// stack.  In order to walk the call stack correctly, we have to use
// the DWARF-2 unwind data.  This alone is incredibly, uselessly slow
// for our purposes.
//
// We avoid using the unwind data by caching frame structures for
// recently seen functions.  This is slow to start with, but very
// quickly gets fast enough for our purposes.  Fortunately the x86-64
// unwind library appears to be robust enough to be called in signal
// handlers (unlike at least some IA-32 versions).
//
// The cache consists of two arrays arranged as an open-addressed
// unprobed hash table.  Hash collisions overwrite the entry with the
// latest data.  We try to avoid making this a problem by using a
// high-quality hash function and pure brute force in the form of a
// large hash table.  A couple of megabytes goes a long way to help!
//
// The first of the cache arrays, of "void *", tracks program counter
// addresses.  A parallel array of "int" tracks the size of the call
// frame at that address.  Given a program counter and the canonical
// frame address (CFA) of the previous (= above) call frame, the new
// frame address is the previous plus the delta.  We find the address
// of the caller just above this new frame address.
//
// We use the cache as long as we can find the addresses there.  When
// we fall off the cache, we resort to the language run time unwinder.

struct IgHookTraceArgs
{
  struct
  {
    void **pc;
    int **frame;
  } cache;
  struct
  {
    void **addresses;
    int top;
    int size;
  } stack;
  void **prevframe;
};

static _Unwind_Reason_Code
GCCBackTrace (_Unwind_Context *context, void *arg)
{
  IgHookTraceArgs *args = (IgHookTraceArgs *) arg;
  if (args->stack.top < 0 || args->stack.top >= args->stack.size)
    return _URC_END_OF_STACK;

  args->stack.addresses [args->stack.top++] = (void *) _Unwind_GetIP (context);
  args->prevframe = (void **) _Unwind_GetCFA (context);
  return _URC_NO_REASON;
}
#endif

bool
IgHookTrace::symbol (void *address,
		     const char *&sym,
		     const char *&lib,
		     int &offset,
		     int &liboffset)
{
    sym = lib = 0;
    offset = 0;
    liboffset = (unsigned long) address;

    Dl_info info;
    if (dladdr (address, &info))
    {
	if (info.dli_fname && info.dli_fname [0])
	    lib = info.dli_fname;

	if (info.dli_fbase)
	    liboffset = (unsigned long) address - (unsigned long) info.dli_fbase;

	if (info.dli_saddr)
	    offset = (unsigned long) address - (unsigned long) info.dli_saddr;

	if (info.dli_sname && info.dli_sname [0])
	    sym = info.dli_sname;

	return true;
    }

    return false;
}

void *
IgHookTrace::tosymbol (void *address)
{
    Dl_info info;
    return (dladdr (address, &info)
	    && info.dli_fname
	    && info.dli_fname [0]
	    && info.dli_saddr)
	? info.dli_saddr : address;
}

int
IgHookTrace::stacktrace (void **addresses, int nmax)
{
#if __linux && __i386__
// Safer assumption for the VSYSCALL_PAGE.
//
// This in particular fixes the regression that I spotted
// in the recent changes for RHEL5. Notice that this
// assumption is not valid anymore if the program is
// being profiled under an hypervisor as mentioned here:
//
//     http://lkml.indiana.edu/hypermail/linux/kernel/0605.2/0016.html
//
# define PROBABLY_VSYSCALL_PAGE 0xffffe000
    struct frame
    {
	// Normal frame.
	frame		*ebp;
	void		*eip;
	// Signal frame stuff, put in here by kernel.
	int		signo;
	siginfo_t	*info;
	ucontext_t	*ctx;
    };
    register frame      *ebp __asm__ ("ebp");
    register frame      *esp __asm__ ("esp");
    frame               *fp = ebp;
    int			depth = 0;

    // Add fake entry to be compatible with other methods
    //
    // Removing the __extension__ gives a warning which
    // is acknowledged as a language problem in the C++ Standard Core 
    // Language Defect Report
    //
    // http://www.open-std.org/jtc1/sc22/wg21/docs/cwg_defects.html#195
    //
    // since the suggested decision seems to be that the syntax should
    // actually be "Conditionally-Supported Behavior" in some 
    // future C++ standard I simply silence the warning.
    if (depth < nmax)
	addresses[depth++] = __extension__ (void *) &IgHookTrace::stacktrace;

    // Top-most frame ends with null pointer; check the rest is reasonable
    while (depth < nmax && fp >= esp)
    {
	// Add this stack frame.  The return address is the
	// instruction immediately after the "call".  The call
	// instruction itself is 4 or 6 bytes; we guess 4.
        addresses[depth++] = (char *) fp->eip - 4;

	// Recognise signal frames.  We use two different methods
        // depending on the linux kernel version.
	//
        // For the "old" kernels / systems we check the instructions
        // at the caller's return address.  We take it to be a signal
        // frame if we find the signal return code sequence there
	// and the thread register context structure pointer:
	//
        //    mov $__NR_rt_sigreturn, %eax
	//    int 0x80
	//
	// For the "new" kernels / systems the operating system maps
        // a "vsyscall" page at a high address, and it may contain
	// either the above code, or use of the sysenter/sysexit
        // instructions.  We cannot poke at that page so we take the
        // the high address as an indication this is a signal frame.
	// (http://www.trilithium.com/johan/2005/08/linux-gate/)
	// (http://manugarg.googlepages.com/systemcallinlinux2_6.html)
	//
	// If we don't recognise the signal frame correctly here, we
	// lose one stack frame: signal delivery is not a call so
	// when the signal handler is entered, ebp still points to
	// what it was just before the signal.
	unsigned char *insn = (unsigned char *) fp->eip;
        if (insn
	    && insn[0] == 0xb8 && insn[1] == __NR_rt_sigreturn
            && insn[5] == 0xcd && insn[6] == 0x80
            && fp->ctx)
        {   
	    void *retip = (void *) fp->ctx->uc_mcontext.gregs [REG_EIP];
            if (depth < nmax)
		addresses[depth++] = retip;

	    if ((fp = (frame *)fp->ctx->uc_mcontext.gregs[REG_EBP])
		&& (unsigned long) fp < PROBABLY_VSYSCALL_PAGE
		&& (unsigned long) retip > PROBABLY_VSYSCALL_PAGE)
	    {
		// __kernel_vsyscall stack on system call exit is
		// [0] %ebp, [1] %edx, [2] %ecx, [3] return address.
		if (depth < nmax)
		    addresses[depth++] = ((void **) fp)[3];
		fp = fp->ebp;

		// It seems the frame _above_ __kernel_syscall (the
		// syscall implementation in libc, such as __mmap())
		// is essentially frame-pointer-less, so we should
		// find also the call above, but I don't know how
		// to determine how many arguments the system call
		// pushed on stack to call __kernel_syscall short
		// of interpreting the DWARF unwind information :-(
		// So we may lose one level of call stack here.
	    }

	    if ((unsigned long) fp >= PROBABLY_VSYSCALL_PAGE)
	      fp = 0;
        }

	// Otherwise it's a normal frame, process through frame pointer.
	// Allow at most 256kB displacement per frame.
        else if (abs((char *) fp - (char *) fp->ebp) < 256*1024)
            fp = fp->ebp;
	else
	    break;
    }

    return depth;
#elif __linux && __x86_64__
    union { void *ptr; int (*func)(void **, int); } u;
    unw_cursor_t  cur;
    unw_context_t ctx;
    unw_word_t    ip;
    int		  depth = 0;
    u.func = &IgHookTrace::stacktrace;

    // Add fake entry to be compatible with other methods
    if (depth < nmax)
	addresses[depth++] = u.ptr;

    // Walk the stack.
    unw_getcontext(&ctx);
    unw_init_local(&cur, &ctx);
    while (depth < nmax && unw_step(&cur) > 0)
    {
      unw_get_reg(&cur, UNW_REG_IP, &ip);
      addresses[depth++] = (void *) ip;
    }

    return depth;
#elif 0
    struct frame
    {
	// Normal frame.
	frame		*rbp;
	void		*rip;
	// Signal frame stuff, put in here by kernel.
	siginfo_t	*info;
	ucontext_t	*ctx;
    };
    register frame      *rbp __asm__ ("rbp");
    register frame      *rsp __asm__ ("rsp");
    frame               *fp = rbp;
    int			depth = 0;
    char		msgbuf [128];

    // Add fake entry to be compatible with other methods
    if (depth < nmax)
	addresses[depth++] = (void *) &IgHookTrace::stacktrace;

    // Top-most frame ends with null pointer; check the rest is reasonable
    while (depth < nmax /* && fp >= rsp */)
    {
        // write(2, msgbuf, sprintf(msgbuf, "trace %d rsp=%p rbp=%p fp=%p rip=%p frbp=%p\n", depth, rsp, rbp, fp, fp->rip, fp->rbp));
	// Add this stack frame.  The return address is the
	// instruction immediately after the "call".  The call
	// instruction itself is 4 or 6 bytes; we guess 4.
        addresses[depth++] = (char *) fp->rip - 4;

	// Recognise signal frames.
	//
        // Check the instructions at the caller's return address.
	// We take it to be a signal frame if we find the signal
	// return code sequence there and the thread register
	// context structure pointer:
	//
	//    mov $__NR_rt_sigreturn,%rax
	//    syscall
	//
	// If we don't recognise the signal frame correctly here, we
	// lose one stack frame: signal delivery is not a call so
	// when the signal handler is entered, rbp still points to
	// what it was just before the signal.
	unsigned char *insn = (unsigned char *) fp->rip;
        if (insn // recognise __restore_rt
	    && insn[0] == 0x48 && insn[1] == 0xc7 && insn[2] == 0xc0
	    && insn[3] == __NR_rt_sigreturn && insn[4] == 0 && insn[5] == 0
	    && insn[6] == 0 && insn[7] == 0x0f && insn[8] == 0x05
	    && fp->ctx)
        {   
            // write(2, msgbuf, sprintf(msgbuf, " -> signal frame retrip=%p retrbp=%p\n",
	    // 		             (void *) fp->ctx->uc_mcontext.gregs [REG_RIP],
	    // 		             (void *) fp->ctx->uc_mcontext.gregs [REG_RBP]));
	    void *retip = (void *) fp->ctx->uc_mcontext.gregs [REG_RIP];
            if (depth < nmax)
		addresses[depth++] = retip;

	    fp = (frame *) fp->ctx->uc_mcontext.gregs [REG_RBP];
        }

	// Otherwise it's a normal frame, process through frame pointer.
        else
            fp = fp->rbp;
    }

    return depth;
#elif __APPLE__ && __ppc__
    struct frame { frame *sp; void *cr; char *lr; };
    char		*sigtramplow = (char *) &_sigtramp;
    char		*sigtramphi  = (char *) sigtramplow + 256;
    register frame	*sp __asm__ ("sp");
    register char	*lr __asm__ ("lr");
    frame		*fp = sp;
    char		*entry = lr;
    int			depth = 0;

    // Add fake entry to be compatible with other methods
    if (depth < nmax)
	addresses[depth++] = (void *) &IgHookTrace::stacktrace;

    while (depth < nmax && entry)
    {
	// LR points to the instruction after call, so step back.
	addresses[depth++] = entry - 4;

	// Check next one is a valid frame.
	frame *next = fp->sp;
	if (next <= fp || next <= sp)
	    break;

	// Get and handle previous frame's call address.  Signal
	// frames are detected by being in sigtramp() and need
	// special handling.  The offset for pre-signal SP is
	// somewhat magic.
	if (entry >= sigtramplow && entry <= sigtramphi)
	{
	    fp = *(frame **) ((char *) next + 156);
	    entry = *(char **) ((char *) next + 144);
	}
	else
	{
	    fp = next;
	    entry = fp->lr;
	}
    }

    return depth;
#elif 0 && __linux
    return backtrace (addresses, nmax);
#elif __linux
    if (nmax >= 1)
    {
	IgHookTraceArgs args = { { 0, 0 }, { addresses, 0, nmax, },
				 (void **) __builtin_frame_address(0) };
	_Unwind_Backtrace (&GCCBackTrace, &args);

	if (args.stack.top > 1 && args.stack.addresses [args.stack.top-1] == 0)
	    args.stack.top--;

	return args.stack.top;
    }
    return 0;
#else
    return 0;
#endif
}
