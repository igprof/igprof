#ifndef IG_HOOK_IG_HOOK_H
# define IG_HOOK_IG_HOOK_H

class IgHook
{
public:
    enum Status
    {
	Success = 0,
	ErrBadOptions,
	ErrLibraryNotFound,
	ErrSymbolNotFoundInLibrary,
	ErrSymbolNotFoundInSelf,
	ErrPrologueNotRecognised,
	ErrPrologueTooLarge,
	ErrMemoryProtection,
	ErrAllocateTrampoline,
	ErrOther
    };

    enum JumpDirection
    {
	JumpToTrampoline,
	JumpFromTrampoline
    };

    struct Data
    {
	int		options;
	const char	*function;
	const char	*version;
	const char	*library;
	void		*replacement;
	void		*chain;
	void		*original;
	void		*trampoline;
    };

    template <typename Func>
    struct SafeData
    {
	int		options;
	const char	*function;
	const char	*version;
	const char	*library;
	Func		*replacement;
	Func		*chain;
	Func		*original;
	void		*trampoline;
    };

    template <typename Func>
    union TypedData
    {
	SafeData<Func>	typed;
	Data		raw;
    };

    static Status	hook (Data &data);
    static Status	hook (const char *function,
			      const char *version,
			      const char *library,
			      void *replacement,
			      int options = 0,
			      void **chain = 0,
			      void **original = 0,
			      void **trampoline = 0);
};

inline IgHook::Status
IgHook::hook (Data &data)
{
    return hook (data.function, data.version, data.library, data.replacement,
		 data.options, &data.chain, &data.original, &data.trampoline);
}

#endif // IG_HOOK_IG_HOOK_H
