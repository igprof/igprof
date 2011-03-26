#ifndef BUFFER_H
# define BUFFER_H

# include "macros.h"
# include "profile.h"
# include <stdlib.h>
# include <stdint.h>

/** Utility class for implementing private heap and hashed data structures.  */
class HIDDEN IgProfBuffer
{
protected:
  IgProfBuffer(void);
  ~IgProfBuffer(void);

protected:
  void unallocateRaw(void *p, size_t size);
  void *allocateRaw(size_t size);
  void *allocateSpace(size_t amount)
    {
      if (size_t(freeend_ - freestart_) < amount)
        allocatePool();

      ASSERT(size_t(freeend_ - freestart_) > amount);
      void *p = freestart_;
      freestart_ += amount;
      return p;
    }
  template <class T> T *allocate(void)
    { return static_cast<T *>(allocateSpace(sizeof(T))); }

  static uint32_t hash(uintptr_t key)
    {
      // Reduced version of Bob Jenkins' hash function at:
      //   http://www.burtleburtle.net/bob/c/lookup3.c
      // Simply converted to operate on known sized fixed
      // integral keys and no initial value (initval = 0).
      //
      // in the end get the bin with 2^BITS mask:
      //   uint32_t bin = hash(key) & (((uint32_t)1 << BITS)-1);
#     define rot(x,k) (((x)<<(k)) | ((x)>>(32-(k))))
      uint32_t a, b, c;
      a = b = c = 0xdeadbeef + sizeof (key);
#if __WORDSIZE > 32
      b += key >> 32; // for 64-bit systems, may warn on 32-bit systems
#endif
      a += key & 0xffffffffU;
      c ^= b; c -= rot(b,14);
      a ^= c; a -= rot(c,11);
      b ^= a; b -= rot(a,25);
      c ^= b; c -= rot(b,16);
      a ^= c; a -= rot(c,4);
      b ^= a; b -= rot(a,14);
      c ^= b; c -= rot(b,24);
      return c;
#     undef rot
    }

private:
  void allocatePool(void);

  void                  **poolfirst_;            //< Pointer to first memory pool.
  void                  **poolcur_;              //< Pointer to current memory pool.
  char                  *freestart_;             //< Next free address.
  char                  *freeend_;               //< Last free address.

  // Unavailable copy constructor, assignment operator
  IgProfBuffer(IgProfBuffer &);
  IgProfBuffer &operator=(IgProfBuffer &);
};

#endif // BUFFER_H
