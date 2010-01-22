#ifndef IG_RESOLVE_SYMBOLS
#define IG_RESOLVE_SYMBOLS

#include <classlib/iotools/InputStream.h>
#include <classlib/iotools/StorageInputStream.h>
#include <classlib/iotools/BufferInputStream.h>
#include <classlib/iobase/File.h>
#include <classlib/iobase/FileError.h>
#include <classlib/iobase/Filename.h>
#include <classlib/utils/DebugAids.h>
#include <classlib/utils/StringOps.h>
#include <classlib/utils/Regexp.h>
#include <classlib/utils/RegexpMatch.h>
#include <classlib/utils/Argz.h>
#include <classlib/iobase/Pipe.h>
#include <classlib/iotools/IOChannelInputStream.h>
#include <classlib/iotools/InputStream.h>
#include <classlib/iotools/InputStreamBuf.h>
#include <classlib/zip/GZIPInputStream.h>
#include <classlib/zip/BZIPInputStream.h>
#include <classlib/zip/ZipInputStream.h>
#include <classlib/iobase/SubProcess.h>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <string>
#include <list>
#include <iostream>
#include <cmath>
#include <sys/stat.h>
#include <map>
#include <stdint.h>

// FIXME: Doh... Why did I not use isspace?? Is this actually faster? To check.
bool isWhitespace(char c)
{
  //^ \t\n\r\f\v
  if (c == ' '
      || c == '\t'
      || c == '\n'
      || c == '\r'
      || c == '\f'
      || c == '\v') return true;
  return false;
}

class PipeReader
{
public:
  PipeReader(const std::string &args, lat::IOChannel *source=0)
    : m_argz(args),
      m_is(0),
      m_isbuf(0),
      m_cmd(0)
    {
      static lat::File s_stderr(lat::Filename::null(), lat::IOFlags::OpenRead | lat::IOFlags::OpenWrite);
      lat::IOChannel *nil = 0;

      if (!source)
        m_cmd = new lat::SubProcess(m_argz.argz(), 
                                    lat::SubProcess::One | lat::SubProcess::Read | lat::SubProcess::NoCloseError,
                                    &m_pipe, nil, &s_stderr);
      else
        m_cmd = new lat::SubProcess(m_argz.argz(), 
                                    lat::SubProcess::One | lat::SubProcess::Read | lat::SubProcess::NoCloseError,
                                    source, m_pipe.sink(), &s_stderr);
      m_is = new lat::IOChannelInputStream(m_pipe.source());
      m_isbuf = new lat::InputStreamBuf(m_is);
      m_istd  = new std::istream(m_isbuf);    
    }
  
  ~PipeReader(void)
    {
      if (m_pipe.source())
        m_pipe.source()->close();
      delete m_isbuf;
      delete m_istd;
      delete m_is;
      delete m_cmd;
    }
  
  std::istream &output(void)
    {
      return *m_istd;
    }
private:
  lat::Argz m_argz;
  lat::Pipe m_pipe;
  std::istream *m_istd;
  lat::IOChannelInputStream *m_is;
  lat::InputStreamBuf *m_isbuf;
  lat::SubProcess *m_cmd;
};

bool skipWhitespaces(const char *srcbuffer, const char **destbuffer)
{
  if (!isWhitespace(*srcbuffer++))
    return false;
  while (isWhitespace(*srcbuffer))
    srcbuffer++;
  *destbuffer = srcbuffer;
  return true;
}

bool skipString(const char *strptr, const char *srcbuffer, const char **dstbuffer)
{
  // Skips strings of the form '\\s+strptr\\s+' starting from buffer.
  // Returns a pointer to the first char which does not match the above regexp,
  // or 0 in case the regexp is not matched.
  if(strncmp(srcbuffer, strptr, strlen(strptr))) 
    return false;
  *dstbuffer = srcbuffer + strlen(strptr);
  return true;
}

class FileInfo
{
public:
  typedef uint64_t Offset;
private:
  struct CacheItem {
    CacheItem(Offset offset, const std::string &name)
      :OFFSET(offset), NAME(name) {};
    Offset OFFSET;
    std::string NAME;
  };

  typedef std::vector<CacheItem> SymbolCache;
  
  struct CacheItemComparator {
    bool operator()(const CacheItem& a, 
                    const Offset &b) const
      { return a.OFFSET < b; }
      
    bool operator()(const Offset &a, 
                    const CacheItem &b) const
      { return a < b.OFFSET; }    
  };
public:
  std::string NAME;
  FileInfo(void) : NAME("<dynamically generated>") {}
  FileInfo(const std::string &name, bool useGdb)
    : NAME(name)
    {
      if (useGdb)
      {
        ASSERT(lat::Filename(name).isDirectory() == false);
        this->createOffsetMap();
      }
    }

  const char *symbolByOffset(Offset offset)
    {
      if (m_symbolCache.empty())
        return 0;

      SymbolCache::iterator i = lower_bound(m_symbolCache.begin(),
                                            m_symbolCache.end(),
                                            offset, CacheItemComparator());
      if (i->OFFSET == offset)
        return i->NAME.c_str();
    
      if (i == m_symbolCache.begin())
        return m_symbolCache.begin()->NAME.c_str();

      --i;

      return i->NAME.c_str(); 
    }

  Offset next(Offset offset)
    {
      SymbolCache::iterator i = upper_bound(m_symbolCache.begin(),
                                            m_symbolCache.end(),
                                            offset, CacheItemComparator());
      if (i == m_symbolCache.end())
        return 0;
      return i->OFFSET;      
    }
private:
  void createOffsetMap(void)
    {
      // FIXME: On macosx we should really use otool
#ifndef __APPLE__
      std::string commandLine = "objdump -p " + std::string(NAME);
      PipeReader objdump(commandLine);
    
      std::string oldname;
      std::string suffix;
      Offset vmbase = 0;
      bool matched = false;

      while (objdump.output())
      {
        // Checks the following regexp
        //    
        //    LOAD\\s+off\\s+(0x[0-9A-Fa-f]+)\\s+vaddr\\s+(0x[0-9A-Fa-f]+)
        // 
        // and sets vmbase to be $2 - $1 of the first matched entry.
      
        std::string line;
        std::getline(objdump.output(), line);
    
        if (!objdump.output()) 
          break;
        if (line.empty()) 
          continue;
      
        const char *lineptr = line.c_str();
        if (!skipWhitespaces(lineptr, &lineptr)) 
          continue;
        if (!skipString("LOAD", lineptr, &lineptr)) 
          continue;
        if (!skipWhitespaces(lineptr, &lineptr)) 
          continue;
        if (!skipString("off", lineptr, &lineptr)) 
          continue;
        char *endptr = 0;
        Offset initialBase = strtol(lineptr, &endptr, 16);
        if (lineptr == endptr) 
          continue;
        lineptr = endptr;
        if (!skipWhitespaces(lineptr, &lineptr))
          continue;
        if (!skipString("vaddr", lineptr, &lineptr))
          continue;
        if (!skipWhitespaces(lineptr, &lineptr))
          continue;
        Offset finalBase = strtol(lineptr, &endptr, 16);
        if (lineptr == endptr)
          continue;
        vmbase = finalBase - initialBase;
        matched = true;
        break;
      }
    
      if (!matched)
      {
        std::cerr << "Cannot determine VM base address for " 
                  << NAME << std::endl;
        std::cerr << "Error while running `objdump -p " + std::string(NAME) + "`" << std::endl;
        exit(1);
      }
    
      PipeReader nm("nm -t d -n " + std::string(NAME));
      while (nm.output())
      {
        std::string line;
        std::getline(nm.output(), line);
    
        if (!nm.output()) break;
        if (line.empty()) continue;
        // If line does not match "^(\\d+)[ ]\\S[ ](\S+)$", exit.
        const char *begin = line.c_str();
        char *endptr = 0;
        Offset address = strtol(begin, &endptr, 10);
        if (endptr == begin) 
          continue; 

        if (*endptr++ != ' ') 
          continue; 

        if (isWhitespace(*endptr++))  
          continue; 
        if (*endptr++ != ' ')  
          continue; 

        char *symbolName = endptr;
      
        while (*endptr && !isWhitespace(*endptr))
          endptr++;
        if (*endptr != 0)
          continue;
        // If line starts with '.' forget about it.
        if (symbolName[0] == '.')
          continue;
        // Create a new symbol with the given fileoffset.
        // The symbol is automatically saved in the FileInfo cache by offset.
        // If a symbol with the same offset is already there, the new one 
        // replaces the old one.
        Offset offset = address - vmbase;
        if (m_symbolCache.size() && (m_symbolCache.back().OFFSET == offset))
          m_symbolCache.back().NAME = symbolName;
        else
          m_symbolCache.push_back(CacheItem(address-vmbase, symbolName));
      }
#endif /* __APPLE__ */
    }

  SymbolCache m_symbolCache;
};

#endif
