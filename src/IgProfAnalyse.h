#ifndef IG_PROF_ANALYZE
#define IG_PROF_ANALYZE

#include "IgResolveSymbols.h"
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
#include <inttypes.h>
#include <cstdio>

class IntConverter
{
public:
  IntConverter(const std::string &string, lat::RegexpMatch *match)
    :m_string(string.c_str()),
     m_match(match) {}

  IntConverter(const char *string, lat::RegexpMatch *match)
    :m_string(string),
     m_match(match) {}
  
  int64_t operator()(int position, int base=10)
    {
      return strtoll(m_string + m_match->matchPos(position), 0, base);
    }
private:
  const char *m_string;
  lat::RegexpMatch *m_match;
};

/** This class is the payload for a node in the stacktrace
    and holds all the information about the counter that 
    we looking at.
  */
struct Counter
{
public:
  Counter()
  :cnt(0), freq(0), ccnt(0), cfreq(0)
  {}

  /** Adds the counts and freqs of @a other to this Counter.

      @a other source counter.
 
      @a isMax whether or not it needs to sum the counts
       or take the maximum between the two.
    */
  void add(const Counter &other, bool isMax)
  {
    this->freq += other.freq;

    if (isMax)
    {
      if (this->cnt < other.cnt)
        this->cnt = other.cnt;
    }
    else
      this->cnt += other.cnt;
  }

  /** Adds the cumulative counts and freqs of @a other 
      to this Counter.

      @a other source counter.
 
      @a isMax whether or not it needs to sum the counts
       or take the maximum between the two.
    */
  void accumulate(const Counter &other, bool isMax)
  {
    this->cfreq += other.cfreq;

    if (isMax)
    {
      if (this->ccnt < other.ccnt)
        this->ccnt = other.ccnt;
    }
    else
      this->ccnt += other.ccnt;
  }

  /** The total counts of the counter. */
  int64_t cnt;
  /** The number of times the counter got triggered (e.g. number of allocations) */
  int64_t freq;
  /** The accumulated counts. */
  int64_t ccnt;
  /** The accumulated number of times the counter got triggered (e.g. the 
      number of allocations of a node and all its children.)
    */
  int64_t cfreq;
};

class NameChecker
{
public:
  NameChecker(const std::string& arg) : m_arg(arg) {};
  bool operator()(const char *fullname) { return m_arg == fullname; }
  bool operator()(const char *fullname, const char *abbr)
    { 
      return (m_arg == fullname) || (m_arg == abbr); 
    }
private:
  const std::string m_arg; 
};

class ArgsLeftCounter
{
public:
  typedef std::list<std::string> ArgsList;
  ArgsLeftCounter(const ArgsList::const_iterator& end) : m_end(end) {};
  int operator()(ArgsList::const_iterator arg)
    {
      int size = 0;
      while (arg++ != m_end) { size++; }
      return size;
    }
private:
  const ArgsList::const_iterator m_end;
};


class FileOpener 
{
public:
  static const int INITIAL_BUFFER_SIZE=40000000;
  FileOpener(void)
    : m_buffer(new char[INITIAL_BUFFER_SIZE]),
      m_posInBuffer(INITIAL_BUFFER_SIZE),
      m_lastInBuffer(INITIAL_BUFFER_SIZE),
      m_eof(false),
      m_bufferSize(INITIAL_BUFFER_SIZE)
    {}
  
  virtual ~FileOpener(void)
    {
      for (Streams::reverse_iterator i = m_streams.rbegin();
           i != m_streams.rend();
           i++)
      {
        delete *i;
      }
      free(m_buffer);
    }
  
  lat::InputStream &stream(void)
    {
      return *m_streams.back();
    }

  void addStream(lat::InputStream *stream)
    {
      m_streams.push_back(stream);
    }

  void resizeBuffer(int size)
    {
      char * buffer = new char[size];
      memmove(buffer, m_buffer, m_bufferSize);
      delete[] m_buffer;
      m_buffer = buffer;
      m_bufferSize = size;
    } 
 
  void readLine()
    {
      int beginInBuffer = m_posInBuffer;

      while (m_posInBuffer < m_lastInBuffer)
      {
        if (m_buffer[m_posInBuffer++] == '\n')
        {
          m_curString = m_buffer + beginInBuffer;
          m_curStringSize = m_posInBuffer-beginInBuffer-1;
          return;
        }
      }
      int remainingsSize = m_lastInBuffer-beginInBuffer;
      ASSERT(remainingsSize <= m_bufferSize);

      if (remainingsSize == m_bufferSize)
        resizeBuffer(remainingsSize * 2);

      if (remainingsSize)
        memmove(m_buffer, m_buffer + beginInBuffer, remainingsSize);
 
      int readSize = this->stream().read(m_buffer + remainingsSize, m_bufferSize-remainingsSize);

      if (!readSize)
      { 
        m_eof = true;
        m_curString = m_buffer;
        m_curStringSize = remainingsSize;
        return;
      }

      m_posInBuffer = 0;
      m_lastInBuffer = remainingsSize + readSize;
      return this->readLine();
    }
  
  void assignLineToString(std::string &str)
    {
      str.assign(m_curString, m_curStringSize);
    }
  
  bool eof(void) {return m_eof;}
private:
  typedef std::list<lat::InputStream *> Streams; 
  Streams m_streams;
  char *m_buffer;
  int m_posInBuffer;
  int m_lastInBuffer;
  int m_eof;
  const char *m_curString;
  int m_curStringSize;
  int m_bufferSize;
};

class FileReader : public FileOpener
{
public:
  FileReader(const std::string &filename)
    : FileOpener(),
      m_file(openFile(filename))
    { 
      ASSERT(m_file);
      lat::StorageInputStream *storageInput = new lat::StorageInputStream(m_file);
      lat::BufferInputStream *bufferStream = new lat::BufferInputStream(storageInput);
      addStream(storageInput);
      addStream(bufferStream);

      FILE *f = fopen(filename.c_str(), "r"); 
      fread(m_fileHeader, 4, 1, f);
      fclose(f);
    
      if (m_fileHeader[0] == 0x1f 
          && m_fileHeader[1] == 0x8b) 
        addStream(new lat::GZIPInputStream(bufferStream));
      else if (m_fileHeader[3] == 0x04 
               && m_fileHeader[2] == 0x03
               && m_fileHeader[1] == 0x4b
               && m_fileHeader[0] == 0x50) 
        addStream(new lat::ZipInputStream(bufferStream));
      else if (m_fileHeader[0] == 'B' 
               && m_fileHeader[1] == 'Z' 
               && m_fileHeader[2] == 'h') 
        addStream(new lat::BZIPInputStream(bufferStream));
    }
  ~FileReader(void)
    {
      m_file->close();
    }
private:
  static lat::File *openFile(const std::string &filename)
    {
      try 
      {
        lat::File *file = new lat::File(filename);
        return file;
      }
      catch(lat::FileError &e)
      {
        std::cerr << "ERROR: Unable to open file " << filename << " for input." 
                  << std::endl;
        exit(1);
      }
    }
  lat::File *m_file;
  unsigned char m_fileHeader[4];
};

class PathCollection
{
public:
  typedef lat::StringList Paths;
  typedef Paths::const_iterator Iterator;
  PathCollection(const char *variableName)
    {
      char *value = getenv(variableName);
      if (!value)
        return;
      m_paths = lat::StringOps::split(value, ':', lat::StringOps::TrimEmpty);
    }
  
  std::string which (const std::string &name)
    {
      for (Iterator s = m_paths.begin();
           s != m_paths.end();
           s++)
      {
        lat::Filename filename(*s, name);
        if (filename.exists())
          return std::string(filename);
      }
      return "";
    }
  
  Iterator begin(void) { return m_paths.begin(); }
  Iterator end(void) { return m_paths.end(); }  
private:
  Paths m_paths;
};

std::string 
thousands(int64_t value, int leftPadding=0)
{
  // Converts an integer value to a string
  // adding `'` to separate thousands and possibly
  ASSERT(leftPadding >= 0);
  int64_t n = 1; int digitCount = 0;
  std::string result = "";
  bool sign = value >= 0; 

  if (value < 0)
    value = -value;
  if (!value)
    result = "0";
    
  char d[2];
  d[1] = 0;
   
  while ((value / n))
  {
    int digit = (value / n) % 10;
    ASSERT(digit < 10);
    if ((! digitCount) && (n != 1))
    { result = "'" + result; }
    d[0] = static_cast<char>('0'+ static_cast<char>(digit));
    result = std::string(d) + result;
    n *= 10;
    digitCount = (digitCount + 1) % 3;
  }
  
  if (leftPadding)
  {
    ASSERT(leftPadding-digitCount > 0);
    result = std::string("", leftPadding-digitCount) + result;
  }
  return(sign ? "" : "-")  + result;
}

std::string
thousands(double value, int leftPadding, int decimalPositions)
{
  value = round(value * 100.) / 100.;
  decimalPositions += value < 0 ? 1 : 0;
  int padding = leftPadding-decimalPositions;
  std::string result = thousands(int64_t(value), padding > 0 ? padding : 0);
  ASSERT(decimalPositions < 63);
  char buffer[64];
  double decimal = fabs(value-int64_t(value));
  sprintf(buffer+1, "%.2f", decimal);
  buffer[decimalPositions+3] = 0;
  return result + &buffer[2];
}


std::string
toString(int64_t value)
{
  // FIXME: not thread safe... Do we actually care? Probably not.
  static char buffer [1024];
  sprintf(buffer,"%" PRIi64,value);
  return buffer;
}


class AlignedPrinter
{
public:
  AlignedPrinter(int size)
    :m_size(size)
    {}
    
  void operator()(const std::string &n)
    {
      printf("%*s", m_size, n.c_str());
      printf("  ");
      fflush(stdout);
    }
private:
  int m_size;
};

class FractionPrinter
{
public:
  FractionPrinter(int size)
    :m_size(size) 
    {}
  
  void operator()(const std::string &n, const std::string &d)
    {
      printf("%*s", m_size, n.c_str());
      char denBuffer[256];
      sprintf(denBuffer, " / %%-%ds", m_size);
      printf(denBuffer, d.c_str());
    }
  
private:
  int m_size;
};

class PrintIf
{
public:
  PrintIf(int size)
    :m_size(size)
    {}
  
  void operator()(bool condition, const std::string &value)
    {
      if (condition)
        printf("%*s  ", m_size, value.c_str());
    }
private:
  int m_size;
};

class SymbolFilter
{
public:
  SymbolFilter &operator=(const char *symbolName)
    { 
      return this->addFilteredSymbol(symbolName); 
    }
  
  SymbolFilter &operator,(const char *symbolName)
    { 
      return this->addFilteredSymbol(symbolName); 
    }

  SymbolFilter &addFilteredSymbol(const char *symbolName)
    {
      m_symbols.push_back(symbolName); return *this; 
    }
  
  bool contains(const std::string &name)
    {
      bool result = std::find(m_symbols.begin(), m_symbols.end(), name) != m_symbols.end();
      return result; 
    }
  
private:
  typedef std::list<std::string> SymbolNames; 
  SymbolNames m_symbols;
};

#endif
