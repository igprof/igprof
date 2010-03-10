#include "IgProfAnalyse.h"
#include <classlib/utils/DebugAids.h>
#include <classlib/utils/Callback.h>
#include <classlib/utils/Hook.h>
#include <classlib/utils/Error.h>
#include <classlib/utils/Signal.h>
#include <classlib/utils/Regexp.h>
#include <classlib/iobase/File.h>
#include <classlib/iobase/TempFile.h>
#include <classlib/iotools/StorageInputStream.h>
#include <classlib/iotools/BufferInputStream.h>
#include <classlib/iotools/IOChannelOutputStream.h>
#include <iostream>
#include <fstream>
#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <deque>
#include <list>
#include <map>
#include <set>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <cstdio>
#include <cfloat>
#include <iomanip>

#define IGPROF_MAX_DEPTH 1000

void dummy(void) {}

void
dieWithUsage(const char *message = 0)
{
  // The following options
  //
  // * --list-filter / -lf
  // * -f FILTER[, FILTER]
  // * -F/--filter-module [FILE]
  // * --callgrind
  //
  // which where present in the old perl version
  // are either obsolete or not supported at the moment
  // by igprof-analyse. We do not show them in the usage, but
  // we do show a different message if someone uses them.
  if (message)
    std::cerr << message << "\n";

  std::cerr << ("igprof-analyse\n"
                "  {[-r/--report KEY[,KEY]...], --show-pages, --show-partial-pages, --show-locality-metrics}"
                "  [-o/--order ORDER]\n"
                "  [-p/--paths] [-c/--calls] [--value peak|normal]\n"
                "  [-mr/--merge-regexp REGEXP]\n"
                "  [-ml/--merge-libraries REGEXP]\n"
                "  [-nf/--no-filter]\n"
                "  { [-t/--text], [-s/--sqlite], [--top <n>], [--tree] }\n"
                "  [--libs] [--demangle] [--gdb] [-v/--verbose]\n"
                "  [-b/--baseline FILE [--diff-mode]]\n"
                "  [-Mc/--max-count-value <value>] [-mc/--min-count-value <value>]\n"
                "  [-Mf/--max-calls-value <value>] [-mc/--min-calls-value <value>]\n"
                "  [-Ma/--max-average-value <value>] [-ma/--min-average-value <value>]\n"
                "  [--] [FILE]...\n") << std::endl;
  exit(1);
}

float percent(int64_t a, int64_t b)
{
  double value = static_cast<double>(a) / static_cast<double>(b);
  if (value < -1.0)
  {
    std::cerr << "Something is wrong. Invalid percentage value: " << value * 100. << "%" << std::endl;
    exit(1);
  }
  return value * 100.;
}


class SymbolInfo
{
public:
  std::string NAME;
  FileInfo  *FILE;
  int     FILEOFF;
  SymbolInfo(const char *name, FileInfo *file, int fileoff)
    : NAME(name), FILE(file), FILEOFF(fileoff), RANK(-1) {}
  int rank(void) { return RANK; }
  void setRank(int rank) { RANK = rank; }
private:
  int RANK;
};

/** Structure which holds information about a given
    live allocation. This is used to hold
    information about the LK elements found in the
    report.
 */
struct Allocation
{
  uintptr_t address;  // The address of the allocation
  uint64_t  size;     // The size of the allocation
};


/** Structure to hold information about nodes in the
    call tree. */
class NodeInfo
{
public:
  typedef std::vector<NodeInfo *> Nodes;
  typedef std::vector<Allocation> Allocations;
  typedef Nodes::iterator Iterator;

  Nodes CHILDREN;
  Counter COUNTER;
  Allocations allocations;

  NodeInfo()
    : SYMBOL(0), m_reportSymbol(0) {};

  NodeInfo *getChildrenBySymbol(SymbolInfo *symbol)
    {
      for (size_t ni = 0, ne = CHILDREN.size(); ni != ne; ++ni)
      {
        NodeInfo *node = CHILDREN[ni];
        if (node->SYMBOL == symbol)
          return node;

        if (symbol && (node->SYMBOL->NAME == symbol->NAME))
          return node;
      }
      return 0;
    }

  void printDebugInfo(int level=0)
    {
      std::string indent(level*4, ' ');
      std::cerr << indent << "Node: " << this
                << " Symbol name: " << this->symbol()->NAME
                << " File name: " << this->symbol()->FILE->NAME
                << std::endl;
      for (size_t ni = 0, ne = CHILDREN.size(); ni != ne; ++ni)
        CHILDREN[ni]->printDebugInfo(level+1);
    }

  void removeChild(NodeInfo *node) {

    ASSERT(node);
    Nodes::iterator new_end = std::remove_if(CHILDREN.begin(),
                                             CHILDREN.end(),
                                             std::bind2nd(std::equal_to<NodeInfo *>(), node));
    if (new_end != CHILDREN.end())
      CHILDREN.erase(new_end, CHILDREN.end());
  }

  SymbolInfo *symbol(void) const
    {
      return m_reportSymbol ? m_reportSymbol : SYMBOL;
    }

  void reportSymbol(SymbolInfo *reportSymbol)
    {
      m_reportSymbol = reportSymbol;
    }

  SymbolInfo *reportSymbol(void) const
    {
      return m_reportSymbol;
    }
  SymbolInfo *originalSymbol(void) const
    {
      return SYMBOL;
    }
  void setSymbol(SymbolInfo *symbol)
    {
      SYMBOL = symbol;
      m_reportSymbol = 0;
    }
private:
  SymbolInfo *SYMBOL;
  SymbolInfo *m_reportSymbol;
};


class ProfileInfo
{
private:
  struct FilesComparator
  {
    bool operator()(FileInfo *f1, FileInfo *f2) const
      {
        return strcmp(f1->NAME.c_str(), f2->NAME.c_str()) < 0;
      }
  };

public:
  typedef std::set<FileInfo *, FilesComparator> Files;
  typedef std::vector<SymbolInfo *> Syms;
  typedef std::vector<NodeInfo *> Nodes;
  typedef std::vector<int> Counts;
  typedef std::map<std::string, Counts> CountsMap;
  typedef std::map<std::string, std::string> Freqs;
  typedef std::map<std::string, std::string> LeaksMap;
  typedef std::map<std::string, SymbolInfo*> SymCacheByFile;
  typedef std::map<std::string, SymbolInfo*> SymCacheByName;
  typedef std::set<SymbolInfo*> SymCache;

  ProfileInfo(void)
    {
      FileInfo *unknownFile = new FileInfo("<unknown>", false);
      SymbolInfo *spontaneousSym = new SymbolInfo("<spontaneous>", unknownFile, 0);
      m_spontaneous = new NodeInfo();
      m_spontaneous->setSymbol(spontaneousSym);
      m_files.insert(unknownFile);
      m_syms.push_back(spontaneousSym);
      m_nodes.push_back(m_spontaneous);
    };

  Files & files(void) { return m_files; }
  Syms & syms(void) { return m_syms; }
  Nodes & nodes(void) { return m_nodes; }
  NodeInfo *spontaneous(void) { return m_spontaneous; }
  SymCacheByFile &symcacheByFile(void) { return m_symcacheFile; }
  SymCache &symcache(void) { return m_symcache; }
private:
  Files m_files;
  Syms m_syms;
  Nodes m_nodes;
  LeaksMap m_leaks;
  SymCacheByFile m_symcacheFile;
  SymCache m_symcache;
  NodeInfo  *m_spontaneous;
};

class IgProfFilter;

/** Structure that hold information
    about the regular expressions to apply.
  */
struct RegexpSpec
{
  // The actual regular expression to match.
  std::string  re;
  // The replacement string.
  std::string  with;
};

class Configuration
{
public:
  enum OutputType {
    TEXT=0,
    XML=1,
    HTML=2,
    SQLITE=3
  };
  enum Ordering {
    DESCENDING=-1,
    ASCENDING=1
  };

  Configuration(void);

  void setShowLib(bool value) { m_showLib = value;}
  bool showLib(void) { return m_showLib; }

  void setCallgrind(bool value)  { m_callgrind = value ? 1 : 0; }
  bool callgrind(void) { return m_callgrind == 1; }
  bool isCallgrindDefined(void) { return m_callgrind != -1; }

  void setShowCalls(bool value) { m_showCalls = value ? 1 : 0; }
  bool isShowCallsDefined(void) { return m_showCalls != -1; }
  bool showCalls(void) { return m_showCalls == 1; }

  void setDoDemangle(bool value) { m_doDemangle = value;}
  bool doDemangle(void) { return m_doDemangle; }

  void setShowPaths(bool value)  { m_showPaths = value;}
  bool showPaths(void) { return m_showPaths; }

  void setVerbose(bool value) { m_verbose = value;}
  bool verbose(void) { return m_verbose; }

  void setOutputType(enum OutputType value) { m_outputType = value; }
  OutputType outputType(void) { return m_outputType; }

  void setOrdering(enum Ordering value) { m_ordering = value; }
  Ordering ordering(void) { return m_ordering; }

  void setNormalValue(bool value) { m_normalValue = value; }
  bool normalValue(void) { return m_normalValue; }

  void setTickPeriod(float value) { m_tickPeriod = value; }
  float tickPeriod(void) {return m_tickPeriod; }

  void setMergeLibraries(bool value) { m_mergeLibraries = value; }
  bool mergeLibraries(void) { return m_mergeLibraries; }

  void setBaseline(const std::string &baseline)
    {
      m_baseline = baseline;
    }

  const std::string &baseline(void)
    {
      return m_baseline;
    }

  void setDiffMode(bool value)
    {
      m_diffMode = value;
    }

  bool diffMode(void)
    {
      return m_diffMode;
    }

  bool hasHitFilter(void)
    {
      return minCountValue > 0
        || maxCountValue > 0
        || minCallsValue > 0
        || maxCallsValue > 0
        || minAverageValue > 0
        || maxAverageValue > 0;
    }

private:
  std::string m_key;
  OutputType  m_outputType;
  Ordering  m_ordering;
  bool m_showLib;
  int m_callgrind;
  bool m_doDemangle;
  bool m_showPaths;
  int m_showCalls;
  bool m_verbose;
  bool m_normalValue;
  float m_tickPeriod;
  bool m_mergeLibraries;
  std::string m_baseline;
  bool m_diffMode;
public:
  int64_t minCountValue;
  int64_t maxCountValue;
  int64_t minCallsValue;
  int64_t maxCallsValue;
  int64_t minAverageValue;
  int64_t maxAverageValue;
  bool    tree;
  bool    useGdb;
  bool    dumpAllocations;
  std::vector<RegexpSpec>   regexps;
};

Configuration::Configuration()
  :m_outputType(Configuration::TEXT),
   m_ordering(Configuration::ASCENDING),
   m_showLib(false),
   m_callgrind(-1),
   m_doDemangle(false),
   m_showPaths(false),
   m_showCalls(-1),
   m_verbose(false),
   m_normalValue(true),
   m_tickPeriod(0.01),
   m_diffMode(false),
   minCountValue(-1),
   maxCountValue(-1),
   minCallsValue(-1),
   maxCallsValue(-1),
   minAverageValue(-1),
   maxAverageValue(-1)
{}

class StackTraceFilter
{
public:
  virtual ~StackTraceFilter();
  virtual void filter(SymbolInfo *symbol,
                      int64_t &counter,
                      int64_t &freq) = 0;
};

StackTraceFilter::~StackTraceFilter() {}

class ZeroFilter : public StackTraceFilter
{
public:
  virtual void filter(SymbolInfo *, int64_t &counter, int64_t &freq)
    {
      counter=0; freq = 0;
    }
};

class BaseLineFilter : public StackTraceFilter
{
public:
  virtual void filter(SymbolInfo *, int64_t &counter, int64_t &freq)
    {
      counter=-counter; freq = -freq;
    }
};

// Filters the incoming stacktraces by the size
// of their counters(either absolute total, average, or
// by the number of calls to a given stacktrace).
// If the counter value is not within limits,
// the the stacktrace is not accumulated in the
// tree.
class HitFilter : public StackTraceFilter
{
public:
  HitFilter(Configuration &config)
    :m_minValue(config.minCountValue), m_maxValue(config.maxCountValue),
     m_minFreq(config.minCallsValue), m_maxFreq(config.maxCallsValue),
     m_minAvg(config.minAverageValue), m_maxAvg(config.maxAverageValue)
    {}

  virtual void filter(SymbolInfo *, int64_t &counter, int64_t &freq)
    {
      if (m_minValue > 0 && counter < m_minValue)
      {
        counter = 0; freq = 0;
        return;
      }

      if (m_maxValue > 0 && counter > m_maxValue)
      {
        counter = 0; freq = 0;
        return;
      }

      if (m_minFreq > 0 && freq < m_minFreq)
      {
        counter = 0; freq = 0;
        return;
      }

      if (m_maxFreq > 0 && freq > m_maxFreq)
      {
        counter = 0; freq = 0;
        return;
      }

      if (m_minAvg > 0 && freq && (counter/freq < m_minAvg))
      {
        counter = 0; freq = 0;
        return;
      }

      if (m_maxAvg > 0 && freq && (counter/freq > m_maxAvg))
      {
        counter = 0; freq = 0;
        return;
      }
    }

private:
  int64_t m_minValue;
  int64_t m_maxValue;
  int64_t m_minFreq;
  int64_t m_maxFreq;
  int64_t m_minAvg;
  int64_t m_maxAvg;
};

class TreeMapBuilderFilter;
class FlatInfo;

class IgProfFilter
{
public:
  enum FilterType
  {
    PRE = 1,
    POST = 2,
    BOTH = 3
  };

  virtual ~IgProfFilter(void) {}
  virtual std::string name(void) const = 0;
  virtual enum FilterType type(void) const = 0;
  virtual void pre(NodeInfo *, NodeInfo *) {};
  virtual void post(NodeInfo *, NodeInfo *) {};
};

/** Merges @a node and all its children to @a parent.

    We iterate on all the children of node.
    If parent does not have any children with the same name, we simply add it
    to the list of children.
    If parent already has a children with the same symbol name
    we merge the counters and call mergeToNode for every one of the children.
    Finally if node is among the children of parent, remove it from them.

    @a node is the node to be removed.

    @a parent is the parent of that node, which will get all the
     children of node.

    @a isMax whether or not peak value has to be taken for the counts,
     rather than accumulating them.
*/
void mergeToNode(NodeInfo *parent, NodeInfo *node, bool isMax)
{
  // We iterate on all the children of node. [1]
  // * If parent does not have any children with the same name, we simply add it
  //   to the list of children. [2]
  // * If parent already has a children with the same symbol name
  //   we merge the counters and call mergeToNode for every one of the
  //   children. [3]
  // Finally if node is among the children of parent we copy all
  // its allocations to it and remove the node from the children list. [4]

  // [1]
  for (size_t i = 0, e = node->CHILDREN.size(); i != e; i++)
  {
    NodeInfo *nodeChild = node->CHILDREN[i];
    ASSERT(nodeChild);
    if (!nodeChild->symbol())
      continue;
    NodeInfo *parentChild = parent->getChildrenBySymbol(nodeChild->symbol());
    if (!parentChild)
    {
      parent->CHILDREN.push_back(nodeChild);
      continue;
    }

    ASSERT(parentChild != nodeChild);
    parentChild->COUNTER.add(nodeChild->COUNTER, isMax);
    mergeToNode(parentChild, nodeChild, isMax);
  }

  if (node == parent->getChildrenBySymbol(node->symbol()))
  {
    parent->allocations.insert(parent->allocations.end(), node->allocations.begin(), node->allocations.end());

    NodeInfo::Nodes::iterator new_end = std::remove_if(parent->CHILDREN.begin(),
                                                       parent->CHILDREN.end(),
                                                       std::bind2nd(std::equal_to<NodeInfo *>(), node));
    if (new_end != parent->CHILDREN.end())
      parent->CHILDREN.erase(new_end, parent->CHILDREN.end());
  }
}

class RemoveIgProfFilter : public IgProfFilter
{
public:
  RemoveIgProfFilter(bool isMax)
  : m_isMax(isMax)
  {}

  virtual void post(NodeInfo *parent,
                    NodeInfo *node)
    {
      if (!parent)
        return;

      ASSERT(node);
      ASSERT(node->originalSymbol());
      ASSERT(node->originalSymbol()->FILE);

      if (strstr(node->originalSymbol()->FILE->NAME.c_str(), "IgProf.")
          || strstr(node->originalSymbol()->FILE->NAME.c_str(), "IgHook."))
      {
        mergeToNode(parent, node, m_isMax);
      }
    }

  virtual std::string name(void) const { return "igprof remover"; }
  virtual enum FilterType type(void) const { return POST; }
private:
  bool m_isMax;
};

/** Removes any malloc related symbol from the calltree
    adding their contribution to the nearest parent.
 */
class MallocFilter : public IgProfFilter
{
public:
  MallocFilter(bool isMax)
  :m_isMax(isMax)
  {
    m_filter = "malloc", "calloc", "realloc", "memalign", "posix_memalign",
               "valloc", "zmalloc", "zcalloc", "zrealloc", "_Znwj",
               "_Znaj", "_Znam";
  }

  virtual void post(NodeInfo *parent, NodeInfo *node)
    {
      ASSERT(node);
      ASSERT(node->symbol());
      ASSERT(m_filter.contains(std::string("_Znaj")));
      if (!parent)
        return;

      if (! m_filter.contains(node->symbol()->NAME))
        return;

      parent->COUNTER.add(node->COUNTER, m_isMax);
      parent->removeChild(node);
    }

  virtual std::string name(void) const { return "malloc"; }
  virtual enum FilterType type(void) const { return POST; }

private:
  SymbolFilter m_filter;
  bool m_isMax;
};

class IgProfGccPoolAllocFilter : public IgProfFilter
{
public:
  IgProfGccPoolAllocFilter(void)
    {
      m_filter = "_ZNSt24__default_alloc_templateILb1ELi0EE14_S_chunk_allocEjRi",
                 "_ZNSt24__default_alloc_templateILb1ELi0EE9_S_refillEj",
                 "_ZNSt24__default_alloc_templateILb1ELi0EE8allocateEj";
    }

  virtual void post(NodeInfo *parent, NodeInfo *node)
    {
      if (! m_filter.contains(node->symbol()->NAME))
        return;
      parent->removeChild(node);
    }
  virtual std::string name(void) const { return "gcc_pool_alloc"; }
  virtual enum FilterType type(void) const { return POST; }
private:
  SymbolFilter m_filter;
};

class IgProfAnalyzerApplication
{
  typedef std::vector<FlatInfo *> FlatVector;
public:
  typedef std::list <std::string> ArgsList;

  IgProfAnalyzerApplication(int argc, const char **argv);

  void run(void);
  void parseArgs(const ArgsList &args);
  void readDump(ProfileInfo &prof, const std::string& filename, StackTraceFilter *filter = 0);
  void analyse(ProfileInfo &prof, TreeMapBuilderFilter *baselineBuilder);
  void generateFlatReport(ProfileInfo &prof,
                          TreeMapBuilderFilter *callTreeBuilder,
                          TreeMapBuilderFilter *baselineBuilder,
                          FlatVector &sorted);
  void callgrind(ProfileInfo &prof);
  void topN(ProfileInfo &prof);
  void tree(ProfileInfo &prof);
  void dumpAllocations(ProfileInfo &prof);
  void prepdata(ProfileInfo &prof);

  /** Sets the mnemonic name of the counter is to be used as a key.

      Update the m_keyMax and m_isPerfTick to match the kind of
      counter specified.

      It also sets up the default filters (unless --no-filter / -nf is
      specified).
    */
  void setKey(const std::string &value)
  {
    m_key = value;

    if (strstr(m_key.c_str(), "_MAX") == m_key.c_str() + m_key.size() - 4)
      m_keyMax = true;
    if (m_key == "PERF_TICKS")
      m_isPerfTicks = true;

    if (m_disableFilters)
      return;

    m_filters.push_back(new RemoveIgProfFilter(m_keyMax));

    if (!m_filters.empty() && !memcmp(m_key.c_str(), "MEM_", 4))
      m_filters.push_back(new MallocFilter(m_keyMax));
    if (!m_filters.empty() && m_key == "MEM_LIVE")
      m_filters.push_back(new IgProfGccPoolAllocFilter());
  }

private:
  void verboseMessage(const char *msg, const char *arg = 0);
  Configuration *               m_config;
  int                           m_argc;
  const char                    **m_argv;
  std::vector<std::string>      m_inputFiles;
  std::vector<RegexpSpec>       m_regexps;
  std::vector<IgProfFilter *>   m_filters;
  std::deque<NodeInfo>          m_nodesStorage;
  std::string                   m_key;
  bool                          m_isPerfTicks;
  bool                          m_keyMax;
  bool                          m_disableFilters;
  bool                          m_showPartialPages;
  bool                          m_showPages;
  bool                          m_showLocalityMetrics;
  size_t                        m_topN;
};


IgProfAnalyzerApplication::IgProfAnalyzerApplication(int argc, const char **argv)
  :m_config(new Configuration()),
   m_argc(argc),
   m_argv(argv),
   m_disableFilters(false),
   m_showPartialPages(false),
   m_showPages(false),
   m_showLocalityMetrics(false),
   m_topN(0)
{}

float
parseHeaders(const std::string &headerLine)
{
  lat::Regexp matchHeader("^P=\\(.*T=(.*)\\)");
  lat::RegexpMatch match;

  if (!matchHeader.match(headerLine, 0, 0, &match))
  {
    std::cerr << "\nThis does not look like an igprof profile stats:\n  "
              << headerLine << std::endl;
    exit(1);
  }
  ASSERT(match.numCaptures() == 1);
  std::string result = match.matchString(headerLine.c_str(), 1);
  return atof(result.c_str());
}

static int s_counter = 0;

void
printProgress(void)
{
  s_counter = (s_counter + 1) % 100000;
  if (! s_counter)
    std::cerr << "o";
}

int
index(const std::string &s, char c)
{
  int pos = 0;
  for (std::string::const_iterator i = s.begin();
       i != s.end();
       i++)
  {
    if (*i == c)
      return pos;
    pos++;
  }
  return -1;
}

class Position
{
public:
  unsigned int operator()(void) { return m_pos; }
  void operator()(unsigned int newPos) { m_pos = newPos; }
private:
  unsigned int m_pos;
};



std::string
symlookup(FileInfo *file, int fileoff, const std::string& symname, bool useGdb)
{
  // This helper function beautifies a symbol name in the following fashion:
  // * If the useGdb option is true, it uses the symbol offset to look up,
  //   via nm, the closest matching symbol.
  // * If the useGdb option is not given and the symbol starts with @?
  // * If any of the above match, it simply
  ASSERT(file);
  std::string result = symname;
  if ((symname.size() > 1 && symname[0] == '@' && symname[1] == '?') && file->NAME.size() && (fileoff > 0))
  {
    char buffer[1024];
    if (file->NAME == "<dynamically generated>" )
    {
      sprintf(buffer, "@?0x%x{<dynamically-generated>}", fileoff);
      result = std::string() + buffer;
    }
    else
    {
      sprintf(buffer, "+%d}",fileoff);
      result = std::string("@{")
               + lat::Filename(file->NAME).asFile().nondirectory().name()
               + buffer;
    }
  }

  if (useGdb && lat::Filename(file->NAME).isRegular())
  {
    const char *name = file->symbolByOffset(fileoff);
    if (name) return name;
  }
  return result;
}

void
printSyntaxError(const std::string &text,
                 const std::string &filename,
                 int line, int position)
{
  std::cerr << filename << ":" << "line " << line
            << ", character " << position <<" unexpected input:\n"
            << text << "\n"
            << std::string(position, ' ') << "^\n"
            << std::endl;
}

// A simple filter which reports the number of allocations
// required to allocate the amount of memory that fits on
// one page. This is a rough indication of the actual
// fragmentation and has the advantage that the greater the number is
// the more fragmented the memory is likely to be.
//
// FIXME: a more accurate indication of fragmentation is
//        to find out how many pages were actually touched
//        by all the allocations done in a given node.
//        This is much more complicated because we would
//        have to do the binning of all the allocations
//        to see how many of them share the same page
//        and how many don't.
class AllocationsPerPage : public IgProfFilter
{
public:
  virtual void post(NodeInfo *,
                    NodeInfo *node)
    {
      ASSERT(node);
      Counter &counter = node->COUNTER;
      if (counter.freq != 0)
        counter.cnt = 4096 * counter.freq / counter.cnt;
    }
  virtual std::string name(void) const { return "average allocation size"; }
  virtual enum FilterType type(void) const { return POST; }
};

/** This filter accumulates all the counters so that
    parents cumulative counts / freq contain all
    include those of all their children.

    On the way down (pre) the filter sets all the cumulative
    values to the counts for the node itself,
    while on the way up (post) the counts of a child are
    added properly to the parent.
  */
class AddCumulativeInfoFilter : public IgProfFilter
{
public:
  AddCumulativeInfoFilter(bool isMax)
    : m_isMax(isMax)
    {}

  virtual void pre(NodeInfo *, NodeInfo *node)
    {
      ASSERT(node);
      Counter &counter = node->COUNTER;
      counter.cfreq = counter.freq;
      counter.ccnt = counter.cnt;
    }

  virtual void post(NodeInfo *parent, NodeInfo *node)
    {
      ASSERT(node);
      if (!parent)
        return;
      parent->COUNTER.accumulate(node->COUNTER, m_isMax);
    }
  virtual std::string name(void) const { return "cumulative info"; }
  virtual enum FilterType type(void) const { return BOTH; }

private:
  bool m_isMax;
};

/** Simple tree consistency class that makes sure that there
    is only one node (the root) without parent.
*/
class CheckTreeConsistencyFilter : public IgProfFilter
{
public:
  CheckTreeConsistencyFilter()
    :m_noParentCount(0)
    {}

  virtual void post(NodeInfo *parent,
                    NodeInfo *)
    {
      if (!parent)
      {
        m_noParentCount++;
        ASSERT(m_noParentCount == 1);
      }
    }
  virtual std::string name(void) const { return "Check consitency of tree"; }
  virtual enum FilterType type(void) const { return POST; }
private:
  int m_noParentCount;
};

/** Prints the whole calltree as a tree (i.e. indenting children according to their
    level) */
class PrintTreeFilter : public IgProfFilter
{
public:
  PrintTreeFilter(void)
    {}

  virtual void pre(NodeInfo *parent, NodeInfo *node)
    {
      m_parentStack.erase(std::find(m_parentStack.begin(), m_parentStack.end(), parent), m_parentStack.end());
      m_parentStack.push_back(parent);

      std::cerr << std::string(2*(m_parentStack.size()-1), ' ') << node->symbol()->NAME;
      Counter &counter = node->COUNTER;
      std::cerr << " C" << "[" << counter.cnt << ", "
                << counter.freq << ", "
                << counter.ccnt << ", "
                << counter.cfreq << "]";
      std::cerr << std::endl;
    }
  virtual std::string name(void) const { return "Printing tree structure"; }
  virtual enum FilterType type(void) const {return PRE; }
private:
  std::vector<NodeInfo *> m_parentStack;
};

/** Filter which dumps per node allocation information
    in a file.
 */
class DumpAllocationsFilter : public IgProfFilter
{
public:
  DumpAllocationsFilter(std::ostream &out)
  :m_out(out)
  {
  }

  /** While traversing down the tree, print out all the
      allocations and keep track of the symbols that we
      find.
    */
  virtual void pre(NodeInfo *, NodeInfo *node)
  {
    for (size_t i = 0, e = node->allocations.size(); i != e; ++i)
    {
      Allocation &a = node->allocations[i];
      m_out << node << "," << node->symbol() << ","
            << std::hex << a.address << "," << a.size << "\n";
    }
  }

  virtual std::string name() const { return "Dump Allocations"; }
  virtual FilterType type() const { return PRE; }
private:
  typedef std::set<SymbolInfo *> Symbols;
  std::ostream            &m_out;
  Symbols                 m_symbols;
};

class CollapsingFilter : public IgProfFilter
{
public:
  CollapsingFilter(bool isMax)
  : m_isMax(isMax)
  {}

  // On the way down add extra nodes for libraries.
  virtual void pre(NodeInfo *parent, NodeInfo *node)
    {
      if (!parent)
        return;
      ASSERT(parent);
      ASSERT(node);
      ASSERT(node->symbol());
      ASSERT(node->symbol()->FILE);

      std::deque<NodeInfo *> todos;
      todos.insert(todos.begin(), node->CHILDREN.begin(), node->CHILDREN.end());
      node->CHILDREN.clear();
      convertSymbol(node);

      while (!todos.empty())
      {
        NodeInfo *todo = todos.front();
        todos.pop_front();

        // Obtain a SymbolInfo with the filename, rather than the actual symbol name.
        convertSymbol(todo);

        // * If the parent has the same SymbolInfo, we merge the node to the parent
        // and add its children to the todo list.
        // * If there is already a child of the parent with the same symbol info,
        //   we merge with it.
        // * Otherwise we simply re-add the node.
        if (todo->symbol() == node->symbol())
        {
          todos.insert(todos.end(), todo->CHILDREN.begin(), todo->CHILDREN.end());
          node->COUNTER.add(todo->COUNTER, m_isMax);
        }
        else if (NodeInfo *same = node->getChildrenBySymbol(todo->symbol()))
        {
          same->CHILDREN.insert(same->CHILDREN.end(), todo->CHILDREN.begin(), todo->CHILDREN.end());
          same->COUNTER.add(todo->COUNTER, m_isMax);
        }
        else
          node->CHILDREN.push_back(todo);
      }
    }
  virtual enum FilterType type(void) const {return PRE; }
protected:
  virtual void convertSymbol(NodeInfo *node) = 0;
private:
  bool m_isMax;
};

class UseFileNamesFilter : public CollapsingFilter
{
  typedef std::map<std::string, SymbolInfo *> FilenameSymbols;
public:
  UseFileNamesFilter(bool isMax)
  :CollapsingFilter(isMax)
  {}
  virtual std::string name(void) const { return "unify nodes by library."; }
  virtual enum FilterType type(void) const {return PRE; }
protected:
  void convertSymbol(NodeInfo *node)
    {
      FilenameSymbols::iterator i = m_filesAsSymbols.find(node->symbol()->FILE->NAME);
      SymbolInfo *fileInfo;
      if (i == m_filesAsSymbols.end())
      {
        fileInfo = new SymbolInfo(node->symbol()->FILE->NAME.c_str(),
                                  node->symbol()->FILE, 0);
        m_filesAsSymbols.insert(FilenameSymbols::value_type(node->symbol()->FILE->NAME,
                                                            fileInfo));
      }
      else
        fileInfo = i->second;
      node->setSymbol(fileInfo);
    }
private:
  FilenameSymbols m_filesAsSymbols;
};

class RegexpFilter : public CollapsingFilter
{
  struct Regexp
  {
    lat::Regexp   *re;
    std::string   with;
  };

  typedef std::map<std::string, SymbolInfo *> CollapsedSymbols;
public:
  RegexpFilter(const std::vector<RegexpSpec> &specs, bool isMax)
  :CollapsingFilter(isMax)
  {
    for (size_t i = 0, e = specs.size(); i != e; i++)
    {
      m_regexps.resize(m_regexps.size() + 1);
      Regexp &regexp = m_regexps.back();
      regexp.re = new lat::Regexp(specs[i].re);
      regexp.with = specs[i].with;
    }
  }

  virtual std::string name(void) const { return "collapsing nodes using regular expression."; }
  virtual enum FilterType type(void) const { return PRE; }

protected:
  /** Applies the text substitution to the symbol
      belonging to @a node or the filename where the @a node
      is found.
   */
  void convertSymbol(NodeInfo *node)
    {
      if (m_symbols.find(node->symbol()->NAME) != m_symbols.end())
        return;

      std::string translatedName;
      std::string mutantString;

      for (size_t i = 0, e = m_regexps.size(); i != e; i++)
      {
        Regexp &regexp = m_regexps[i];

        if (regexp.re->match(node->symbol()->NAME))
          mutantString = node->symbol()->NAME;
        else if (node->symbol()->FILE && regexp.re->match(node->symbol()->FILE->NAME))
          mutantString = node->symbol()->FILE->NAME;
        else
          continue;

        translatedName = lat::StringOps::replace(mutantString, *(regexp.re), regexp.with);

        CollapsedSymbols::iterator csi = m_symbols.find(translatedName);
        if (csi != m_symbols.end())
          node->setSymbol(csi->second);

        SymbolInfo *newInfo = new SymbolInfo(translatedName.c_str(),
                                             node->symbol()->FILE, 0);
        m_symbols.insert(CollapsedSymbols::value_type(translatedName,
                                                        newInfo));
        node->setSymbol(newInfo);

        break;
      }
    }
  CollapsedSymbols m_symbols;
private:
  std::vector<Regexp> m_regexps;
};

/** Filter to merge use by C++ std namespace entities to parents.
 */
class RemoveStdFilter : public IgProfFilter
{
public:
  RemoveStdFilter(bool isMax)
  :m_isMax(isMax)
  {}

  virtual void post(NodeInfo *parent,
                    NodeInfo *node)
    {
      if (!parent)
        return;
      ASSERT(node);
      ASSERT(node->originalSymbol());
      // Check if the symbol refers to a definition in the c++ "std" namespace.
      const char *symbolName = node->originalSymbol()->NAME.c_str();

      if (*symbolName++ != '_' || *symbolName++ != 'Z')
        return;
      if (strncmp(symbolName, "NSt", 3) || strncmp(symbolName, "St", 2))
        return;

      // Yes it was.  Squash resource usage to the caller and hide this
      // function from the call tree.(Note that the std entry may end
      // up calling something in the user space again, so we don't want
      // to lose that information.)
      std::cerr << "Symbol " << node->originalSymbol()->NAME << " is "
                << " in " << node->originalSymbol()->FILE->NAME
                << ". Merging." << std::endl;
      mergeToNode(parent, node, m_isMax);
    }
  virtual std::string name(void) const { return "remove std"; }
  virtual enum FilterType type(void) const { return POST; }
private:
  bool m_isMax;
};


class CallInfo
{
public:
  int64_t VALUES[3];
  SymbolInfo *SYMBOL;

  CallInfo(SymbolInfo *symbol)
    :SYMBOL(symbol)
    {
      memset(VALUES, 0, 3*sizeof(int64_t));
    }
};

template<class T>
struct CompareBySymbol
{
  bool operator()(T *a, T *b) const
    {
      return a->SYMBOL < b->SYMBOL;
    }
};

class FlatInfo;
typedef std::map<SymbolInfo *, FlatInfo *> FlatInfoMap;

class FlatInfo
{
public:
  typedef std::set<CallInfo*, CompareBySymbol<CallInfo> > Calls;
  typedef std::set<SymbolInfo *> Callers;

  CallInfo *getCallee(SymbolInfo *symbol, bool create=false)
    {
      static CallInfo dummy(0);
      ASSERT(symbol);
      dummy.SYMBOL = symbol;
      Calls::const_iterator i = CALLS.find(&dummy);
      if (i != CALLS.end())
        return *i;
      if (!create)
        return 0;

      CallInfo *callInfo = new CallInfo(symbol);
      this->CALLS.insert(callInfo);
      return callInfo;
    }

  static FlatInfo *getInMap(FlatInfoMap *flatMap, SymbolInfo *sym, bool create=true)
    {
      FlatInfoMap::iterator i = flatMap->find(sym);
      if (i != flatMap->end())
        return i->second;

      if (!create)
        return 0;

      FlatInfo *result = new FlatInfo(sym);
      flatMap->insert(FlatInfoMap::value_type(sym, result));
      return result;
    }

  std::string filename(void)
    {
      ASSERT(SYMBOL);
      ASSERT(SYMBOL->FILE);
      return SYMBOL->FILE->NAME;
    }

  const char *name(void)
    {
      ASSERT(SYMBOL);
      return SYMBOL->NAME.c_str();
    }

  Callers CALLERS;
  Calls CALLS;
  SymbolInfo *SYMBOL;
  int DEPTH;
  int rank(void) {
    ASSERT(SYMBOL);
    return SYMBOL->rank();
  }
  void setRank(int rank) {
    ASSERT(SYMBOL);
    SYMBOL->setRank(rank);
  }

  int64_t SELF_KEY[3];
  int64_t CUM_KEY[3];
protected:
  FlatInfo(SymbolInfo *symbol)
    : SYMBOL(symbol), DEPTH(-1) {
    memset(SELF_KEY, 0, 3*sizeof(int64_t));
    memset(CUM_KEY, 0, 3*sizeof(int64_t));
  }
};

class SymbolInfoFactory
{
public:
  typedef std::map<std::string, SymbolInfo *> SymbolsByName;

  SymbolInfoFactory(ProfileInfo *prof, bool useGdb)
    :m_prof(prof), m_useGdb(useGdb)
    {}

  SymbolInfo *getSymbol(unsigned int id)
    {
      ASSERT( id <= m_symbols.size());
      return m_symbols[id];
    }

  FileInfo *getFile(unsigned int id)
    {
      ASSERT(id <= m_files.size());
      return m_files[id];
    }

  FileInfo *createFileInfo(const std::string &origname, unsigned int fileid)
    {

      static PathCollection paths("PATH");
      if ((m_files.size() >= fileid + 1)  && m_files[fileid] == 0){
        std::cerr << "Error in igprof input file." << std::endl;
        exit(1);
      }
      // FIXME: die if exists $filebyid{$1};
      std::string absname = origname;
      if (index(origname, '/') == -1)
        absname = paths.which(origname);

      absname = lat::Filename(absname).truename();
      // TODO:
      // $absname =(abs_path($origname) || $origname)
      //     if length($origname);
      FilesByName::iterator fileIter = m_namedFiles.find(absname);
      if (fileIter != m_namedFiles.end())
        return fileIter->second;
      else
      {
        FileInfo *file;

        if (lat::Filename(absname).isDirectory() == true)
          file = new FileInfo("<dynamically generated>", false);
        else
          file = new FileInfo(absname, m_useGdb);

        m_namedFiles.insert(FilesByName::value_type(absname, file));
        int oldsize = m_files.size();
        int missingSize = fileid + 1 - oldsize;
        if (missingSize > 0)
        {
          m_files.resize(fileid + 1);
          for (int i = oldsize; i < oldsize + missingSize; i++)
            ASSERT(m_files[i] == 0);
        }
        m_files[fileid] = file;
        return file;
      }
    }


  SymbolInfo *createSymbolInfo(const std::string &line, unsigned int symid,
                               Position &pos, int lineCount)
    {
      // Regular expressions matching the file and symbolname information.
      static lat::Regexp fRE("F(\\d+)\\+(-?\\d+) N=\\((.*?)\\)\\)\\+\\d+\\s*");
      static lat::Regexp fWithFilenameRE("F(\\d+)=\\((.*?)\\)\\+(-?\\d+) N=\\((.*?)\\)\\)\\+\\d+\\s*");
      static lat::RegexpMatch match;

      FileInfo *file = 0;
      std::string symname;
      unsigned int fileoff;

      match.reset();

      if (fRE.match(line, pos(), 0, &match))
      {
        IntConverter getIntMatch(line, &match);
        fileoff = getIntMatch(2);
        symname = match.matchString(line, 3);
        int fileId = getIntMatch(1);
        file = getFile(fileId);
        ASSERT(file);
      }
      else if (fWithFilenameRE.match(line, pos(), 0, &match))
      {
        IntConverter getIntMatch(line, &match);
        fileoff = getIntMatch(3);
        symname = match.matchString(line, 4);
        file = createFileInfo(match.matchString(line, 2),
                              getIntMatch(1));
        ASSERT(file);
      }
      else
      {
        std::string fn = file ? file->NAME : "Unknown";
        printSyntaxError(line, fn.c_str(), lineCount, pos());
        exit (1);
      }

      pos(match.matchEnd());

      symname = symlookup(file, fileoff, symname, m_useGdb);

      SymbolInfoFactory::SymbolsByName::iterator symiter = namedSymbols().find(symname);

      if (symiter != namedSymbols().end())
      {
        ASSERT(symiter->second);
        if (m_symbols.size() < symid+1) {
          m_symbols.resize(symid+1);
        }
        m_symbols[symid] = symiter->second;
        ASSERT(getSymbol(symid) == symiter->second);
        return symiter->second;
      }

      SymbolInfo *sym = new SymbolInfo(symname.c_str(), file, fileoff);
      namedSymbols().insert(SymbolInfoFactory::SymbolsByName::value_type(symname, sym));
      ASSERT(symid >= m_symbols.size());
      m_symbols.resize(symid + 1);
      m_symbols[symid] = sym;
      return sym;
    }


  static SymbolsByName &namedSymbols(void)
    {
      static SymbolsByName s_namedSymbols;
      return s_namedSymbols;
    }

private:
  typedef std::vector<FileInfo *> Files;
  typedef std::map<std::string, FileInfo *> FilesByName;
  typedef std::vector<SymbolInfo *> Symbols;
  Files m_files;
  Symbols m_symbols;
  FilesByName m_namedFiles;
  ProfileInfo *m_prof;
  bool m_useGdb;
};

struct SuffixOps
{
  static void splitSuffix(const std::string &fullSymbol,
                          std::string &oldSymbol,
                          std::string &suffix)
    {
      size_t tickPos = fullSymbol.rfind("'");
      if (tickPos == std::string::npos)
      {
        oldSymbol = fullSymbol;
        suffix = "";
        return;
      }
      ASSERT(tickPos < fullSymbol.size());
      oldSymbol.assign(fullSymbol.c_str(), tickPos - 1);
      suffix.assign(fullSymbol.c_str() + tickPos);
    }

  static std::string removeSuffix(const std::string &fullSymbol)
    {
      size_t tickPos = fullSymbol.rfind("'");
      if (tickPos == std::string::npos)
        return fullSymbol;
      ASSERT(tickPos < fullSymbol.size());
      return std::string(fullSymbol.c_str(), tickPos - 1);
    }
};

class MassifTreeBuilder : public IgProfFilter
{
public:
  MassifTreeBuilder(Configuration *)
  :m_indent(0),
   m_totals(0),
   m_sorter(false),
   m_reverseSorter(true)
  {
  }

  virtual void pre(NodeInfo *parent, NodeInfo *node)
  {
    std::sort(node->CHILDREN.begin(), node->CHILDREN.end(), m_reverseSorter);

    Counter &nodeCounter = node->COUNTER;

    float pct = 0;
    if (!parent)
      m_totals = nodeCounter.ccnt;

    pct = percent(nodeCounter.ccnt, m_totals);

    // Determine which children are above threshold.
    // Sum up the contribution of those below threshold.
    // FIXME: Add a new node called "others" to the list
    //        with the aggregated sum.
    int lastPrinted = -1;
    float others = 0.;
    for (size_t i = 0, e = node->CHILDREN.size(); i != e; i++)
    {
      Counter &childCounter = node->CHILDREN[i]->COUNTER;
      float childPct = percent(childCounter.ccnt, m_totals);
      if ((childPct < 1. && pct < 1.) || childPct < 0.1)
        others += childPct;
      else
        lastPrinted++;
    }

    if ((size_t)(lastPrinted + 1) != node->CHILDREN.size())
      node->CHILDREN.resize(lastPrinted + 1);

    std::sort(node->CHILDREN.begin(), node->CHILDREN.end(), m_sorter);

    if (m_kids.size() <= m_indent)
      m_kids.resize(m_indent+1);

    m_kids[m_indent] = node->CHILDREN.size();

    for (int i = 0, e = m_kids.size() - 1; i < e; i++)
    {
      std::cout << " ";
      if (m_kids[i] == 0)
        std::cout << " ";
      else
        std::cout << "|";
    }

    if (nodeCounter.cnt)
      std::cout << "->(" << std::fixed << std::setprecision(2) << pct << ") ";

    if (node->symbol() && !node->symbol()->NAME.empty())
      std::cout << node->symbol()->NAME;
    else
      std::cout << "<no symbol>";

    // After the node gets printed, it's parent has one kid less.
    if (m_indent)
      m_kids[m_indent-1]--;

    std::cout << std::endl;
    m_indent++;
  }

  virtual void post(NodeInfo *, NodeInfo *)
  {
    m_indent--;
    m_kids.resize(m_indent);
  }

  virtual std::string name() const { return "massif tree"; }
  virtual enum FilterType type() const { return BOTH; }
private:

  struct SortByCumulativeCount
  {
    SortByCumulativeCount(bool reverse)
    :m_reverse(reverse)
    {
    }

    bool operator()(NodeInfo * const&a, NodeInfo * const&b)
    {
      if (!a)
        return !m_reverse;
      if (!b)
        return m_reverse;
      Counter &ca = a->COUNTER;
      Counter &cb = b->COUNTER;

      return (ca.ccnt < cb.ccnt) ^ m_reverse;
    }
    bool                  m_reverse;
  };

  size_t                m_indent;
  int64_t               m_totals;
  std::vector<size_t>   m_kids;
  SortByCumulativeCount m_sorter;
  SortByCumulativeCount m_reverseSorter;
};

/** This filter navigates the tree, finds out which
    are the top N contributions for a given counter
    and reports them together with their stacktrace.

    While parsing the tree it maintains a stacktrace
    and if a leaf has a self counter which enters
    in the "top N", it saves the stacktrace.
*/
class TopNBuilderFilter : public IgProfFilter
{
public:
  typedef std::vector<NodeInfo *> StackTrace;

  TopNBuilderFilter(size_t rankingSize)
  :m_rankingSize(rankingSize)
  {
    m_topNValues = new int64_t[rankingSize];
    memset(m_topNValues, 0, sizeof(int64_t) * rankingSize);
    m_topNStackTrace = new StackTrace[rankingSize];
  }

  ~TopNBuilderFilter()
  {
    delete[] m_topNValues;
    delete[] m_topNStackTrace;
  }

  virtual void pre(NodeInfo *, NodeInfo *node)
  {
    // If a node has children, simply record it on the stacktrace
    // and navigate further.
    m_currentStackTrace.push_back(node);

    // If the node does not have children, compare its "self" values
    // against the topten, find the minimum of the top ten and
    // if it is smaller than the counter, replace the
    Counter &nodeCounter = node->COUNTER;

    int min = -1;
    for (size_t i = 0; i != m_rankingSize; ++i)
      if (m_topNValues[i] < nodeCounter.cnt
          && (min == -1 || m_topNValues[i] < m_topNValues[min]))
        min = i;

    if (min == -1)
      return;

    m_topNValues[min] = nodeCounter.cnt;
    m_topNStackTrace[min].resize(m_currentStackTrace.size());
    std::copy(m_currentStackTrace.begin(),
              m_currentStackTrace.end(),
              m_topNStackTrace[min].begin());
  }

  virtual void post(NodeInfo */*parent*/, NodeInfo */*node*/)
  {
    if (!m_currentStackTrace.empty())
      m_currentStackTrace.pop_back();
  }

  StackTrace &stackTrace(size_t pos, int64_t &value)
  {
    std::vector<std::pair<int64_t, size_t> > sorted;
    for (size_t i = 0; i != m_rankingSize; ++i)
      sorted.push_back(std::make_pair(m_topNValues[i], i));

    std::sort(sorted.begin(), sorted.end(), Cmp());
    value = m_topNValues[sorted[pos].second];
    return m_topNStackTrace[sorted[pos].second];
  }

  virtual std::string name() const { return "top N builder"; }
  virtual enum FilterType type() const { return BOTH; }

private:
  struct Cmp
  {
    bool operator()(const std::pair<int64_t, size_t> &a, const std::pair<int64_t, size_t> &b)
    {
      return b.first < a.first;
    }
  };

  size_t                    m_rankingSize;
  int64_t                   *m_topNValues;
  StackTrace                *m_topNStackTrace;
  std::vector<NodeInfo *>   m_currentStackTrace;
};

class TreeMapBuilderFilter : public IgProfFilter
{
public:
  TreeMapBuilderFilter(bool isMax, ProfileInfo *prof)
    :m_prof(prof), m_flatMap(new FlatInfoMap), m_firstInfo(0), m_isMax(isMax)
    {
    }

  /** Creates the GPROF like output.

  * Gets invoked with a node and it's parent.
  * Finds a unique name for the node, keeping into account recursion.
  * Gets the unique FlatInfo associated to the symbols. Recursive calls result in same symbol.
  * Calculates the depths in the tree of the node.
  * Gets the relevant counter associated to the node.
  * For the case in which there is a parent.
  * Get the counter for the parent.
  * Find the parent unique symbol.
  * Find the parent unique FlatInfo.
  * Find the FlatInfo associated to the node, when it was called by the parent.
  * If the above does not exist, create it and insert it among those which can be reached from the parent.
  * Accumulate counts.
  */
  virtual void pre(NodeInfo *parent, NodeInfo *node)
    {
      ASSERT(node);
      SymbolInfo *sym = symfor(node);
      ASSERT(sym);
      FlatInfo *symnode = FlatInfo::getInMap(m_flatMap, sym);
      ASSERT(symnode);

      if (!m_firstInfo)
        m_firstInfo = symnode;

      if (symnode->DEPTH < 0 || int(m_seen.size()) < symnode->DEPTH)
        symnode->DEPTH = int(m_seen.size());

      Counter &nodeCounter = node->COUNTER;

      if (parent)
      {
        SymbolInfo *parsym = parent->symbol();
        FlatInfo *parentInfo = FlatInfo::getInMap(m_flatMap, parsym, false);
        ASSERT(parentInfo);

        symnode->CALLERS.insert(parsym);

        CallInfo *callInfo = parentInfo->getCallee(sym, true);

        accumulateCounts(callInfo->VALUES, nodeCounter.ccnt, nodeCounter.cfreq);
      }

      // Do SELF_KEY
      accumulateCounts(symnode->SELF_KEY, nodeCounter.cnt, nodeCounter.freq);
      // Do CUM_KEY
      accumulateCounts(symnode->CUM_KEY, nodeCounter.ccnt, nodeCounter.cfreq);
    }

  virtual void post(NodeInfo *,
                    NodeInfo *node)
    {
      ASSERT(node);
      ASSERT(node->symbol());
      if (m_seen.count(node->symbol()->NAME) <= 0)
        std::cerr << "Error: " << node->symbol()->NAME << std::endl;

      ASSERT(m_seen.count(node->symbol()->NAME) > 0);
      m_seen.erase(node->symbol()->NAME);
      ASSERT(m_seen.count(node->symbol()->NAME) == 0);
    }

  virtual std::string name() const { return "tree map builder"; }
  virtual enum FilterType type() const { return BOTH; }

  void getTotals(int64_t &totals, int64_t &totfreqs)
    {
      ASSERT(m_firstInfo);
      totals = m_firstInfo->CUM_KEY[0];
      totfreqs = m_firstInfo->CUM_KEY[1];
    }

  FlatInfoMap *flatMap()
    {
      return m_flatMap;
    }
private:
  typedef std::map<std::string, SymbolInfo *>  SeenSymbols;

  void accumulateCounts(int64_t *buffer, int64_t c, int64_t f)
  {
    // Do CUM_KEY
    if (m_isMax)
    {
      if (buffer[0] < c)
        buffer[0] = c;
    }
    else
      buffer[0] += c;

    buffer[1] += f;
    buffer[2]++;
  }

  SymbolInfo *symfor(NodeInfo *node)
    {
      ASSERT(node);
      SymbolInfo *reportSymbol = node->reportSymbol();
      if (reportSymbol)
      {
        m_seen.insert(SeenSymbols::value_type(reportSymbol->NAME,
                                              reportSymbol));
        return reportSymbol;
      }

      std::string suffix = "";

      ASSERT(node->originalSymbol());
      std::string symbolName = node->originalSymbol()->NAME;

      SeenSymbols::iterator i = m_seen.find(symbolName);
      if (i != m_seen.end())
      {
        std::string newName = getUniqueName(symbolName);
        SymbolInfoFactory::SymbolsByName &namedSymbols = SymbolInfoFactory::namedSymbols();
        SymbolInfoFactory::SymbolsByName::iterator s = namedSymbols.find(newName);
        if (s == namedSymbols.end())
        {
          SymbolInfo *originalSymbol = node->originalSymbol();
          reportSymbol = new SymbolInfo(newName.c_str(),
                                        originalSymbol->FILE,
                                        originalSymbol->FILEOFF);
          namedSymbols.insert(SymbolInfoFactory::SymbolsByName::value_type(newName,
                                                                           reportSymbol));
        }
        else
          reportSymbol = s->second;
      }
      ASSERT(node);
      node->reportSymbol(reportSymbol);
      ASSERT(node->symbol());
      m_seen.insert(SeenSymbols::value_type(node->symbol()->NAME,
                                            node->symbol()));
      return node->symbol();
    }

  std::string getUniqueName(const std::string &symbolName)
    {
      int index = 2;
      std::string origname = SuffixOps::removeSuffix(symbolName);
      std::string candidate = origname;

      do
      {
        candidate = origname + "'" + toString(index++);
      } while (m_seen.find(candidate) != m_seen.end());
      return candidate;
    }

  ProfileInfo *m_prof;
  FlatInfoMap *m_flatMap;
  FlatInfo    *m_firstInfo;
  SeenSymbols m_seen;
  bool        m_isMax;
};

class TextStreamer
{
public:
  TextStreamer(lat::File *file)
    :m_file(file) {}

  TextStreamer &operator<<(const std::string &string)
    {
      m_file->write(string.c_str(), string.size());
      return *this;
    }
  TextStreamer &operator<<(const char *text)
    { m_file->write(text, strlen(text)); return *this; }

  TextStreamer &operator<<(int num)
    {
      char buffer[32];
      sprintf(buffer, "%d", num);
      m_file->write(buffer, strlen(buffer));
      return *this;
    }

private:
  lat::File *m_file;
};

static lat::Regexp SYMCHECK_RE("IGPROF_SYMCHECK <(.*)>");
static lat::Regexp STARTS_AT_RE(".*starts at .* <([A-Za-z0-9_]+)(\\+\\d+)?>");
static lat::Regexp NO_LINE_NUMBER("^No line number .*? <([A-Za-z0-9_]+)(\\+\\d+)?>");


void symremap(ProfileInfo &prof, std::vector<FlatInfo *> infos, bool usegdb, bool demangle)
{
  typedef std::vector<FlatInfo *> FlatInfos;

  if (usegdb)
  {
    lat::Filename tmpFilename("/tmp/igprof-analyse.gdb.XXXXXXXX");
    lat::File *file = lat::TempFile::file(tmpFilename);
    TextStreamer out(file);
    out << "set width 10000\n";

    std::multimap<FileInfo *, SymbolInfo *> fileAndSymbols;

    for (FlatInfos::const_iterator i = infos.begin();
         i != infos.end();
         i++)
    {
      SymbolInfo *sym = (*i)->SYMBOL;
      if (!sym)
        continue;
      if ((! sym->FILE) || (! sym->FILEOFF) || (!sym->FILE->NAME.size()))
      {
        continue;
      }
      if (sym->FILE->symbolByOffset(sym->FILEOFF)) {
        continue;
      }
      fileAndSymbols.insert(std::pair<FileInfo *, SymbolInfo *>(sym->FILE, sym));
    }

    FileInfo *prevfile = 0;

    for (std::multimap<FileInfo *, SymbolInfo *>::iterator i = fileAndSymbols.begin();
         i != fileAndSymbols.end();
         i++)
    {
      SymbolInfo *sym = i->second;
      FileInfo *fileInfo =i->first;

      ASSERT(sym);
      ASSERT(file);
      prof.symcache().insert(sym);

      if (memcmp(fileInfo->NAME.c_str(), "<dynamically", 12))
      {
        if (fileInfo != prevfile)
        {
          out << "file " << fileInfo->NAME << "\n";
          prevfile = fileInfo;
        }
        out << "echo IGPROF_SYMCHECK <" << (intptr_t) sym << ">\\n\n"
            << "info line *" << toString(sym->FILEOFF)<< "\n";
      }
    }
    file->close();
    delete file;

    PipeReader gdb("gdb --batch --command=" + std::string(tmpFilename));

    std::string oldname;
    std::string suffix;
    SymbolInfo *sym = 0;

    while (gdb.output())
    {
      std::string line;
      std::getline(gdb.output(), line);

      if (!gdb.output())
        break;
      if (line.empty())
        continue;

      lat::RegexpMatch match;


      if (SYMCHECK_RE.match(line, 0, 0, &match))
      {
        ProfileInfo::SymCache::iterator symitr = prof.symcache().find((SymbolInfo *)(atol(match.matchString(line, 1).c_str())));
        ASSERT(symitr !=prof.symcache().end());
        sym = *symitr;
        SuffixOps::splitSuffix(sym->NAME, oldname, suffix);
      }
      else if (STARTS_AT_RE.match(line, 0, 0, &match))
      {
        ASSERT(sym);
        sym->NAME = match.matchString(line, 1) + suffix;
        sym = 0; suffix = "";
      }
      else if (NO_LINE_NUMBER.match(line, 0, 0, &match))
      {
        ASSERT(sym);
        sym->NAME = match.matchString(line, 1) + suffix;
        sym = 0; suffix = "";
      }
    }
    unlink(tmpFilename);
  }

  if (demangle)
  {
    lat::Filename tmpFilename("/tmp/igprof-analyse.c++filt.XXXXXXXX");
    lat::File *file = lat::TempFile::file(tmpFilename);
    TextStreamer out(file);

    for (FlatInfos::const_iterator i = infos.begin(); i != infos.end(); i++)
    {
      SymbolInfo *symbol = (*i)->SYMBOL;
      ASSERT(symbol);
      out << (intptr_t)(symbol) << ": " << symbol->NAME << "\n";
    }
    file->close();
    delete file;

    lat::File symbolFile(tmpFilename);
    PipeReader cppfilt("c++filt", &symbolFile);

    while (cppfilt.output())
    {
      std::string line;
      std::getline(cppfilt.output(), line);
      if (! cppfilt.output())
        break;
      if (line.empty())
        continue;
      const char *lineStart = line.c_str();
      char *endptr = 0;

      SymbolInfo *symbolPtr = (SymbolInfo *)(strtol(lineStart, &endptr, 10));
      ASSERT(endptr != lineStart);
      ASSERT(*endptr == ':');
      symbolPtr->NAME.assign(endptr+2, lineStart+line.size() - (endptr+2));
    }
    unlink(tmpFilename);
  }
}


// Regular expressions matching the symbol information header.
static lat::Regexp vWithDefinitionRE("V(\\d+)=\\((.*?)\\):\\((\\d+),(\\d+)(,(\\d+))?\\)\\s*");

static int
parseStackLine(const char *line, std::vector<NodeInfo *> &nodestack)
{
  // Matches the same as matching "^C(\\d+)\\s*" and resize nodestack to $1.
  if ((line[0] == 0) || line[0] != 'C')
    return 0;
  char *endptr = 0;
  int newPosition = strtol(line+1, &endptr, 10) - 1;
  if (endptr == line+1)
    return 0;

  do
  {
    ++endptr;
  }
  while (*endptr == ' ' || *endptr == '\t');

  int stackSize = nodestack.size();
  ASSERT(newPosition <= stackSize);
  ASSERT(newPosition >= 0);
  int difference = newPosition - stackSize;
  if (difference > 0)
    nodestack.resize(newPosition);
  else
    nodestack.erase(nodestack.begin() + newPosition, nodestack.end());
  return endptr - line;
}

static bool
parseFunctionRef(const char *lineStart, Position &pos,
                 unsigned int &symid, unsigned int fileoff)
{
  const char *line = lineStart + pos();
  // Matches "FN(\\d+)\\+\\d+\\s*" and sets symid = $1
  if (line[0] != 'F' && line[1] != 'N')
    return false;
  char *endptr = 0;
  int fnRef = strtol(line+2, &endptr, 10);
  if (endptr == line + 2)
    return false;
  if (*endptr != '+' )
    return false;
  char *endptr2 = 0;
  int offset = strtol(endptr, &endptr2, 10);
  if (endptr == endptr2)
    return false;

  symid = fnRef;
  fileoff = offset;

  while (*endptr2 == ' ' || *endptr2 == '\t')
    ++endptr2;
  pos(endptr2 - lineStart);
  return true;
}

static bool
parseFunctionDef(const char *lineStart, Position &pos, unsigned int &symid)
{
  const char *line = lineStart + pos();
  // Matches FN(\\d+)=\\( and sets symid = $1
  if (line[0] != 'F' && line[1] != 'N')
    return false;
  char *endptr = 0;
  int fnRef = strtol(line+2, &endptr, 10);
  if (endptr == line + 2)
    return false;
  if (*endptr++ != '=')
    return false;
  if (*endptr++ != '(')
    return false;

  symid = fnRef;

  pos(endptr - lineStart);
  return true;
}

static bool
parseCounterVal(const char *lineStart, Position &pos,
                size_t &ctrid, int64_t &ctrfreq,
                int64_t &ctrvalNormal, int64_t &ctrvalPeak)
{
  // Matches "V(\\d+):\\((\\d+),(\\d+)(,(\\d+))?\\)\\s*" and then sets the arguments accordingly.
  const char *line = lineStart + pos();

  if (line[0] != 'V')
    return false;

  char *endptr = 0;
  int cntRef = strtol(++line, &endptr, 10);
  if (endptr == line || *endptr != ':' || *++endptr != '(')
    return false;

  char *endptr2 = 0;
  int64_t count1 = strtoll(++endptr, &endptr2, 10);
  if (endptr2 == endptr || *endptr2 != ',')
    return false;

  char *endptr3 = 0;
  int64_t count2 = strtoll(++endptr2, &endptr3, 10);
  if (endptr3 == endptr2 || *endptr3 != ',')
    return false;

  char *endptr4 = 0;
  int64_t count3 = strtoll(++endptr3, &endptr4, 10);
  if (endptr3 == endptr4)
    return false;

  if (*endptr4++ != ')')
    return false;

  ctrid = cntRef;
  ctrfreq = count1;
  ctrvalNormal = count2;
  ctrvalPeak= count3;
  while (*endptr4 == ' ' || *endptr4 == '\t')
    endptr4++;
  pos(endptr4 - lineStart);
  return true;
}

static bool
parseCounterDef(const std::string &line, int pos, int /* flags */, lat::RegexpMatch *match)
{
  return vWithDefinitionRE.match(line, pos, 0, match);
}

static bool
parseLeak(const char *lineStart, Position &pos, int64_t &leakAddress, int64_t &leakSize)
{
  // ";LK=\\(0x[\\da-z]+,\\d+\\)\\s*"
  const char *line = lineStart + pos();
  if (*line != ';' || *++line != 'L' || *++line != 'K' || *++line != '='
      || *++line != '(' || *++line != '0' || *++line != 'x')
    return false;

  char *endptr = 0;
  int64_t address = strtoll(++line, &endptr, 16);
  if (endptr == line)
    return false;

  if (*endptr++ != ',')
    return false;

  char *endptr2 = 0;
  int64_t size = strtoll(endptr, &endptr2, 10);
  if (endptr == line)
    return false;
  if (*endptr2++ != ')')
    return false;

  leakAddress = address;
  leakSize = size;

  while (*endptr2 == ' ' || *endptr2 == '\t')
    endptr2++;

  pos(endptr2 - lineStart);

  return true;
}

void
IgProfAnalyzerApplication::readDump(ProfileInfo &prof, const std::string &filename, StackTraceFilter *filter)
{
  ProfileInfo::Nodes &nodes = prof.nodes();
  typedef std::vector<NodeInfo *> Nodes;
  Nodes nodestack;
  nodestack.reserve(IGPROF_MAX_DEPTH);

  verboseMessage("Parsing igprof output file:", filename.c_str());
  FileReader reader(filename);

  std::string line;
  line.reserve(FileOpener::INITIAL_BUFFER_SIZE);
  reader.readLine();
  reader.assignLineToString(line);
  m_config->setTickPeriod(parseHeaders(line));

  PathCollection paths("PATH");

  int lineCount = 1;
  lat::RegexpMatch match;

  SymbolInfoFactory symbolsFactory(&prof, m_config->useGdb);

  // A vector whose i-th element specifies whether or
  // not the counter file id "i" is a key.
  std::vector<bool> keys;

  // A vector keeping track of all the pages touched by the
  // allocations. We store here the address of the page,
  // in order to improve lookup whether or not a page is
  // already there. This way the total number of pages
  // touched is given by "count".
  std::vector<int64_t> pages;
  pages.reserve(20000);

  while (! reader.eof())
  {
    // One node per line.
    // int fileid;
    unsigned int fileoff = 0xdeadbeef;
    // int ctrval;
    // int ctrfreq;
    Position pos;

    printProgress();
    reader.readLine();
    reader.assignLineToString(line);

    int newPos = parseStackLine(line.c_str(), nodestack);
    if (! newPos)
      continue;

    pos(newPos);


    // Find out the information about the current stack line.
    SymbolInfo *sym;

    unsigned int symid = 0xdeadbeef;

    if (line.size() <= pos())
    {
      printSyntaxError(line, filename, lineCount, pos());
      exit(1);
    }
    else  if (line.size() > pos()+2
              && parseFunctionRef(line.c_str(), pos, symid, fileoff))
    {
      sym = symbolsFactory.getSymbol(symid);
      if (!sym)
      {
        std::cerr << "Error at line " << lineCount << ": symbol with id "
                  << symid << " was referred before being defined in input file.\n"
                  << "> " << line << std::endl;
        exit(1);
      }
    }
    else if (line.size() > pos()+2
             && parseFunctionDef(line.c_str(), pos, symid))
      sym = symbolsFactory.createSymbolInfo(line, symid, pos, lineCount);
    else
    {
      printSyntaxError(line, filename, lineCount, pos());
      exit(1);
    }

    NodeInfo* parent = nodestack.empty() ? prof.spontaneous() : nodestack.back();

    NodeInfo* child = parent ? parent->getChildrenBySymbol(sym) : 0;

    if (! child)
    {
      // Nodes are allocated in a deque, to maximize locality
      // and reduce the actual number of allocations.
      m_nodesStorage.resize(m_nodesStorage.size() + 1);
      child = &(m_nodesStorage.back());
      child->setSymbol(sym);
      nodes.push_back(child);
      if (parent)
        parent->CHILDREN.push_back(child);
    }

    nodestack.push_back(child);

    match.reset();
    pages.clear();
    int64_t fullPagesCount = 0;

    // Read the counter information.
    while (true)
    {
      size_t fileId;
      int64_t ctrval;
      int64_t ctrfreq;
      int64_t ctrvalNormal;
      int64_t ctrvalPeak;
      int64_t leakAddress;
      int64_t leakSize;

      if (line.size() == pos())
        break;

      if (line.size() >= pos()+2
          && parseCounterVal(line.c_str(), pos, fileId, ctrfreq, ctrvalNormal, ctrvalPeak))
      {
        // FIXME: should really do:
        // $ctrname = $ctrbyid{$1} || die;

        // If the fileId is not among those associated
        // to the key counter, we skip the counter.
        if (keys[fileId] == false)
          continue;
        ctrval = m_config->normalValue() ? ctrvalNormal : ctrvalPeak;
      }
      else if (line.size() >= pos()+2
               && parseCounterDef(line, pos(), 0, &match))
      {
        // FIXME: should really do:
        // die if exists $ctrbyid{$1};

        std::string ctrname = match.matchString(line, 2);
        IntConverter getIntMatch(line, &match);
        fileId = getIntMatch(1);

        // The first counter we meet, we make it the key, unless
        // the key was already set on command line.
        if (m_key.empty())
          setKey(ctrname);

        // Store information about fileId being
        // a key or not.
        if (keys.size() <= fileId)
          keys.resize(fileId + 1, false);
        keys[fileId] = ctrname == m_key;

        // Get information from the counter and be ready to
        // continue.
        ctrfreq = getIntMatch(3);
        ctrval = m_config->normalValue() ? getIntMatch(4)
                 : getIntMatch(6);
        pos(match.matchEnd());
        match.reset();

        // Ignore in case we don't care about the counter and continue.
        if (!keys[fileId])
          continue;
      }
      else if (line.size() >= pos()+3
               && parseLeak(line.c_str(), pos, leakAddress, leakSize))
      {
        // In case we specify --show-pages option, we keep an
        // ordered unique list of all the (non completely allocated) pages
        // that got touched. We only track beginning and end page since
        // the others are not fragmented and not really interesting.
        // This means that an allocation of 2MB has the same cost of an
        // allocation of 5KB or two allocation of 1B that are on different pages.
        // Moreover 4096 allocations of 1B have the same cost of 1 allocation
        // of 1B, if they are continuos (i.e. pooled allocation are considered
        // good).
        if (m_showPages)
        {
          int64_t startPageAddress = leakAddress >> 12;
          std::vector<int64_t>::iterator spi = std::lower_bound(pages.begin(),
                                                                pages.end(),
                                                                startPageAddress);

          // Add contribution to pages if page was never seen.
          if ((spi == pages.end()) ||  (*spi != startPageAddress))
            pages.insert(spi, startPageAddress);

          int64_t endPageAddress = (leakAddress+leakSize) >> 12;
          std::vector<int64_t>::iterator epi = std::lower_bound(pages.begin(),
                                                                pages.end(),
                                                                endPageAddress);
          // Add contribution to pages if page was never seen.
          if ((epi == pages.end()) ||  (*epi != endPageAddress))
            pages.insert(epi, endPageAddress);

          // Keep the contribution of full pages between start and end one,
          // if any.
          int64_t fullPages = (endPageAddress - startPageAddress - 1);
          if (!m_showPartialPages && fullPages > 0)
            fullPagesCount += fullPages;
          continue;
        }
        else
        {
          // Allocations get handled only when --dump-allocations flag
          // is passed in the command line.
          // Here we simply attach the allocation information to the
          // node. They will be printed out by a special filter later on.
          // Notice that allocation information needs to be merged in
          // just like counters do in the case of filtering
          // and reorganization of the calltree.
          if (!m_config->dumpAllocations)
            continue;

          child->allocations.resize(child->allocations.size() + 1);
          Allocation &a = child->allocations.back();
          a.address = leakAddress;
          a.size = leakSize;
          continue;
        }
      }
      else
      {
        printSyntaxError(line, filename, lineCount, pos());
        exit(1);
      }

      if (filter)
        filter->filter(sym, ctrval, ctrfreq);

      child->COUNTER.cnt += ctrval;
      child->COUNTER.freq += ctrfreq;
    }

    // In case the --show-pages option was specified,
    // we keep track of pages touched, rather than the
    // counter value.
    if (m_showPages && m_showLocalityMetrics)
      child->COUNTER.cnt = child->COUNTER.cnt ? 4096 * (pages.size() + fullPagesCount) / child->COUNTER.cnt : 0;
    else if (m_showPages)
      child->COUNTER.cnt = pages.size() + fullPagesCount;
    lineCount++;
  }

  if (keys.empty())
  {
    std::cerr << "No counter values in profile data." << std::endl;
    exit(1);
  }
}

struct StackItem
{
  NodeInfo *parent;
  NodeInfo *pre;
  NodeInfo *post;
};

void walk(NodeInfo *first, size_t total, IgProfFilter *filter=0)
{
  // TODO: Apply more than one filter at the time.
  //     This method applies one filter at the time. Is it worth to do
  //     the walk only once for all the filters? Should increase locality
  //     as well...
  ASSERT(filter);
  ASSERT(first);
  std::vector<StackItem> stack;
  stack.resize(1);
  StackItem &firstItem = stack.back();
  firstItem.parent = 0;
  firstItem.pre = first;
  firstItem.post = 0;
  stack.reserve(10000);

  if (total)
    std::cerr << "\n" << filter->name();

  size_t count = 0;
  size_t newProgress = 0;
  size_t oldProgress = 0;

  while (!stack.empty())
  {
    StackItem &item = stack.back();
    NodeInfo *parent = item.parent, *pre = item.pre, *post = item.post;
    stack.pop_back();
    if (pre)
    {
      if (filter->type() & IgProfFilter::PRE)
      {
        filter->pre(parent, pre);
        ++count;
      }
      if (filter->type() & IgProfFilter::POST)
      {
        StackItem newItem;
        newItem.parent = parent;
        newItem.pre = 0;
        newItem.post = pre;
        stack.push_back(newItem);
      }
      // Add all the children of pre as items in the stack.
      for (size_t ci = 0, ce = pre->CHILDREN.size(); ci != ce; ++ci)
      {
        ASSERT(pre);
        NodeInfo *child = pre->CHILDREN[ci];
        StackItem newItem;
        newItem.parent = pre;
        newItem.pre = child;
        newItem.post = 0;
        stack.push_back(newItem);
      }
    }
    else
    {
      filter->post(parent, post);
      ++count;
    }
    newProgress = (100 * count) / total;
    if (newProgress > oldProgress)
    {
      oldProgress = newProgress;
      std::cerr << ".";
    }
  }
}

void
IgProfAnalyzerApplication::verboseMessage(const char *msg, const char *arg)
{
  if (!m_config->verbose())
    return;
  std::cerr << msg;

  if (arg)
    std::cerr << " " << arg;

  if (msg[0])
    std::cerr << ".";

  std::cerr << std::endl;
}

void
IgProfAnalyzerApplication::prepdata(ProfileInfo& prof)
{
  for (size_t fi = 0, fe = m_filters.size(); fi != fe; ++fi)
  {
    IgProfFilter *filter = m_filters[fi];
    verboseMessage("Applying filter", filter->name().c_str());
    walk(prof.spontaneous(), m_nodesStorage.size(), filter);
  }

  if (m_config->mergeLibraries())
  {
    //    walk<NodeInfo>(prof.spontaneous(), new PrintTreeFilter);

    verboseMessage("Merge nodes belonging to the same library.");
    walk(prof.spontaneous(), m_nodesStorage.size(), new UseFileNamesFilter(m_keyMax));
    //    walk<NodeInfo>(prof.spontaneous(), new PrintTreeFilter);
  }

  if (!m_regexps.empty())
  {
    verboseMessage("Merge nodes using user-provided regular expression.");
    walk(prof.spontaneous(), m_nodesStorage.size(), new RegexpFilter(m_regexps, m_keyMax));
  }

  verboseMessage("Summing counters");
  walk(prof.spontaneous(), m_nodesStorage.size(), new AddCumulativeInfoFilter(m_keyMax));
  walk(prof.spontaneous(), m_nodesStorage.size(), new CheckTreeConsistencyFilter());
}

class FlatInfoComparator
{
public:
  virtual ~FlatInfoComparator() {}
  FlatInfoComparator(int ordering)
    :m_ordering(ordering)
    {}
  bool operator()(FlatInfo *a, FlatInfo *b)
    {
      int64_t cmp;
      cmp = cmpnodekey(a, b);
      if (cmp > 0)
        return true;
      else if (cmp < 0)
        return false;
      cmp = cmpcallers(a, b);
      if (cmp > 0)
        return true;
      else if (cmp < 0)
        return false;
      return strcmp(a->name(), b->name()) < 0;
    }
protected:
  virtual int64_t cmpnodekey(FlatInfo *a, FlatInfo *b)
    {
      int64_t aVal = a->CUM_KEY[0];
      int64_t bVal = b->CUM_KEY[0];
      return  -1 * m_ordering * (llabs(bVal) - llabs(aVal));
    }

  int cmpcallers(FlatInfo *a, FlatInfo *b)
    {
      return b->DEPTH - a->DEPTH;
    }

  int m_ordering;
};

class FlatInfoComparatorWithBaseline : public FlatInfoComparator
{
public:
  FlatInfoComparatorWithBaseline(int ordering, FlatInfoMap *map)
    :FlatInfoComparator(ordering),
     m_baselineMap(map)
    {}

protected:
  virtual int64_t cmpnodekey(FlatInfo *a, FlatInfo *b)
    {
      int64_t aVal = a->CUM_KEY[0];
      int64_t bVal = b->CUM_KEY[0];

      FlatInfoMap::iterator origA = m_baselineMap->find(a->SYMBOL);
      FlatInfoMap::iterator origB = m_baselineMap->find(b->SYMBOL);

      int64_t aOrigVal = aVal;
      int64_t bOrigVal = bVal;

      if (origA != m_baselineMap->end())
        aOrigVal = origA->second->CUM_KEY[0];
      if (origB != m_baselineMap->end())
        bOrigVal = origB->second->CUM_KEY[0];

      return  -1 * m_ordering * ((bVal-bOrigVal)/bOrigVal - (aVal - aOrigVal)/aOrigVal);
    }
private:
  FlatInfoMap *m_baselineMap;
};

class GProfRow
{
public:
  int FILEOFF;
  float PCT;
  float SELF_PCT;

  void initFromInfo(FlatInfo *info)
    {
      ASSERT(info);
      m_info = info;
    }

  const char *name()
    {
      return m_info->name();
    }

  const char *filename()
    {
      return m_info->filename().c_str();
    }

  const unsigned int depth()
    {
      return m_info->DEPTH;
    }

  const unsigned int rank()
    {
      return m_info->rank();
    }

  intptr_t symbolId()
    {
      return(intptr_t)(m_info->SYMBOL);
    }

  intptr_t fileId()
    {
      return(intptr_t)(m_info->SYMBOL->FILE);
    }

private:
  FlatInfo *m_info;
};

/** Helper functor to print percentage numbers
    in different way, depending on whether we are in
    diff mode or not.

    @a mode true in case we are in diff mode,
            false otherwise.
*/
class PercentagePrinter
{
public:
  PercentagePrinter(bool mode)
  :m_mode(mode)
  {}

  void operator()(float value, const char *numeric = "%7.1f  ", const char *overflow = "    new  ")
  {
    if (m_mode && value == FLT_MAX)
      printf(overflow);
    else
      printf(numeric, value);
  }
private:
  bool m_mode;
};


class OtherGProfRow : public GProfRow
{
public:
  int64_t SELF_COUNTS;
  int64_t CHILDREN_COUNTS;
  int64_t SELF_CALLS;
  int64_t TOTAL_CALLS;
  int64_t SELF_PATHS;
  int64_t TOTAL_PATHS;

  OtherGProfRow(void)
    :SELF_COUNTS(0), CHILDREN_COUNTS(0), SELF_CALLS(0),
     TOTAL_CALLS(0), SELF_PATHS(0), TOTAL_PATHS(0)
    {}
};

std::ostream & operator<<(std::ostream &stream, OtherGProfRow& row)
{
  stream << "[" << row.SELF_COUNTS << " " << row.CHILDREN_COUNTS << " "
         << row.SELF_CALLS << " " << row.SELF_CALLS << " "
         << row.SELF_PATHS << " " << row.TOTAL_PATHS << "]" << std::endl;
  return stream;
}


template <int ORDER>
struct CompareCallersRow
{
  bool operator()(OtherGProfRow *a, OtherGProfRow *b)
    {
      int64_t callsDiff = ORDER * (a->SELF_COUNTS - b->SELF_COUNTS);
      int64_t cumDiff = ORDER * (a->CHILDREN_COUNTS - b->CHILDREN_COUNTS);
      if (callsDiff) return callsDiff < 0;
      if (cumDiff) return cumDiff < 0;
      return strcmp(a->name(), b->name()) < 0;
    }
};

/* This is the class which represent an entry in the gprof style flat output.
 *
 * CUM is the accumulated counts for that entry, including the count for the children.
 * SELF is the accumulated counts for only that entry, excluding the counts coming from children.
 * KIDS is the accumulated counts for the entries that are called by that entry.
 *
 * NOTE: one should have CUM = SELF+KIDS,  so I don't quite understand why I actually need one of the three.
 *
 * SELF_ALL I don't remember what it is.
 * CUM_ALL I don't remember what it is.
 */

class MainGProfRow : public GProfRow
{
public:
  typedef std::set <OtherGProfRow *, CompareCallersRow<1> > Callers;
  typedef std::set <OtherGProfRow *, CompareCallersRow<-1> > Calls;

  int64_t CUM;
  int64_t SELF;
  int64_t KIDS;
  int64_t SELF_ALL[3];
  int64_t CUM_ALL[3];

  Callers CALLERS;
  Calls CALLS;
};

class GProfMainRowBuilder
{
public:
  GProfMainRowBuilder(TreeMapBuilderFilter *flatMapBuilder,
                      TreeMapBuilderFilter *baselineBuilder,
                      bool diffMode)
    : m_info(0), m_origInfo(0),
      m_row(0), m_callmax(0),
      m_totals(0),
      m_totfreq(0),
      m_diffMode(diffMode),
      m_flatMap(flatMapBuilder->flatMap()),
      m_baselineMap(baselineBuilder ? baselineBuilder->flatMap() : 0)
    {
      flatMapBuilder->getTotals(m_totals, m_totfreq);
      if (baselineBuilder)
      {
        int64_t oldTotals = 0;
        int64_t oldTotfreq = 0;
        baselineBuilder->getTotals(oldTotals, oldTotfreq);
        m_totals -= oldTotals;
        m_totfreq -= oldTotfreq;
      }
    }

  void addCaller(SymbolInfo *callerSymbol)
    {
      ASSERT(m_info);
      ASSERT(m_row);
      FlatInfo *origin = (*m_flatMap)[callerSymbol];
      CallInfo *thisCall = origin->getCallee(m_info->SYMBOL);

      ASSERT(thisCall);
      if (!thisCall->VALUES[0])
        return;
      OtherGProfRow *callrow = new OtherGProfRow();
      callrow->initFromInfo(origin);

      // In diff mode the percentage value is the percentual increment
      // between the two runs.
      // In the normal mode (i.e. no negative counts) it is the
      // fraction of the total counts.
      if (m_diffMode)
      {
        FlatInfo *origOrigin = (*m_baselineMap)[callerSymbol];
        CallInfo * origThisCall = 0;
        if (origOrigin)
          origThisCall = origOrigin->getCallee(m_info->SYMBOL);
        if (origThisCall)
          callrow->PCT = percent(thisCall->VALUES[0], llabs(origThisCall->VALUES[0]));
        else
          callrow->PCT = FLT_MAX;
      }
      else
        callrow->PCT = percent(thisCall->VALUES[0], m_totals);

      callrow->SELF_COUNTS = thisCall->VALUES[0];
      callrow->CHILDREN_COUNTS = origin->CUM_KEY[0];

      callrow->SELF_CALLS = thisCall->VALUES[1];
      callrow->TOTAL_CALLS = origin->CUM_KEY[1];

      callrow->SELF_PATHS = thisCall->VALUES[2];
      callrow->TOTAL_PATHS = origin->CUM_KEY[2];
      m_row->CALLERS.insert(callrow);
    }

  void addCallee(CallInfo *thisCall)
    {
      ASSERT(m_info);
      ASSERT(m_row);
      // calleeInfo is the global information about this symbol
      // thisCall contains the information when this symbol is called by m_info
      FlatInfo *calleeInfo = (*m_flatMap)[thisCall->SYMBOL];

      if (!thisCall->VALUES[0])
        return;

      if (m_callmax < thisCall->VALUES[0])
        m_callmax = thisCall->VALUES[0];

      OtherGProfRow *callrow = new OtherGProfRow();
      ASSERT(calleeInfo);
      callrow->initFromInfo(calleeInfo);
      if (m_diffMode)
      {
        CallInfo *origCall = 0;
        if (m_origInfo)
          origCall = m_origInfo->getCallee(thisCall->SYMBOL);
        if (origCall)
          callrow->PCT = percent(thisCall->VALUES[0], llabs(origCall->VALUES[0]));
        else
          callrow->PCT = FLT_MAX;
      }
      else
        callrow->PCT = percent(thisCall->VALUES[0], m_totals);

      callrow->SELF_COUNTS = thisCall->VALUES[0];
      callrow->CHILDREN_COUNTS = calleeInfo->CUM_KEY[0];

      callrow->SELF_CALLS = thisCall->VALUES[1];
      callrow->TOTAL_CALLS = calleeInfo->CUM_KEY[1];

      callrow->SELF_PATHS = thisCall->VALUES[2];
      callrow->TOTAL_PATHS = calleeInfo->CUM_KEY[2];

      m_row->CALLS.insert(callrow);
      //ASSERT(callrow->SELF_CALLS <= callrow->TOTAL_CALLS);
    }

  void beginEditingWith(FlatInfo *info)
    {
      ASSERT(!m_info);
      ASSERT(!m_row);
      m_info = info;
      m_row = new MainGProfRow();
      m_row->initFromInfo(m_info);

      // In normal mode PCT is the percentage relative to the
      // total counts.
      // In diff mode we need to lookup the original value for
      // the counter and give the percentage of the increment
      // relative to that.
      // In case the old counter is not there, we simply set the
      // percentage to FLT_MAX and later on print "new".
      if (m_diffMode)
      {
        FlatInfoMap::iterator i = m_baselineMap->find(m_info->SYMBOL);
        if (i != m_baselineMap->end())
          m_origInfo = i->second;

        if (m_origInfo && (m_origInfo->CUM_KEY[0] != 0))
          m_row->PCT = percent(m_info->CUM_KEY[0], llabs(m_origInfo->CUM_KEY[0]));
        else
          m_row->PCT = FLT_MAX;

        if (m_origInfo && (m_origInfo->SELF_KEY[0] != 0))
          m_row->SELF_PCT = percent(m_info->SELF_KEY[0], llabs(m_origInfo->SELF_KEY[0]));
        else
          m_row->SELF_PCT = FLT_MAX;

      }
      else
      {
        m_row->PCT = percent(m_info->CUM_KEY[0], m_totals);
        m_row->SELF_PCT = percent(m_info->SELF_KEY[0], m_totals);
      }

      m_row->CUM = m_info->CUM_KEY[0];
      m_row->SELF = m_info->SELF_KEY[0];
    }

  void endEditing(void)
    {
      ASSERT(m_info);
      ASSERT(m_row);
      m_info = 0;
      m_origInfo = 0;
      m_row = 0;
      m_callmax = 0;
    }

  MainGProfRow *build(bool isMax)
    {
      ASSERT(m_row);
      if (isMax)
        m_row->KIDS = m_callmax;
      else
        m_row->KIDS = m_info->CUM_KEY[0] - m_info->SELF_KEY[0];
      memcpy(m_row->CUM_ALL, m_info->CUM_KEY, 3*sizeof(int64_t));
      memcpy(m_row->SELF_ALL, m_info->SELF_KEY, 3*sizeof(int64_t));
      return m_row;
    }

  int64_t totals(void)
    {
      return m_totals;
    }

  int64_t totfreq(void)
    {
      return m_totfreq;
    }
private:
  FlatInfo *m_info;
  FlatInfo *m_origInfo;
  MainGProfRow *m_row;
  int64_t m_callmax;
  int64_t m_totals;
  int64_t m_totfreq;
  bool m_diffMode;
  FlatInfoMap   *m_flatMap;
  FlatInfoMap   *m_baselineMap;
  MainGProfRow  *m_mainCallrow;
};

class HeaderPrinter
{
public:
  HeaderPrinter(bool showpaths, bool showcalls,
                int maxval, int maxcnt, bool diffMode)
    :m_showPaths(showpaths),
     m_showCalls(showcalls),
     m_maxval(maxval),
     m_maxcnt(maxcnt),
     m_diffMode(diffMode)
    {}

  void print(const char *description, const char *kind)
    {
      std::cout << "\n" << std::string(70, '-') << "\n"
                << description << "\n\n";
      if (m_diffMode)
        std::cout << "delta %  ";
      else
        std::cout << "% total  ";
      (AlignedPrinter(m_maxval))(kind);
      if (m_showCalls)
        (AlignedPrinter(m_maxcnt))("Calls");
      if (m_showPaths)
        (AlignedPrinter(m_maxcnt))("Paths");
      std::cout << "Function\n";
    }

private:
  bool m_showPaths;
  bool m_showCalls;
  int  m_maxval;
  int  m_maxcnt;
  bool m_diffMode;
};

int64_t
max(int64_t a, int64_t b)
{
  return a > b ? a : b;
}

class SortRowBySelf
{
public:
  bool operator()(MainGProfRow *a, MainGProfRow *b)
    {
      return llabs(a->SELF) > llabs(b->SELF);
      //if(a->SELF != b->SELF) return a->SELF > b->SELF;
      //if(a->DEPTH != b->DEPTH) return a->DEPTH < b->DEPTH;
      //return a->NAME < b->NAME;
    }
};

void
IgProfAnalyzerApplication::tree(ProfileInfo &prof)
{
  prepdata(prof);

  // FIXME: make sure that symremap can be called even without
  //        passing a flatMap.
  verboseMessage("Building call tree map");
  TreeMapBuilderFilter *callTreeBuilder = new TreeMapBuilderFilter(m_keyMax, &prof);
  walk(prof.spontaneous(), m_nodesStorage.size(), callTreeBuilder);
  // Sorting flat entries
  verboseMessage("Sorting");
  int rank = 1;
  FlatVector sorted;
  FlatInfoMap *flatMap = callTreeBuilder->flatMap();

  if (flatMap->empty())
  {
    std::cerr << "Could not find any information to print." << std::endl;
    exit(1);
  }

  for (FlatInfoMap::const_iterator i = flatMap->begin();
       i != flatMap->end();
       i++)
    sorted.push_back(i->second);

  sort(sorted.begin(), sorted.end(), FlatInfoComparator(m_config->ordering()));

  for (size_t i = 0, e = sorted.size(); i != e; ++i)
    sorted[i]->setRank(rank++);

  if (m_config->doDemangle() || m_config->useGdb)
  {
    verboseMessage("Resolving symbols");
    symremap(prof, sorted, m_config->useGdb, m_config->doDemangle());
  }

  // Actually producing the tree.
  MassifTreeBuilder *treeBuilder = new MassifTreeBuilder(m_config);
  walk(prof.spontaneous(), m_nodesStorage.size(), treeBuilder);
}

void
IgProfAnalyzerApplication::dumpAllocations(ProfileInfo &prof)
{
  // Calculate the amount of allocations required to fill one page of
  // memory. This is a rough indication of fragmentation.
  AllocationsPerPage *fragmentationEvaluator = new AllocationsPerPage();
  walk(prof.spontaneous(), m_nodesStorage.size(), fragmentationEvaluator);

  prepdata(prof);

  // FIXME: make sure that symremap can be called even without
  //        passing a flatMap.
  verboseMessage("Building call tree map");
  TreeMapBuilderFilter *callTreeBuilder = new TreeMapBuilderFilter(m_keyMax, &prof);
  walk(prof.spontaneous(), m_nodesStorage.size(), callTreeBuilder);

  // Sorting flat entries
  verboseMessage("Sorting");
  int rank = 1;
  FlatVector sorted;
  FlatInfoMap *flatMap = callTreeBuilder->flatMap();

  if (flatMap->empty())
  {
    std::cerr << "Could not find any information to print." << std::endl;
    exit(1);
  }

  for (FlatInfoMap::const_iterator i = flatMap->begin();
       i != flatMap->end();
       i++)
    sorted.push_back(i->second);

  sort(sorted.begin(), sorted.end(), FlatInfoComparator(m_config->ordering()));

  for (size_t i = 0, e = sorted.size(); i != e; ++i)
    sorted[i]->setRank(rank++);

  if (m_config->doDemangle() || m_config->useGdb)
  {
    verboseMessage("Resolving symbols");
    symremap(prof, sorted, m_config->useGdb, m_config->doDemangle());
  }

  // Produce the allocations map information.
  DumpAllocationsFilter dumper(std::cout);
  walk(prof.spontaneous(), m_nodesStorage.size(), &dumper);

  // Dump the symbol information for the first 10 entries.

  // Actually building the top 10.
  verboseMessage("Building top N");
  TopNBuilderFilter *topNFilter = new TopNBuilderFilter(m_topN);
  walk(prof.spontaneous(), m_nodesStorage.size(), topNFilter);

  for (size_t i = 0; i != m_topN; ++i)
  {
    int64_t value;
    TopNBuilderFilter::StackTrace &nodes = topNFilter->stackTrace(i, value);
    if (!value)
      break;

    int j = 0;
    for(std::vector<NodeInfo *>::reverse_iterator ni = nodes.rbegin(), ne = nodes.rend(); ni != ne; ++ni)
      std::cout << "@("<< i << "," << j++ << ")" << *ni << ":" << (*ni)->symbol()->NAME << "\n";
  }

  generateFlatReport(prof, callTreeBuilder, 0, sorted);
}

void
IgProfAnalyzerApplication::topN(ProfileInfo &prof)
{
  prepdata(prof);

  // FIXME: make sure that symremap can be called even without
  //        passing a flatMap.
  verboseMessage("Building call tree map");
  TreeMapBuilderFilter *callTreeBuilder = new TreeMapBuilderFilter(m_keyMax, &prof);
  walk(prof.spontaneous(), m_nodesStorage.size(), callTreeBuilder);
  // Sorting flat entries
  verboseMessage("Sorting");
  int rank = 1;
  FlatVector sorted;
  FlatInfoMap *flatMap = callTreeBuilder->flatMap();

  if (flatMap->empty())
  {
    std::cerr << "Could not find any information to print." << std::endl;
    exit(1);
  }

  for (FlatInfoMap::const_iterator i = flatMap->begin();
       i != flatMap->end();
       i++)
    sorted.push_back(i->second);

  sort(sorted.begin(), sorted.end(), FlatInfoComparator(m_config->ordering()));

  for (size_t i = 0, e = sorted.size(); i != e; ++i)
    sorted[i]->setRank(rank++);

  if (m_config->doDemangle() || m_config->useGdb)
  {
    verboseMessage("Resolving symbols");
    symremap(prof, sorted, m_config->useGdb, m_config->doDemangle());
  }

  if (sorted.empty()) {
    std::cerr << "Could not find any sorted information to print." << std::endl;
    exit(1);
  }
  // Actually building the top 10.
  verboseMessage("Building top N");
  TopNBuilderFilter *topNFilter = new TopNBuilderFilter(m_topN);
  walk(prof.spontaneous(), m_nodesStorage.size(), topNFilter);
  for (size_t i = 0; i != m_topN; i++)
  {
    std::cout << "## Entry " << i+1 << " (";
    int64_t value;
    std::vector<NodeInfo *> &nodes = topNFilter->stackTrace(i, value);
    if (!value)
      break;
    if (m_isPerfTicks)
      std::cout << thousands(static_cast<double>(value) * m_config->tickPeriod(), 0, 2)
                << " seconds)\n";
    else if (m_showLocalityMetrics)
      std::cout << thousands(value) << " spread factor)\n";
    else if (m_showPages)
      std::cout << thousands(value) << " pages)\n";
    else
      std::cout << thousands(value) << " bytes)\n";

    int j = 0;
    for(std::vector<NodeInfo *>::reverse_iterator i = nodes.rbegin(), e = nodes.rend(); i != e; i++)
      std::cout << "#" << j++ << " " << (*i)->symbol()->NAME << "\n";

    std::cout << std::endl;
  }
}

void
IgProfAnalyzerApplication::analyse(ProfileInfo &prof, TreeMapBuilderFilter *baselineBuilder)
{
  prepdata(prof);
  verboseMessage("Building call tree map");
  TreeMapBuilderFilter *callTreeBuilder = new TreeMapBuilderFilter(m_keyMax, &prof);
  walk(prof.spontaneous(), m_nodesStorage.size(), callTreeBuilder);
  // Sorting flat entries
  verboseMessage("Sorting");
  int rank = 1;
  FlatVector sorted;
  FlatInfoMap *flatMap = callTreeBuilder->flatMap();

  if (flatMap->empty())
  {
    std::cerr << "Could not find any information to print." << std::endl;
    exit(1);
  }

  for (FlatInfoMap::const_iterator i = flatMap->begin();
       i != flatMap->end();
       i++)
    sorted.push_back(i->second);

  sort(sorted.begin(), sorted.end(), FlatInfoComparator(m_config->ordering()));

  for (FlatVector::const_iterator i = sorted.begin(); i != sorted.end(); i++)
    (*i)->setRank(rank++);

  if (m_config->doDemangle() || m_config->useGdb)
  {
    verboseMessage("Resolving symbols");
    symremap(prof, sorted, m_config->useGdb, m_config->doDemangle());
  }

  if (sorted.empty()) {
    std::cerr << "Could not find any sorted information to print." << std::endl;
    exit(1);
  }
  generateFlatReport(prof, callTreeBuilder, baselineBuilder, sorted);
}


/** An helper function to generate a flat profile from the tree information.

    @a callTreeBuilder which is the filter used to accumulate the tree information.

    @a baselineBuilder which is the filter used to accumulate the tree information
     of the baseline.

    @a sorted vector which contains the entries of the flat map, correctly
     ordered.
  */
void
IgProfAnalyzerApplication::generateFlatReport(ProfileInfo & /* prof */,
                                              TreeMapBuilderFilter *callTreeBuilder,
                                              TreeMapBuilderFilter *baselineBuilder,
                                              FlatVector &sorted)
{
  verboseMessage("Generating report");

  typedef std::vector <MainGProfRow *> CumulativeSortedTable;
  typedef CumulativeSortedTable FinalTable;
  typedef std::vector <MainGProfRow *> SelfSortedTable;

  FinalTable table;
  GProfMainRowBuilder builder(callTreeBuilder, baselineBuilder, m_config->diffMode());
  int64_t totals = builder.totals();
  int64_t totfreq = builder.totfreq();

  for (FlatVector::const_iterator i = sorted.begin();
       i != sorted.end();
       i++)
  {
    FlatInfo *info = *i;
    if (!info->CUM_KEY[0])
      continue;

    // Sort calling and called functions.
    // FIXME: should sort callee and callers
    builder.beginEditingWith(info);

    for (FlatInfo::Callers::const_iterator j = info->CALLERS.begin();
         j != info->CALLERS.end();
         j++)
      builder.addCaller(*j);

    for (FlatInfo::Calls::const_iterator j = info->CALLS.begin();
         j != info->CALLS.end();
         j++)
      builder.addCallee(*j);
    table.push_back(builder.build(m_keyMax));
    builder.endEditing();
  }

  SelfSortedTable selfSortedTable;

  for (FinalTable::const_iterator i = table.begin();
       i != table.end();
       i++)
    selfSortedTable.push_back(*i);

  stable_sort(selfSortedTable.begin(), selfSortedTable.end(), SortRowBySelf());
  bool diffMode = m_config->diffMode();
  PercentagePrinter printPercentage(diffMode);

  if (m_config->outputType() == Configuration::TEXT)
  {
    bool showcalls = m_config->showCalls();
    bool showpaths = m_config->showPaths();
    bool showlibs = m_config->showLib();
    std::cout << "Counter: ";

    if (m_showLocalityMetrics)
      std::cout << m_key << "@SPREAD_FACTOR\n";
    else if (m_showPartialPages)
      std::cout << m_key << "@PARTIAL_PAGES\n";
    else if (m_showPages)
      std::cout << m_key << "@PAGES\n";
    else
      std::cout << m_key << "\n";

    float tickPeriod = m_config->tickPeriod();

    int maxcnt=0;
    if (m_isPerfTicks && ! m_config->callgrind())
      maxcnt = max(8, max(thousands(static_cast<double>(totals) * tickPeriod, 0, 2).size(),
                          thousands(static_cast<double>(totfreq) * tickPeriod, 0, 2).size()));
    else
      maxcnt = max(8, max(thousands(totals).size(),
                          thousands(totfreq).size()));
    int maxval = maxcnt + (m_isPerfTicks ? 1 : 0);

    std::string basefmt = m_isPerfTicks ? "%.2f" : "%s";
    FractionPrinter valfmt(maxval);
    FractionPrinter cntfmt(maxcnt);

    HeaderPrinter hp(showpaths, showcalls, maxval, maxcnt, diffMode);

    if (diffMode)
      hp.print ("Flat profile (cumulatively different entries only)", "Total");
    else
      hp.print ("Flat profile (cumulative >= 1%)", "Total");

    for (FinalTable::const_iterator i = table.begin();
         i != table.end();
         i++)
    {
      MainGProfRow &row = **i;
      printPercentage(row.PCT);

      if (m_isPerfTicks && ! m_config->callgrind())
        printf("%*s  ", maxval, thousands(static_cast<double>(row.CUM) * tickPeriod, 0, 2).c_str());
      else
        printf("%*s  ", maxval, thousands(row.CUM).c_str());

      PrintIf p(maxcnt);
      p(showcalls, thousands(row.CUM_ALL[1]));
      p(showpaths, thousands(row.SELF_ALL[2]));
      printf("%s [%d]", row.name(), row.rank());
      if (showlibs)
        std::cout << row.filename();
      std::cout << "\n";
      if ((row.PCT < 1. && !diffMode) || row.CUM == 0)
        break;
    }

    std::cout << "\n";

    if (diffMode)
      hp.print ("Flat profile (self different entries only)", "Self");
    else
      hp.print ("Flat profile (self >= 0.01%)", "Self");

    for (SelfSortedTable::const_iterator i = selfSortedTable.begin();
         i != selfSortedTable.end();
         i++)
    {
      MainGProfRow &row = **i;

      printPercentage(row.SELF_PCT, "%7.2f  ");

      if (m_isPerfTicks && ! m_config->callgrind())
        printf("%*s  ", maxval, thousands(static_cast<double>(row.SELF) * tickPeriod, 0, 2).c_str());
      else
        printf("%*s  ", maxval, thousands(row.SELF).c_str());

      PrintIf p(maxcnt);
      p(showcalls, thousands(row.SELF_ALL[1]));
      p(showpaths, thousands(row.SELF_ALL[2]));
      printf("%s [%d]", row.name(), row.rank());
      if (showlibs)
        std::cout << row.filename();
      std::cout << "\n";
      if ((row.SELF_PCT < 0.01 && !diffMode) || row.SELF == 0)
        break;
    }
    std::cout << "\n\n" << std::string(70, '-') << "\n";
    std::cout << "Call tree profile (cumulative)\n";

    for (FinalTable::const_iterator i = table.begin();
         i != table.end();
         i++)
    {
      int64_t divlen = 34+3*maxval
                       + (showcalls ? 1 : 0)*(2*maxcnt+5)
                       + (showpaths ? 1 : 0)*(2*maxcnt+5);

      std::cout << "\n";
      for (int x = 0 ; x <((1+divlen)/2); x++)
        printf("- ");
      std::cout << std::endl;

      MainGProfRow &mainRow = **i;

      if ((mainRow.rank() % 10) == 1)
      {
        printf("%-8s", "Rank");
        if (diffMode)
          printf("delta %%  ");
        else
          printf("%% total  ");
        (AlignedPrinter(maxval))("Self");
        valfmt("Self", "Children");
        printf("  ");
        if (showcalls)
        {
          cntfmt("Calls", "Total");
          printf("  ");
        }

        if (showpaths)
        {
          cntfmt("Paths", "Total");
          printf("  ");
        }

        printf("Function\n");
      }

      for (MainGProfRow::Callers::const_iterator c = mainRow.CALLERS.begin();
           c != mainRow.CALLERS.end();
           c++)
      {
        OtherGProfRow &row = **c;
        std::cout << std::string(8, ' ');

        printPercentage(row.PCT);

        ASSERT(maxval);
        std::cout << std::string(maxval, '.') << "  ";
        if (m_isPerfTicks && ! m_config->callgrind())
          valfmt(thousands(static_cast<double>(row.SELF_COUNTS) * tickPeriod, 0, 2),
                 thousands(static_cast<double>(row.CHILDREN_COUNTS) * tickPeriod, 0, 2));
        else
          valfmt(thousands(row.SELF_COUNTS), thousands(row.CHILDREN_COUNTS));

        printf("  ");
        if (showcalls)
        {
          cntfmt(thousands(row.SELF_CALLS),
                 thousands(row.TOTAL_CALLS));
          printf("  ");
        }

        if (showpaths)
        {
          cntfmt(thousands(row.SELF_PATHS),
                 thousands(row.TOTAL_PATHS));
          printf("  ");
        }
        printf("  %s [%d]", row.name(), row.rank());
        if (showlibs)
          std::cout << "  " << row.filename();
        std::cout << "\n";
      }

      char rankBuffer[256];
      sprintf(rankBuffer, "[%d]", mainRow.rank());
      printf("%-8s", rankBuffer);
      printPercentage(mainRow.PCT);

      if (m_isPerfTicks && ! m_config->callgrind())
      {
        (AlignedPrinter(maxval))(thousands(static_cast<double>(mainRow.CUM) * tickPeriod, 0, 2));
        valfmt(thousands(static_cast<double>(mainRow.SELF) * tickPeriod, 0, 2),
               thousands(static_cast<double>(mainRow.KIDS) * tickPeriod, 0, 2));
      }
      else
      {
        (AlignedPrinter(maxval))(thousands(mainRow.CUM));
        valfmt(thousands(mainRow.SELF), thousands(mainRow.KIDS));
      }
      printf("  ");
      if (showcalls)
      {
        (AlignedPrinter(maxcnt))(thousands(mainRow.CUM_ALL[1]));
        (AlignedPrinter(maxcnt))(""); printf(" ");
      }
      if (showpaths)
      {
        (AlignedPrinter(maxcnt))(thousands(mainRow.SELF_ALL[2]));
        (AlignedPrinter(maxcnt))(""); printf(" ");
      }

      std::cout << mainRow.name();

      if (showlibs)
        std::cout << mainRow.filename();

      std::cout << "\n";

      for (MainGProfRow::Calls::const_iterator c = mainRow.CALLS.begin();
           c != mainRow.CALLS.end();
           c++)
      {
        OtherGProfRow &row = **c;
        std::cout << std::string(8, ' ');
        printPercentage(row.PCT);

        std::cout << std::string(maxval, '.') << "  ";

        if (m_isPerfTicks && ! m_config->callgrind())
          valfmt(thousands(static_cast<double>(row.SELF_COUNTS) * tickPeriod, 0, 2),
                 thousands(static_cast<double>(row.CHILDREN_COUNTS) * tickPeriod, 0, 2));
        else
          valfmt(thousands(row.SELF_COUNTS), thousands(row.CHILDREN_COUNTS));

        printf("  ");

        if (showcalls)
        {
          cntfmt(thousands(row.SELF_CALLS),
                 thousands(row.TOTAL_CALLS));
          printf("  ");
        }
        if (showpaths)
        {
          cntfmt(thousands(row.SELF_PATHS),
                 thousands(row.TOTAL_PATHS));
          printf("  ");
        }
        printf("  %s [%d]", row.name(), row.rank());

        if (showlibs)
          std::cout << "  " << row.filename();
        std::cout << "\n";
      }
    }
  }
  else if (m_config->outputType() == Configuration::SQLITE)
  {
    std::cout << ("PRAGMA journal_mode=OFF;\n"
                  "PRAGMA count_changes=OFF;\n"
                  "DROP TABLE IF EXISTS files;\n"
                  "DROP TABLE IF EXISTS symbols;\n"
                  "DROP TABLE IF EXISTS mainrows;\n"
                  "DROP TABLE IF EXISTS children;\n"
                  "DROP TABLE IF EXISTS parents;\n"
                  "DROP TABLE IF EXISTS summary;\n\n"
                  "CREATE TABLE summary (\n"
                  "counter TEXT,\n"
                  "total_count INTEGER,\n"
                  "total_freq INTEGER,\n"
                  "tick_period REAL\n"
                  ");\n\n"
                  "CREATE TABLE files (\n"
                  "id,\n"
                  "name TEXT\n"
                  ");\n\n"
                  "CREATE TABLE symbols (\n"
                  "id,\n"
                  "name TEXT,\n"
                  "filename_id INTEGER CONSTRAINT file_id_exists REFERENCES files(id)\n"
                  ");\n\n"
                  "CREATE TABLE mainrows (\n"
                  "id INTEGER PRIMARY KEY,\n"
                  "symbol_id INTEGER CONSTRAINT symbol_id_exists REFERENCES symbols(id),\n"
                  "self_count INTEGER,\n"
                  "cumulative_count INTEGER,\n"
                  "kids INTEGER,\n"
                  "self_calls INTEGER,\n"
                  "total_calls INTEGER,\n"
                  "self_paths INTEGER,\n"
                  "total_paths INTEGER,\n"
                  "pct REAL\n"
                  ");\n\n"
                  "CREATE TABLE children (\n"
                  "self_id INTEGER CONSTRAINT self_exists REFERENCES mainrows(id),\n"
                  "parent_id INTEGER CONSTRAINT parent_exists REFERENCES mainrows(id),\n"
                  "from_parent_count INTEGER,\n"
                  "from_parent_calls INTEGER,\n"
                  "from_parent_paths INTEGER,\n"
                  "pct REAL\n"
                  ");\n\n"
                  "CREATE TABLE parents (\n"
                  "self_id INTEGER CONSTRAINT self_exists REFERENCES mainrows(id),\n"
                  "child_id INTEGER CONSTRAINT child_exists REFERENCES mainrows(id),\n"
                  "to_child_count INTEGER,\n"
                  "to_child_calls INTEGER,\n"
                  "to_child_paths INTEGER,\n"
                  "pct REAL\n"
                  ");\nPRAGMA synchronous=OFF;\n\nBEGIN TRANSACTION;\n"
                  "INSERT INTO summary (counter, total_count, total_freq, tick_period) VALUES(\"");
    if (m_showLocalityMetrics)
      std::cout << m_key << "@SPREAD_FACTOR";
    else if (m_showPartialPages)
      std::cout << m_key << "@PARTIAL_PAGES";
    else if (m_showPages)
      std::cout << m_key << "@PAGES";
    else
      std::cout << m_key;

    std::cout  << "\", " << totals << ", " << totfreq << ", " << m_config->tickPeriod() << ");\n\n";

    unsigned int insertCount = 0;
    std::set<int> filesDone;
    std::set<int> symbolsDone;

    for (FinalTable::const_iterator i = table.begin();
         i != table.end();
         i++)
    {
      MainGProfRow &mainRow = **i;

      if (filesDone.find(mainRow.fileId()) == filesDone.end())
      {
        filesDone.insert(mainRow.fileId());
        std::cout << "INSERT INTO files VALUES ("
                  << mainRow.fileId() << ", \"" << mainRow.filename() << "\");\n";
      }

      if (symbolsDone.find(mainRow.symbolId()) == symbolsDone.end())
      {
        symbolsDone.insert(mainRow.symbolId());
        std::cout << "INSERT INTO symbols VALUES ("
                  << mainRow.symbolId() << ", \"" << mainRow.name() << "\", "
                  << mainRow.fileId() << ");\n";
      }

      std::cout << "INSERT INTO mainrows VALUES ("
                << mainRow.rank() << ", " << mainRow.symbolId() << ", "
                << mainRow.SELF << ", " << mainRow.CUM << ", " << mainRow.KIDS << ", "
                << mainRow.SELF_ALL[1] << ", " << mainRow.CUM_ALL[1] << ", "
                << mainRow.SELF_ALL[2] << ", " << mainRow.CUM_ALL[2] << ", ";
      printPercentage(mainRow.PCT, "%7.2f", "-101");
      std::cout << ");\n";
      if ((++insertCount % 100000) == 0)
        std::cout << "END TRANSACTION;\nBEGIN TRANSACTION;\n";

      for (MainGProfRow::Callers::const_iterator c = mainRow.CALLERS.begin();
           c != mainRow.CALLERS.end();
           c++)
      {
        OtherGProfRow &row = **c;
        std::cout << "INSERT INTO parents VALUES ("
                  << row.rank() << ", " << mainRow.rank() << ", "
                  << row.SELF_COUNTS << ", " << row.SELF_CALLS << ", " << row.SELF_PATHS << ", ";
        printPercentage(row.PCT, "%7.2f", "-101");
        std::cout << ");\n";
        if ((++insertCount % 100000) == 0)
          std::cout << "END TRANSACTION;\nBEGIN TRANSACTION;\n";
      }

      for (MainGProfRow::Calls::const_iterator c = mainRow.CALLS.begin();
           c != mainRow.CALLS.end();
           c++)
      {
        OtherGProfRow &row = **c;
        std::cout << "INSERT INTO children VALUES("
                  << row.rank() << ", " << mainRow.rank() << ", "
                  << row.SELF_COUNTS << ", "<< row.SELF_CALLS << ", " << row.SELF_PATHS << ", ";
        printPercentage(row.PCT, "%7.2f", "-101");
        std::cout << ");\n";
        if ((++insertCount % 100000) == 0)
          std::cout << "END TRANSACTION;\nBEGIN TRANSACTION;\n";
      }
    }
    std::cout << "END TRANSACTION;\n"
                 "CREATE UNIQUE INDEX fileIndex ON files (id);\n"
                 "CREATE UNIQUE INDEX symbolsIndex ON symbols (id);\n"
                 "CREATE INDEX selfCountIndex ON mainrows(self_count);\n"
                 "CREATE INDEX totalCountIndex ON mainrows(cumulative_count);\n"
              << std::endl;
  }
  else
  {
    ASSERT(false);
  }
}




void
IgProfAnalyzerApplication::callgrind(ProfileInfo & /* prof */)
{
  ASSERT(false);
}



void
IgProfAnalyzerApplication::run(void)
{
  ArgsList args;
  for (int i = 0; i < m_argc; i++)
    args.push_back(m_argv[i]);

  this->parseArgs(args);

  ProfileInfo *prof = new ProfileInfo;
  TreeMapBuilderFilter *baselineBuilder = 0;

  if (!m_config->baseline().empty())
  {
    std::cerr << "Reading baseline" << std::endl;
    this->readDump(*prof, m_config->baseline(), new BaseLineFilter);
    prepdata(*prof);
    baselineBuilder = new TreeMapBuilderFilter(m_keyMax, prof);
    walk(prof->spontaneous(), m_nodesStorage.size(), baselineBuilder);
    std::cerr << std::endl;
  }

  std::cerr << "Reading profile data" << std::endl;
  StackTraceFilter *stackTraceFilter = 0;
  if (m_config->hasHitFilter())
    stackTraceFilter = new HitFilter(*m_config);

  for (size_t i = 0, e = m_inputFiles.size(); i != e; ++i)
  {
    this->readDump(*prof, m_inputFiles[i], stackTraceFilter);
    verboseMessage("");
  }

  if (! m_config->isShowCallsDefined())
  {
    if (!memcmp(m_key.c_str(), "MEM_", 4))
      m_config->setShowCalls(true);
    else
      m_config->setShowCalls(false);
  }

  if (m_config->callgrind())
    callgrind(*prof);
  else if (m_topN)
    topN(*prof);
  else if (m_config->tree)
    tree(*prof);
  else if (m_config->dumpAllocations)
    dumpAllocations(*prof);
  else
    analyse(*prof, baselineBuilder);
}


int64_t
parseOptionToInt(const std::string &valueString, const char *msg)
{
  char *endptr;
  int64_t value = strtoll(valueString.c_str(), &endptr, 10);
  if (endptr && *endptr == 0)
    return value;
  std::cerr << "Error, " << msg << " expects an integer." << std::endl;
  exit(1);
}

void
unsupportedOptionDeath(const char *option)
{
  std::cerr << "Option " << option << " is not supported anymore" << std::endl;
  exit(1);
}

void
regexpErrorDeath(std::string re, size_t pos)
{
  std::cerr << "Error in regular expression:\n\n" << re << std::endl;
  std::cerr << std::string(pos, ' ') << "^" << std::endl;
  exit(1);
}

void
unexpectedArgumentDeath(const char *opt, const char *arg, const char *possible)
{
  std::cerr << "Unexpected argument " << arg << " for option" << opt << std::endl;
  if (possible)
    std::cerr << "Possible values: " << possible << std::endl;
  exit(1);
}

void
IgProfAnalyzerApplication::parseArgs(const ArgsList &args)
{

  ArgsList::const_iterator arg = args.begin();

  while (++arg != args.end())
  {
    NameChecker is(*arg);
    ArgsLeftCounter left(args.end());
    if (is("--help"))
      dieWithUsage();
    else if (is("--verbose", "-v"))
      m_config->setVerbose(true);
    else if (is("--report", "-r") && left(arg))
    {
      if (!m_key.empty())
      {
        std::cerr << "Cannot specify more that one \"-ri / --report \" option." << std::endl;
        exit(1);
      }
      setKey(*(++arg));
    }
    else if (is("--value") && left(arg) > 1)
    {
      std::string type = *(++arg);
      if (type == "peak")
        m_config->setNormalValue(false);
      else if (type == "normal")
        m_config->setNormalValue(true);
      else
        unexpectedArgumentDeath("--value", type.c_str(), "normal (default), peak");
    }
    else if (is("--merge-libraries", "-ml"))
      m_config->setMergeLibraries(true);
    else if (is("--order", "-o"))
    {
      std::string order = *(arg++);
      if (order == "ascending")
        m_config->setOrdering(Configuration::ASCENDING);
      else if (order == "descending")
        m_config->setOrdering(Configuration::DESCENDING);
      else
        unexpectedArgumentDeath("-o / --order", order.c_str(), "ascending (default), descending");
    }
    else if (is("--filter-file", "-F"))
      unsupportedOptionDeath(arg->c_str());
    else if (is("--filter", "-f"))
      unsupportedOptionDeath(arg->c_str());
    else if (is("--no-filter", "-nf"))
      m_disableFilters = true;
    else if (is("--list-filters", "-lf"))
      unsupportedOptionDeath(arg->c_str());
    else if (is("--libs", "-l"))
      m_config->setShowLib(true);
    else if (is("--callgrind", "-C"))
      unsupportedOptionDeath(arg->c_str());
    else if (is("--text", "-t"))
      m_config->setOutputType(Configuration::TEXT);
    else if (is("--sqlite", "-s"))
      m_config->setOutputType(Configuration::SQLITE);
    else if (is("--top", "-tn"))
      m_topN = parseOptionToInt(*(++arg), "--top / -tn");
    else if (is("--tree", "-T"))
      m_config->tree = true;
    else if (is("--demangle", "-d"))
      m_config->setDoDemangle(true);
    else if (is("--gdb", "-g"))
      m_config->useGdb = true;
    else if (is("--paths", "-p"))
      m_config->setShowPaths(true);
    else if (is("--calls", "-c"))
      m_config->setShowCalls(true);
    else if (is("--merge-regexp", "-mr") && left(arg))
    {
      std::string re = *(++arg);
      const char *regexpOption = re.c_str();
      std::string origRe = re;

      size_t pos = 0;
      while (*regexpOption)
      {
        if (*regexpOption++ != 's')
          regexpErrorDeath(origRe, pos);
        pos++;
        char separator[] = {0, 0};
        separator[0] = *regexpOption++;
        pos++;
        int searchSize = strcspn(regexpOption, separator);
        std::string search(regexpOption, searchSize);
        regexpOption += searchSize;
        pos += searchSize;
        if (*regexpOption++ != separator[0])
          regexpErrorDeath(origRe, pos);
        pos++;
        int withSize = strcspn(regexpOption, separator);
        std::string with(regexpOption, withSize);
        regexpOption += withSize;
        pos += withSize;

        if (*regexpOption++ != separator[0])
          regexpErrorDeath(origRe, pos);
        pos++;
        if (*regexpOption && *regexpOption++ != ';')
          regexpErrorDeath(origRe, pos);
        pos++;
        m_regexps.resize(m_regexps.size() + 1);

        RegexpSpec &spec = m_regexps.back();
        spec.re = search;
        spec.with = with;
      }
    }
    else if (is("--baseline", "-b") && left(arg))
      m_config->setBaseline(*(++arg));
    else if (is("--diff-mode", "-D"))
      m_config->setDiffMode(true);
    else if (is("--max-count-value", "-Mc") && left(arg))
      m_config->maxCountValue = parseOptionToInt(*(++arg), "--max-value / -Mc");
    else if (is("--min-count-value", "-mc"))
      m_config->minCountValue = parseOptionToInt(*(++arg), "--min-value / -mc");
    else if (is("--max-calls-value", "-Mf") && left(arg))
      m_config->maxCallsValue = parseOptionToInt(*(++arg), "--max-calls-value / -Mf");
    else if (is("--min-calls-value", "-mf") && left(arg))
      m_config->minCallsValue = parseOptionToInt(*(++arg), "--min-calls-value / -mf");
    else if (is("--max-average-value", "-Ma") && left(arg))
      m_config->maxAverageValue = parseOptionToInt(*(++arg), "--max-average-value / -Ma");
    else if (is("--min-average-value", "-ma") && left(arg))
      m_config->minAverageValue = parseOptionToInt(*(++arg), "--min-average-value / -ma");
    else if (is("--dump-allocations"))
      m_config->dumpAllocations = true;
    else if (is("--show-locality-metrics"))
    {
      m_showLocalityMetrics = true;
      m_showPartialPages = true;
      m_showPages = true;
    }
    else if (is("--show-partial-pages"))
    {
      m_showPartialPages = true;
      m_showPages = true;
    }
    else if (is("--show-pages"))
      m_showPages = true;
    else if (is("--show-locality-metric"))
      m_showLocalityMetrics = true;
    else if (is("--"))
    {
      while (left(arg) - 1)
        m_inputFiles.push_back(*(++arg));
    }
    else if ((*arg)[0] == '-')
    {
      std::cerr << "Unknown option " << (*arg) << std::endl;
      dieWithUsage();
    }
    else
      m_inputFiles.push_back(*arg);
  }

  // For the moment we force using MEM_LIVE.
  if (m_showPages)
  {
    if (!m_key.empty())
     dieWithUsage("Option --show-pages / --show-partial-pages cannot be used with -r");
    setKey("MEM_LIVE");
    m_config->setShowCalls(false);
  }

  if (m_config->diffMode() && m_config->baseline().empty())
    dieWithUsage("Option --diff-mode / -D requires --baseline / -b");

  if (m_inputFiles.empty())
    dieWithUsage("ERROR: No input files specified");
}

void
userAborted(int)
{
  std::cerr << "\nUser interrupted." << std::endl;
  exit(1);
}

int
main(int argc, const char **argv)
{
  lat::Signal::handleFatal(argv [0]);
  signal(SIGINT, userAborted);
  try
  {
    IgProfAnalyzerApplication *app = new IgProfAnalyzerApplication(argc, argv);
    app->run();
  }
  catch(lat::Error &e) {

    std::cerr << "Internal error \"" << e.explain() << "\".\n"
      "Oh my, you have found a bug in igprof-analyse!\n"
      "Please file a bug report and some mean to reproduce it to:\n\n"
      "  https://savannah.cern.ch/bugs/?group=cmssw\n\n" << std::endl;
  }
  catch(std::exception &e) {
    std::cerr << "Internal error: \"" << e.what() << "\".\n"
      "\nOh my, you have found a bug in igprof-analyse!\n"
      "Please file a bug report and some mean to reproduce it to:\n\n"
      "  https://savannah.cern.ch/bugs/?group=cmssw\n\n" << std::endl;
  }
  catch(...)
  {
    std::cerr << "Internal error.\n"
      "Oh my, you have found a bug in igprof-analyse!\n"
      "Please file a bug report and some mean to reproduce it to:\n\n"
      "  https://savannah.cern.ch/bugs/?group=cmssw\n\n" << std::endl;
  }
}
