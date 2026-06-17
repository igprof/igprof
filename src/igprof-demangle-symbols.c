/* igprof-demangle-symbols — resolve + demangle the symbols of one or more
 * IgProf dumps, ON the profiling host (where the binaries live), and emit a
 * portable per-dump side-car so the analysis (igprof-query) can run elsewhere
 * WITHOUT the binaries — like shipping perf's resolved symbols.
 *
 * IgProf follows forks, so a run yields many dumps (one per process). Each dump
 * has its OWN FN-id space, so each gets its OWN side-car; but the forked
 * processes share the same binaries, so every binary's nm/objdump scan is done
 * ONCE across all dumps (a global binary registry), then mapped back per dump.
 *
 * Per binary, resolution replicates igprof-analyse (src/sym-resolve.h):
 *     vmbase = (first LOAD vaddr) - (first LOAD off)      [objdump -p]
 *     name(off) = greatest nm symbol with (addr - vmbase) <= off   [nm -t d -n]
 * Only the FN<id>=(...) offsets that actually appear in the dumps are resolved
 * (streamed against nm's address-sorted output, one name held at a time — never
 * the whole symbol table). "_Z..." names are demangled. Binaries run in parallel.
 *
 * Build (Linux, on the profiling host):
 *     cc -O2 -pthread -o igprof-demangle-symbols igprof-demangle-symbols.c -lstdc++
 * Use:
 *     igprof-demangle-symbols -j 8 igprof.host.*.gz.dump ...   # writes <dump>.syms each
 *     gzip -dc igprof.*.gz | igprof-demangle-symbols -          # one dump -> stdout
 * (Pass already-decompressed dumps, or a path; gz must be expanded by the caller.)
 *
 * NB: like igprof, offset resolution is GNU binutils / Linux only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

extern char *__cxa_demangle(const char *, char *, size_t *, int *);

static void die(const char *m) { fprintf(stderr, "igprof-demangle-symbols: %s\n", m); exit(1); }
static void *xmalloc(size_t n) { void *p = malloc(n); if (!p) die("oom"); return p; }
static void *xrealloc(void *p, size_t n) { p = realloc(p, n); if (!p) die("oom"); return p; }

/* ------------------------------------------------------------- data model */

typedef struct {                       /* one FN<id>=(...) definition in a dump */
  const char *raw; uint32_t rawlen;    /* dump name (zero-copy into the dump buffer) */
  int64_t binoff; int32_t bin;         /* offset within its binary; global Bin index */
  char *out;                           /* resolved+demangled @? name (else NULL) */
} Sym;

typedef struct { Sym *syms; size_t nsyms; char *buf; char *path; } Dump;

typedef struct { uint64_t off; int32_t dump, fn; } Req;   /* a @? offset to resolve */
typedef struct { char *path; Req *req; size_t nreq, cap; } Bin;

static Dump *dumps; static size_t ndumps;
static Bin  *bins;  static size_t nbins, capbins;
static int   g_base = 10;

static int bin_for(const char *path, uint32_t len) {
  for (size_t i = 0; i < nbins; i++)
    if (!strncmp(bins[i].path, path, len) && bins[i].path[len] == 0) return (int)i;
  if (nbins == capbins) { capbins = capbins ? capbins * 2 : 64; bins = xrealloc(bins, capbins * sizeof *bins); }
  bins[nbins].path = xmalloc(len + 1); memcpy(bins[nbins].path, path, len); bins[nbins].path[len] = 0;
  bins[nbins].req = NULL; bins[nbins].nreq = bins[nbins].cap = 0;
  return (int)nbins++;
}

static void bin_add_req(int b, uint64_t off, int dump, int fn) {
  Bin *B = &bins[b];
  if (B->nreq == B->cap) { B->cap = B->cap ? B->cap * 2 : 16; B->req = xrealloc(B->req, B->cap * sizeof *B->req); }
  B->req[B->nreq].off = off; B->req[B->nreq].dump = dump; B->req[B->nreq].fn = fn; B->nreq++;
}

/* ----------------------------------------------------------------- scanner */

static inline int64_t scan_int(const char **pp) {
  const char *p = *pp; int64_t v = 0;
  if (g_base == 16)
    for (;; p++) { unsigned c = (unsigned char)*p;
      if (c>='0'&&c<='9') v=(v<<4)|(c-'0'); else if (c>='a'&&c<='f') v=(v<<4)|(c-'a'+10);
      else if (c>='A'&&c<='F') v=(v<<4)|(c-'A'+10); else break; }
  else { int neg=(*p=='-'); if(neg)p++; for(;*p>='0'&&*p<='9';p++) v=v*10+(*p-'0'); if(neg)v=-v; }
  *pp = p; return v;
}

/* Parse one dump into dumps[d]: grep the FN<id>=(...) defs, map local file ids
 * to global bins, queue @? offsets for resolution. */
static void parse_dump(int d, const char *p) {
  Dump *D = &dumps[d];
  if (strncmp(p, "P=(", 3)) die("not an igprof dump");
  p += 3; g_base = (*p == 'H') ? 16 : 10; if (g_base == 16) p += 4;
  while (*p && *p != '\n') p++;
  if (*p) p++;

  int32_t *localbin = NULL; size_t lbcap = 0;       /* dump-local file id -> global bin */
  Sym *syms = NULL; size_t nsyms = 0, cap = 0;

  while (*p == 'C') {
    p++; scan_int(&p); p += 3;                       /* depth, " FN" */
    int64_t symid = scan_int(&p);
    if (*p == '=') {
      p += 3;                                        /* "=(F" */
      int64_t fid = scan_int(&p);
      if ((size_t)fid + 1 > lbcap) { size_t nc = lbcap ? lbcap*2 : 64; while (nc < (size_t)fid+1) nc*=2;
        localbin = xrealloc(localbin, nc*sizeof *localbin); for (size_t i=lbcap;i<nc;i++) localbin[i]=-1; lbcap=nc; }
      if (*p == '=') {                               /* F<fid>=(<path>) definition */
        p += 2; const char *fn = p; while (*p && *p != ')') p++;
        localbin[fid] = bin_for(fn, (uint32_t)(p - fn)); p++;
      }
      p++;                                           /* '+' */
      int64_t binoff = scan_int(&p);
      p += 4;                                         /* " N=(" */
      const char *nm = p; while (*p && *p != ')') p++;
      uint32_t nl = (uint32_t)(p - nm);
      if (nl == 6 && !memcmp(nm, "@?(nil", 6)) { nl = 7; p++; }
      p++;                                            /* ')' of N=( */
      if ((size_t)symid + 1 > cap) { size_t nc = cap ? cap*2 : 1024; while (nc < (size_t)symid+1) nc*=2;
        syms = xrealloc(syms, nc*sizeof *syms); memset(syms+cap, 0, (nc-cap)*sizeof *syms); cap = nc; }
      if ((size_t)symid + 1 > nsyms) nsyms = symid + 1;
      int32_t b = ((size_t)fid < lbcap) ? localbin[fid] : -1;
      syms[symid].raw = nm; syms[symid].rawlen = nl; syms[symid].binoff = binoff; syms[symid].bin = b;
      if (nl >= 2 && nm[0] == '@' && nm[1] == '?' && b >= 0)
        bin_add_req(b, (uint64_t)binoff, d, (int)symid);
      p++;                                            /* ')' of FN=( */
    }
    while (*p && *p != '\n') p++;                     /* skip counters/rest */
    if (*p) p++;
  }
  free(localbin);
  D->syms = syms; D->nsyms = nsyms;
}

/* --------------------------------------------------------- demangle + nm */

static char *humanize(const char *name, size_t len) {
  if (len > 2 && name[0] == '_' && name[1] == 'Z') {
    char buf[1 << 16];
    if (len < sizeof buf) { memcpy(buf, name, len); buf[len] = 0; int st;
      char *dd = __cxa_demangle(buf, NULL, NULL, &st); if (!st && dd) return dd; }
  }
  char *c = xmalloc(len + 1); memcpy(c, name, len); c[len] = 0; return c;
}

static int load_vmbase(const char *path, uint64_t *vmbase) {
  char cmd[8192]; snprintf(cmd, sizeof cmd, "objdump -p '%s' 2>/dev/null", path);
  FILE *f = popen(cmd, "r"); if (!f) return 0;
  char line[4096]; int ok = 0;
  while (fgets(line, sizeof line, f)) {
    char *s = line; while (*s == ' ' || *s == '\t') s++;
    if (strncmp(s, "LOAD", 4)) continue;
    char *o = strstr(s, "off"), *v = strstr(s, "vaddr"); if (!o || !v) continue;
    *vmbase = strtoull(v + 5, NULL, 16) - strtoull(o + 3, NULL, 16); ok = 1; break;
  }
  pclose(f); return ok;
}

static int reqcmp(const void *a, const void *b) {
  uint64_t x = ((const Req *)a)->off, y = ((const Req *)b)->off; return x < y ? -1 : x > y ? 1 : 0;
}

/* Resolve a binary's queued FN offsets in one streamed nm pass, holding a
 * single symbol name at a time and allocating only per resolved FN. */
static void resolve_bin(Bin *B) {
  if (!B->nreq) return;
  uint64_t vmbase = 0;
  if (!load_vmbase(B->path, &vmbase)) return;          /* unresolved => placeholder */
  qsort(B->req, B->nreq, sizeof *B->req, reqcmp);

  char cmd[8192]; snprintf(cmd, sizeof cmd, "nm -t d -n '%s' 2>/dev/null", B->path);
  FILE *f = popen(cmd, "r"); if (!f) return;
  static __thread char line[1 << 16], held[1 << 16];
  int have = 0; size_t ti = 0;
  while (ti < B->nreq && fgets(line, sizeof line, f)) {
    char *s = line, *end = NULL;
    uint64_t addr = strtoull(s, &end, 10);
    if (end == s) continue;                            /* undefined symbol */
    while (*end == ' ' || *end == '\t') end++;
    if (end[1] != ' ' && end[1] != '\t') continue;     /* single-char type field */
    char *name = end + 1; while (*name == ' ' || *name == '\t') name++;
    if (*name == '.' || !*name) continue;
    char *nl = strchr(name, '\n'); if (nl) *nl = 0;
    uint64_t off = addr - vmbase;
    while (ti < B->nreq && B->req[ti].off < off) {
      Req *r = &B->req[ti++];
      if (have) dumps[r->dump].syms[r->fn].out = humanize(held, strlen(held));
    }
    memcpy(held, name, strlen(name) + 1); have = 1;
  }
  while (ti < B->nreq) {
    Req *r = &B->req[ti++];
    if (have) dumps[r->dump].syms[r->fn].out = humanize(held, strlen(held));
  }
  pclose(f);
}

static size_t g_next; static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static void *worker(void *a) { (void)a;
  for (;;) { pthread_mutex_lock(&g_lock); size_t i = g_next++; pthread_mutex_unlock(&g_lock);
    if (i >= nbins) break;
    resolve_bin(&bins[i]); }
  return NULL;
}

/* ------------------------------------------------------------------- main */

static char *slurp(const char *path, size_t *outlen) {
  int fd = 0;
  if (path && strcmp(path, "-")) { fd = open(path, O_RDONLY); if (fd < 0) die("cannot open dump"); }
  size_t cap = 1 << 20, len = 0; char *buf = xmalloc(cap);
  for (;;) { if (len + (1<<20) + 1 > cap) buf = xrealloc(buf, cap *= 2);
    ssize_t n = read(fd, buf + len, 1<<20); if (n < 0) die("read"); if (!n) break; len += n; }
  if (fd) close(fd);
  buf[len] = 0; if (outlen) *outlen = len; return buf;
}

/* write one dump's side-car: <fnid>\t<human name> */
static void emit(int d, FILE *out) {
  Dump *D = &dumps[d]; size_t resolved = 0, total = 0;
  for (size_t i = 0; i < D->nsyms; i++) {
    Sym *s = &D->syms[i]; if (!s->raw) continue; total++;
    if (s->out) { fprintf(out, "%zu\t%s\n", i, s->out); resolved++; continue; }
    if (s->rawlen >= 2 && s->raw[0] == '@' && s->raw[1] == '?') {  /* unresolved @? */
      const char *bn = "?"; if (s->bin >= 0) { const char *p = bins[s->bin].path, *sl = strrchr(p, '/'); bn = sl ? sl + 1 : p; }
      fprintf(out, "%zu\t@{%s+%" PRId64 "}\n", i, bn, s->binoff);
    } else {
      char *h = humanize(s->raw, s->rawlen); fprintf(out, "%zu\t%s\n", i, h); free(h);
    }
  }
  fprintf(stderr, "  %s: %zu symbols, %zu @?-resolved\n", D->path ? D->path : "<stdin>", total, resolved);
}

int main(int argc, char **argv) {
  int jobs = 4; const char **inputs = xmalloc(argc * sizeof *inputs); int nin = 0;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-j") && i + 1 < argc) jobs = atoi(argv[++i]);
    else inputs[nin++] = argv[i];
  }
  if (!nin) inputs[nin++] = "-";

  dumps = xmalloc(nin * sizeof *dumps); ndumps = nin;
  for (int d = 0; d < nin; d++) {
    dumps[d].path = (!strcmp(inputs[d], "-")) ? NULL : (char *)inputs[d];
    dumps[d].buf = slurp(inputs[d], NULL);
    parse_dump(d, dumps[d].buf);
  }

  if (jobs < 1) jobs = 1;
  pthread_t *th = xmalloc(jobs * sizeof *th);
  for (int i = 0; i < jobs; i++) pthread_create(&th[i], NULL, worker, NULL);
  for (int i = 0; i < jobs; i++) pthread_join(th[i], NULL);

  fprintf(stderr, "igprof-demangle-symbols: %zu dumps, %zu binaries, -j%d\n", ndumps, nbins, jobs);
  for (int d = 0; d < nin; d++) {
    if (!dumps[d].path) { emit(d, stdout); continue; }   /* stdin -> stdout (caller may gzip) */
    char cmd[8192]; snprintf(cmd, sizeof cmd, "gzip -c > '%s.syms.gz'", dumps[d].path);
    FILE *f = popen(cmd, "w"); if (!f) die("cannot write side-car");
    emit(d, f); pclose(f);
  }
  return 0;
}
