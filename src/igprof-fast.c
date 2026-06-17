/* igprof-fast — fast streaming reader for IgProf dumps, built for interactive
 * / MCP-style drill-down: each invocation re-reads the dump and aggregates only
 * what the query needs, so demangling stays trivial (only the symbols on the
 * answer are demangled, never the whole table).
 *
 * Dump grammar (one line per call-stack node, pre-order DFS, tree position in
 * the C<depth> prefix; `HEX ` in the header => all integers base-16; names are
 * mangled, so the N=(...) terminator ')' is unambiguous):
 *
 *   P=(HEX ID=<pid> N=(<prog>) T=<clockres>)
 *   C<depth> FN<id>[=(F<fid>[=(<file>)]+<binoff> N=(<name>))]+<symoff> \
 *            [ V<cid>[=(<ctrname>)]:(<count>,<bytes>,<peak>)]... [;LK=(<a>,<s>)]...
 *
 * Modes:
 *   igprof-fast [-k CTR] top  [-n N]            flat ranked self/cumulative
 *   igprof-fast [-k CTR] show -s REGEX          one symbol: callers + callees
 *   igprof-fast [-k CTR] show -r RANK           ditto, symbol = RANK-th of `top`
 * Input is a positional dump path or stdin:
 *   gzip -dc igprof.*.gz | igprof-fast show -s DCAFitter
 *
 * Build: cc -O2 -DIGPROF_DEMANGLE -o igprof-fast igprof-fast.c -lstdc++
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <regex.h>

#ifdef IGPROF_DEMANGLE
extern char *__cxa_demangle(const char *, char *, size_t *, int *);
#endif

/* ----------------------------------------------------------------- tables */

typedef struct { const char *name; uint32_t namelen; int64_t fileoff; int32_t fileid; int32_t gid; } Sym;
typedef struct { const char *name; uint32_t namelen; } Str;

static Sym  *syms;  static size_t nsyms,  capsyms;
static Str  *files; static size_t nfiles, capfiles;
static Str  *ctrs;  static size_t nctrs,  capctrs;

/* Name groups: distinct display names interned to a small integer id while the
 * dump streams (once per FN definition, not per node). All aggregation keys on
 * the group id, so symbols that share a display name — one function emitted
 * under several FN ids / call sites, or distinct @? addresses the side-car
 * resolves to the same name — merge automatically, recursion dedup included,
 * with no error-prone post-pass. `match` (set at definition) marks groups
 * selected by `show`. */
typedef struct { const char *name; uint32_t namelen, hash; uint8_t resolved, match, mallocish, igprofish; } Group;
static Group *groups; static size_t ngroups, capgroups;
static int32_t *ghash; static size_t ghcap;   /* open-addressed name->gid; -1 = empty */

static int   key_ctr = -1;
static const char *key_name = NULL;
static int   key_is_max = 0;     /* selected counter is a peak/MAX: aggregate by max, not sum */
static int   g_base = 10;

/* Frame collapsing, matching igprof-analyse's post filters so self/cumulative
 * splits agree (cumulative totals already agree without it).
 *
 *  - MallocFilter: for any MEM_* counter, an allocator frame's bytes belong to
 *    its caller's *self*, not to a separate "operator new"/"malloc" callee. The
 *    frame is removed and its counter added to the parent (igprof-analyse
 *    src/analyse.cc MallocFilter). Gated on g_collapse_malloc (set when the key
 *    counter is recognised as MEM_*).
 *  - RemoveIgProfFilter: the injected profiler's own frames (symbols whose file
 *    is libigprof/IgProf/IgHook) are likewise merged into the caller; always on.
 *
 * Both are "remove node, reparent its children to the parent, add its own
 * counter to the parent" — modelled below by retargeting the node's self to the
 * caller group and reparenting the stack slot so any children attribute to the
 * caller too. */
static int   g_collapse_malloc = 0;

/* Exact raw-name match against igprof-analyse's MallocFilter set. */
static int is_malloc_name(const char *s, uint32_t n)
{
  static const char *const A[] = {
    "malloc", "calloc", "realloc", "memalign", "posix_memalign", "aligned_alloc",
    "valloc", "zmalloc", "zcalloc", "zrealloc", "_Znwj", "_Znwm", "_Znaj", "_Znam"
  };
  for (size_t i = 0; i < sizeof A / sizeof *A; i++)
    if (strlen(A[i]) == n && !memcmp(A[i], s, n)) return 1;
  return 0;
}

/* RemoveIgProfFilter: a frame belonging to the injected profiler library. */
static int is_igprof_file(const char *s, uint32_t n)
{
  /* substring search over the (short) file name, like igprof-analyse */
  static const char *const L[] = { "libigprof.", "IgProf.", "IgHook." };
  for (size_t i = 0; i < sizeof L / sizeof *L; i++)
  {
    size_t ln = strlen(L[i]);
    if (n < ln) continue;
    for (uint32_t j = 0; j + ln <= n; j++)
      if (!memcmp(s + j, L[i], ln)) return 1;
  }
  return 0;
}

static void die(const char *m) { fprintf(stderr, "igprof-fast: %s\n", m); exit(1); }

static void *xgrow(void *p, size_t *cap, size_t need, size_t elem) {
  if (need <= *cap) return p;
  size_t nc = *cap ? *cap : 4096;
  while (nc < need) nc *= 2;
  p = realloc(p, nc * elem);
  if (!p) die("oom");
  *cap = nc;
  return p;
}

/* the selector for `show`: matched against the display name at definition time */
static regex_t  g_re; static int g_re_on = 0;
static int64_t  g_pick_gid = -1;     /* -r RANK resolves to this group id */

/* optional side-car (from igprof-demangle-symbols): fn id -> resolved name.
 * When present, names are already human-readable: used for display and for
 * matching `show -s`, and no demangling/binaries are needed here. */
static char   **sc; static size_t sc_cap;

static void load_sidecar(const char *path) {
  size_t pl = strlen(path); int gz = pl > 3 && !strcmp(path + pl - 3, ".gz");
  FILE *f; char cmd[8192];
  if (gz) { snprintf(cmd, sizeof cmd, "gzip -dc '%s'", path); f = popen(cmd, "r"); }
  else f = fopen(path, "r");
  if (!f) { perror(path); exit(1); }
  char *line = NULL; size_t lc = 0; ssize_t n;
  while ((n = getline(&line, &lc, f)) > 0) {
    char *tab = memchr(line, '\t', n); if (!tab) continue;
    *tab = 0; size_t id = strtoull(line, NULL, 10);
    char *nm = tab + 1, *nl = memchr(nm, '\n', line + n - nm); if (nl) *nl = 0;
    if (id + 1 > sc_cap) { size_t nc = sc_cap ? sc_cap * 2 : 4096; while (nc < id + 1) nc *= 2;
      sc = realloc(sc, nc * sizeof *sc); for (size_t i = sc_cap; i < nc; i++) sc[i] = NULL; sc_cap = nc; }
    free(sc[id]); sc[id] = strdup(nm);
  }
  free(line); if (gz) pclose(f); else fclose(f);
}

static void ensure_sym(size_t id) {
  size_t old = capsyms;
  syms = xgrow(syms, &capsyms, id + 1, sizeof *syms);
  if (capsyms != old) memset(syms + nsyms, 0, (capsyms - nsyms) * sizeof *syms);
  if (id + 1 > nsyms) {
    for (size_t i = nsyms; i <= id; i++) { syms[i].name = NULL; syms[i].gid = -1; }
    nsyms = id + 1;
  }
}

/* Intern a display name to its group id (creating a group on first sight). */
static uint32_t name_hash(const char *s, uint32_t n) {
  uint32_t h = 2166136261u;
  for (uint32_t i = 0; i < n; i++) { h ^= (unsigned char)s[i]; h *= 16777619u; }
  return h;
}
static void ghash_insert(int32_t gid) {
  size_t mask = ghcap - 1, i = groups[gid].hash & mask;
  while (ghash[i] >= 0) i = (i + 1) & mask;
  ghash[i] = gid;
}
static int32_t intern(const char *s, uint32_t n, uint8_t resolved) {
  if (ghcap == 0 || ngroups * 10 >= ghcap * 7) {        /* grow + rehash at 70% load */
    size_t nc = ghcap ? ghcap * 2 : 8192;
    ghash = realloc(ghash, nc * sizeof *ghash); if (!ghash) die("oom");
    for (size_t i = 0; i < nc; i++) ghash[i] = -1;
    ghcap = nc;
    for (size_t g = 0; g < ngroups; g++) ghash_insert((int32_t)g);
  }
  uint32_t h = name_hash(s, n);
  size_t mask = ghcap - 1, i = h & mask;
  while (ghash[i] >= 0) {
    int32_t g = ghash[i];
    if (groups[g].hash == h && groups[g].namelen == n && !memcmp(groups[g].name, s, n)) return g;
    i = (i + 1) & mask;
  }
  groups = xgrow(groups, &capgroups, ngroups + 1, sizeof *groups);
  groups[ngroups] = (Group){ s, n, h, resolved, 0, 0, 0 };
  ghash[i] = (int32_t)ngroups;
  return (int32_t)ngroups++;
}

/* ----------------------------------------------------------------- scanner */

static inline int64_t scan_int(const char **pp) {
  const char *p = *pp; int64_t v = 0;
  if (g_base == 16) {
    for (;; p++) {
      unsigned c = (unsigned char)*p;
      if      (c >= '0' && c <= '9') v = (v << 4) | (c - '0');
      else if (c >= 'a' && c <= 'f') v = (v << 4) | (c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') v = (v << 4) | (c - 'A' + 10);
      else break;
    }
  } else {
    int neg = (*p == '-'); if (neg) p++;
    for (; *p >= '0' && *p <= '9'; p++) v = v * 10 + (*p - '0');
    if (neg) v = -v;
  }
  *pp = p;
  return v;
}

/* One parsed node: the fields both modes need (key counter only). */
typedef struct { int64_t depth, symid, key_cnt, key_bytes; int has_key; } Node;

static const char *parse_header(const char *p) {
  if (strncmp(p, "P=(", 3)) die("not an igprof dump");
  p += 3;
  if (*p == 'H') { g_base = 16; p += 4; }
  while (*p && *p != '\n') p++;
  return *p ? p + 1 : p;
}

/* Advance one node line, updating the string tables; return 0 at end.
 *
 * Robust to truncated / interleaved lines: IgProf dumps are written from a
 * signal handler and, when a process forks or several buffers flush, records
 * can splice into one another (e.g. a `V2:` with no value followed by another
 * record's counters, no newline between). Every field scan is therefore bounded
 * to the current line and the parser always resyncs at the next newline rather
 * than trusting the byte layout — a single corrupt line costs one node, not the
 * rest of the file. */
static int next_node(const char **pp, Node *out) {
  const char *p = *pp;
  while (*p && *p != 'C') {                 /* resync: skip header/blank/garbage lines */
    while (*p && *p != '\n') p++;
    if (*p == '\n') p++;
  }
  if (!*p) return 0;
  p++;                                      /* 'C' */
  out->depth = scan_int(&p);
  p += 3;                                  /* " FN" */
  int64_t symid = scan_int(&p);
  if (*p == '=') {
    p += 3;                                /* "=(F" */
    int64_t fid = scan_int(&p);
    if (*p == '=') {
      p += 2;                              /* "=(" */
      const char *fn = p; while (*p && *p != ')' && *p != '\n') p++;
      files = xgrow(files, &capfiles, fid + 1, sizeof *files);
      files[fid].name = fn; files[fid].namelen = (uint32_t)(p - fn);
      if ((size_t)fid + 1 > nfiles) nfiles = fid + 1;
      if (*p == ')') p++;
    }
    if (*p == '+') p++;                     /* '+' */
    int64_t binoff = scan_int(&p);
    p += 4;                                /* " N=(" */
    const char *nm = p; while (*p && *p != ')' && *p != '\n') p++;
    uint32_t nl = (uint32_t)(p - nm);
    if (nl == 6 && !memcmp(nm, "@?(nil", 6)) { nl = 7; if (*p == ')') p++; }
    if (*p == ')') p++;                    /* ')' of N=( */
    ensure_sym(symid);
    syms[symid].name = nm; syms[symid].namelen = nl;
    syms[symid].fileoff = binoff; syms[symid].fileid = (int32_t)fid;
    /* Intern by the *display* name (side-car resolved if available, else the raw
     * mangled bytes) so the grouping matches what is printed. */
    const char *kn; uint32_t kl; uint8_t res;
    if (sc && (size_t)symid < sc_cap && sc[symid]) { kn = sc[symid]; kl = (uint32_t)strlen(sc[symid]); res = 1; }
    else { kn = nm; kl = nl; res = 0; }
    int32_t gid = intern(kn, kl, res);
    syms[symid].gid = gid;
    /* Classify for frame collapsing on the *raw* dump name/file, exactly the
       fields igprof-analyse matches (node->symbol()->NAME and ->FILE->NAME). */
    if (is_malloc_name(nm, nl)) groups[gid].mallocish = 1;
    if ((size_t)fid < nfiles && files[fid].name
        && is_igprof_file(files[fid].name, files[fid].namelen)) groups[gid].igprofish = 1;
    if (g_pick_gid >= 0) { if (gid == g_pick_gid) groups[gid].match = 1; }
    else if (g_re_on && !groups[gid].match) {
      char tmp[8192]; const char *mn = NULL;
      if (res) mn = kn;                                 /* already NUL-terminated */
      else if (kl < sizeof tmp) { memcpy(tmp, kn, kl); tmp[kl] = 0; mn = tmp; }
      if (mn && regexec(&g_re, mn, 0, NULL, 0) == 0) groups[gid].match = 1;
    }
    if (*p == ')') p++;                    /* ')' of FN=( */
  }
  out->symid = symid;
  if (*p == '+') { p++; scan_int(&p); }    /* per-call sym offset (unused) */

  out->has_key = 0; out->key_cnt = out->key_bytes = 0;
  while (*p == ' ' && p[1] == 'V') {
    p += 2;                                /* " V" */
    int64_t cid = scan_int(&p);
    if (*p == '=') {                       /* "=(name)" counter definition */
      p += 2; const char *cn = p; while (*p && *p != ')' && *p != '\n') p++;
      if (*p != ')') break;                /* truncated def: resync at newline */
      ctrs = xgrow(ctrs, &capctrs, cid + 1, sizeof *ctrs);
      ctrs[cid].name = cn; ctrs[cid].namelen = (uint32_t)(p - cn);
      if ((size_t)cid + 1 > nctrs) nctrs = cid + 1;
      p++;
      if (key_ctr < 0 && (!key_name ||
          (strlen(key_name) == ctrs[cid].namelen && !memcmp(key_name, cn, ctrs[cid].namelen)))) {
        key_ctr = (int)cid;
        /* The dump does not encode counter accumulation type, so recognise the
         * peak counter (MEM_MAX) by name: it must be reduced by max, not sum. */
        key_is_max = (ctrs[cid].namelen >= 3 &&
                      !memcmp(cn + ctrs[cid].namelen - 3, "MAX", 3));
        /* igprof-analyse adds the MallocFilter only for MEM_* counters. */
        g_collapse_malloc = (ctrs[cid].namelen >= 4 && !memcmp(cn, "MEM_", 4));
      }
    }
    if (p[0] != ':' || p[1] != '(') break; /* truncated/interleaved record: resync */
    p += 2;                                /* ":(" */
    int64_t cnt = scan_int(&p); if (*p != ',') break; p++;
    int64_t bytes = scan_int(&p); if (*p != ',') break; p++;
    scan_int(&p); if (*p != ')') break; p++; /* peak ')' */
    while (*p == ';') { while (*p && *p != ')' && *p != '\n') p++; if (*p == ')') p++; }  /* LK */
    if ((int)cid == key_ctr) { out->has_key = 1; out->key_cnt += cnt; out->key_bytes += bytes; }
  }
  while (*p && *p != '\n') p++;            /* always resync to the line boundary */
  if (*p == '\n') p++;
  *pp = p;
  return 1;
}

/* --------------------------------------------------------------- printing */

static void print_group(int32_t gid) {
  const Group *g = &groups[gid];
  if (g->resolved) { fwrite(g->name, 1, g->namelen, stdout); return; }  /* side-car: ready */
#ifdef IGPROF_DEMANGLE
  if (g->namelen > 2 && g->name[0] == '_' && g->name[1] == 'Z' && g->namelen < 8192) {
    char m[8192]; memcpy(m, g->name, g->namelen); m[g->namelen] = 0;
    int st; char *d = __cxa_demangle(m, NULL, NULL, &st);
    if (!st && d) { fputs(d, stdout); free(d); return; }
  }
#endif
  fwrite(g->name, 1, g->namelen, stdout);
}

/* ------------------------------------------------------------- mode: top */

static int64_t *t_self, *t_cnt, *t_cumul; static uint32_t *t_seen;
static int32_t *t_stack; static size_t t_scap;

static int t_cmp(const void *a, const void *b) {
  int32_t ia = *(const int32_t *)a, ib = *(const int32_t *)b;
  return t_cumul[ia] < t_cumul[ib] ? 1 : t_cumul[ia] > t_cumul[ib] ? -1 : 0;
}

static int32_t *aggregate_top(const char *p, size_t *nout) {
  Node nd; uint32_t serial = 0;
  while (next_node(&p, &nd)) {
    int64_t lvl = nd.depth - 1;
    if ((size_t)(lvl + 1) > t_scap) {
      size_t oc = t_scap;
      t_stack = xgrow(t_stack, &t_scap, lvl + 1, sizeof *t_stack); (void)oc;
    }
    int32_t g = syms[nd.symid].gid;
    if (g < 0) g = syms[nd.symid].gid = intern("", 0, 0);   /* corrupt: undefined ref */
    /* per-group arrays grow with ngroups */
    static size_t acap = 0;
    if (ngroups > acap) {
      t_self  = realloc(t_self,  ngroups * sizeof *t_self);
      t_cnt   = realloc(t_cnt,   ngroups * sizeof *t_cnt);
      t_cumul = realloc(t_cumul, ngroups * sizeof *t_cumul);
      t_seen  = realloc(t_seen,  ngroups * sizeof *t_seen);
      for (size_t i = acap; i < ngroups; i++) { t_self[i]=t_cnt[i]=t_cumul[i]=0; t_seen[i]=0; }
      acap = ngroups;
    }
    /* Collapse allocator / profiler frames into the caller: attribute this
       node's self to the parent group (tg) and reparent its stack slot so any
       children attribute to the parent too; the node's own cumulative stops at
       the parent (top). With no parent (lvl 0) the frame stays as-is, like
       igprof-analyse's `if (!parent) return`. */
    int collapse = groups[g].igprofish || (groups[g].mallocish && g_collapse_malloc);
    int32_t tg = g; int64_t top = lvl;
    if (collapse && lvl > 0) { tg = t_stack[lvl - 1]; top = lvl - 1; }
    t_stack[lvl] = tg;
    if (nd.has_key) {
      t_cnt[tg] += nd.key_cnt;
      if (key_is_max) {                       /* peak counter: reduce by max */
        if (nd.key_bytes > t_self[tg]) t_self[tg] = nd.key_bytes;
        for (int64_t l = 0; l <= top; l++) {  /* max is idempotent: no dedup needed */
          int32_t s = t_stack[l];
          if (nd.key_bytes > t_cumul[s]) t_cumul[s] = nd.key_bytes;
        }
        continue;
      }
      t_self[tg] += nd.key_bytes;
      serial++;
      /* dedup per group: a stack with the same name twice (recursion, or two FN
       * ids that share a name) still counts its cumulative once. */
      for (int64_t l = 0; l <= top; l++) {
        int32_t s = t_stack[l];
        if (t_seen[s] != serial) { t_seen[s] = serial; t_cumul[s] += nd.key_bytes; }
      }
    }
  }
  int32_t *order = malloc((ngroups ? ngroups : 1) * sizeof *order); size_t m = 0;
  for (size_t i = 0; i < ngroups; i++)
    if (t_cumul[i] || t_self[i]) order[m++] = (int32_t)i;
  qsort(order, m, sizeof *order, t_cmp);
  *nout = m;
  return order;
}

/* -------------------------------------------------------------- mode: show
 * Closing-based subtree sums: nodecum[L] accumulates the subtree of the node
 * currently open at depth L. When it closes (a shallower line arrives), its
 * total bubbles into the parent and lands on a caller/callee edge if either end
 * is the selected symbol. */

static int64_t s_self = 0, s_cumul = 0, s_cnt = 0;
static int64_t *caller, *callee;            /* indexed by group id */
static int32_t *touch; static size_t ntouch;
static int64_t *nc, *nf, *nfc; static int32_t *sstk; static int32_t *nmatch;
static uint8_t *scol; static size_t s_scap;

static void touch_mark(int32_t g) { if (caller[g] == 0 && callee[g] == 0) touch[ntouch++] = g; }

/* Reduce v into *a per the selected counter's accumulation type. */
static inline void accum(int64_t *a, int64_t v) {
  if (key_is_max) { if (v > *a) *a = v; } else *a += v;
}

static void close_level(int64_t L) {
  if (L < 0) return;
  int32_t sym = sstk[L];                     /* group id of the node closing */
  int32_t par = L > 0 ? sstk[L - 1] : -1;    /* group id of its caller */
  if (scol[L]) {                             /* collapsed allocator/profiler frame */
    /* Its slot was reparented to the caller (sym == par): fold this frame's own
       self and self-count into the caller, propagate its subtree, no edge. */
    if (L > 0) { accum(&nf[L - 1], nf[L]);
                 if (groups[par].match) s_cnt += nfc[L];
                 accum(&nc[L - 1], nc[L]); }
    nc[L] = nf[L] = nfc[L] = 0;
    return;
  }
  if (groups[sym].match) {                   /* selected node closing */
    accum(&s_self, nf[L]);
    /* headline cumulative counts each stack once: only the outermost selected
     * group on the path contributes (recursion dedup). nmatch[L-1] = number of
     * selected groups strictly above L. (For a max counter the dedup is moot —
     * max is idempotent — but the guard is harmless.) */
    if (L == 0 || nmatch[L - 1] == 0) accum(&s_cumul, nc[L]);
    /* Only record non-empty edges. Beyond avoiding clutter, this keeps the
     * touch-list dedup correct: touch_mark() treats a group as new while both
     * its caller/callee weights are zero, so touching on a zero-weight edge
     * would re-add it every time and overflow `touch` (MEM_LIVE dumps are full
     * of freed, zero-live subtrees). */
    if (par >= 0 && nc[L]) { touch_mark(par); accum(&caller[par], nc[L]); }
  }
  if (par >= 0 && nc[L] && groups[par].match) { /* parent is selected => this is a callee */
    touch_mark(sym); accum(&callee[sym], nc[L]);
  }
  if (L > 0) accum(&nc[L - 1], nc[L]);
  nc[L] = nf[L] = nfc[L] = 0;
}

static void aggregate_show(const char *p) {
  size_t acap = 0; int64_t cur = -1;
  Node nd;
  while (next_node(&p, &nd)) {
    int64_t lvl = nd.depth - 1;
    int32_t g = syms[nd.symid].gid;
    if (g < 0) g = syms[nd.symid].gid = intern("", 0, 0);   /* corrupt: undefined ref */
    if (ngroups > acap) {                    /* per-group edge arrays grow with ngroups */
      caller = realloc(caller, ngroups * sizeof *caller);
      callee = realloc(callee, ngroups * sizeof *callee);
      touch  = realloc(touch,  ngroups * sizeof *touch);
      for (size_t i = acap; i < ngroups; i++) { caller[i] = callee[i] = 0; }
      acap = ngroups;
    }
    if ((size_t)(lvl + 1) > s_scap) {
      sstk = xgrow(sstk, &s_scap, lvl + 1, sizeof *sstk);
      nc = realloc(nc, s_scap * sizeof *nc);
      nf = realloc(nf, s_scap * sizeof *nf);
      nfc = realloc(nfc, s_scap * sizeof *nfc);
      nmatch = realloc(nmatch, s_scap * sizeof *nmatch);
      scol = realloc(scol, s_scap * sizeof *scol);
    }
    for (int64_t L = cur; L >= lvl; L--) close_level(L);   /* close siblings/ancestors */
    /* Collapse allocator/profiler frames: reparent the stack slot to the caller
       so the frame's self folds into the caller and its children attribute to
       the caller too (see aggregate_top for the same model). */
    int collapse = lvl > 0 && (groups[g].igprofish || (groups[g].mallocish && g_collapse_malloc));
    int32_t sg = collapse ? sstk[lvl - 1] : g;
    sstk[lvl] = sg; scol[lvl] = collapse; cur = lvl;
    nc[lvl] = nf[lvl] = 0; nfc[lvl] = nd.has_key ? nd.key_cnt : 0;
    nmatch[lvl] = (lvl ? nmatch[lvl - 1] : 0) + (!collapse && groups[sg].match ? 1 : 0);
    if (nd.has_key) { accum(&nc[lvl], nd.key_bytes); accum(&nf[lvl], nd.key_bytes);
                      if (!collapse && groups[sg].match) s_cnt += nd.key_cnt; }
  }
  for (int64_t L = cur; L >= 0; L--) close_level(L);       /* flush at EOF */
}

/* Edges are already keyed by group id, so caller[]/callee[] are merged by name
 * by construction — printing is just a weight sort over the touched groups, no
 * string work. */
typedef struct { int32_t gid; int64_t w; } Edge;
static int edge_by_weight(const void *a, const void *b) {
  int64_t wa = ((const Edge *)a)->w, wb = ((const Edge *)b)->w;
  return wa < wb ? 1 : wa > wb ? -1 : 0;
}
static void print_edges(const int64_t *w) {
  Edge *e = malloc((ntouch ? ntouch : 1) * sizeof *e); size_t n = 0;
  for (size_t i = 0; i < ntouch; i++) { int32_t g = touch[i];
    if (w[g]) { e[n].gid = g; e[n].w = w[g]; n++; } }
  qsort(e, n, sizeof *e, edge_by_weight);
  for (size_t i = 0; i < n; i++) { printf("  %18" PRId64 "  ", e[i].w); print_group(e[i].gid); putchar('\n'); }
  free(e);
}

/* ------------------------------------------------------------------- main */

int main(int argc, char **argv) {
  const char *mode = NULL, *path = NULL, *re = NULL, *sidecar = NULL; int top = 40; long rank = -1;
  for (int i = 1; i < argc; i++) {
    if      (!strcmp(argv[i], "-k") && i + 1 < argc) key_name = argv[++i];
    else if (!strcmp(argv[i], "-n") && i + 1 < argc) top = atoi(argv[++i]);
    else if (!strcmp(argv[i], "-s") && i + 1 < argc) re = argv[++i];
    else if (!strcmp(argv[i], "-r") && i + 1 < argc) rank = atol(argv[++i]);
    else if (!strcmp(argv[i], "-S") && i + 1 < argc) sidecar = argv[++i];
    else if (!strcmp(argv[i], "top") || !strcmp(argv[i], "show")) mode = argv[i];
    else path = argv[i];
  }
  if (!mode) die("usage: igprof-fast [-k CTR] top [-n N] | show (-s REGEX | -r RANK) [dump]");

  int fd = 0;
  if (path && strcmp(path, "-")) { fd = open(path, O_RDONLY); if (fd < 0) die("cannot open dump"); }
  size_t cap = 1 << 20, len = 0; char *buf = malloc(cap);
  for (;;) {
    if (len + (1 << 20) + 1 > cap) { cap *= 2; buf = realloc(buf, cap); if (!buf) die("oom"); }
    ssize_t n = read(fd, buf + len, 1 << 20);
    if (n < 0) die("read"); if (!n) break; len += (size_t)n;
  }
  buf[len] = 0;
  if (sidecar) load_sidecar(sidecar);

  /* -r RANK: a quick `top` pass selects the group, then we show it. */
  if (mode[1] == 'h' && rank > 0) {
    const char *p = parse_header(buf); size_t m; int32_t *o = aggregate_top(p, &m);
    if ((size_t)rank > m) die("rank out of range");
    g_pick_gid = o[rank - 1];
    /* reset for the show re-read; keep the interned groups (re-parsing yields
     * the same ids) but clear the per-pass match flags and counter selection. */
    nsyms = nfiles = nctrs = 0; key_ctr = -1; key_is_max = 0; g_collapse_malloc = 0;
    memset(syms, 0, capsyms * sizeof *syms);
    for (size_t g = 0; g < ngroups; g++) groups[g].match = 0;
  } else if (mode[1] == 'h') {
    if (!re) die("show needs -s REGEX or -r RANK");
    if (regcomp(&g_re, re, REG_EXTENDED | REG_NOSUB)) die("bad regex");
    g_re_on = 1;
  }

  const char *p = parse_header(buf);

  if (mode[1] == 'o') {                       /* top */
    size_t m; int32_t *order = aggregate_top(p, &m);
    if (key_ctr < 0) die("no matching counter");
    fprintf(stderr, "counter=%.*s symbols=%zu\n", (int)ctrs[key_ctr].namelen, ctrs[key_ctr].name, m);
    printf("%5s  %18s  %18s  %12s  symbol\n", "rank", "cumulative", "self", "self-count");
    for (size_t i = 0; i < m && (int)i < top; i++) {
      int32_t s = order[i];
      printf("%5zu  %18" PRId64 "  %18" PRId64 "  %12" PRId64 "  ", i + 1, t_cumul[s], t_self[s], t_cnt[s]);
      print_group(s); putchar('\n');
    }
  } else {                                    /* show */
    aggregate_show(p);
    if (key_ctr < 0) die("no matching counter");
    int32_t self_gid = (int32_t)g_pick_gid;
    for (size_t i = 0; self_gid < 0 && i < ngroups; i++) if (groups[i].match) self_gid = (int32_t)i;
    fprintf(stderr, "counter=%.*s\n", (int)ctrs[key_ctr].namelen, ctrs[key_ctr].name);
    printf("== selected ==\n  cumulative=%" PRId64 "  self=%" PRId64 "  self-count=%" PRId64 "  ",
           s_cumul, s_self, s_cnt);
    if (self_gid >= 0) print_group(self_gid);
    printf("\n== callers (memory through the selected symbol, by caller) ==\n");
    print_edges(caller);
    printf("== callees (memory the selected symbol spends, by callee) ==\n");
    print_edges(callee);
  }
  return 0;
}
