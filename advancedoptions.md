---
title: Advanced Options
layout: default
related:
 - { name: Top, link: . }
 - { name: Downloads, link: "https://github.com/igprof/igprof/tags" }
 - { name: Bugs, link: "https://github.com/igprof/igprof/issues" }
 - { name: Project, link: "https://github.com/igprof/igprof/" }
---
## Empty memory profiler:

The empty memory profiler identifies large allocations of potentially unused
memory. To do so, it scans allocated memory for runs of 4096 bytes or more
containing a pattern that indicates unused memory. The memory scan takes place
on `free()` and during a live heap walk. The results are stored in the `MEM_LIVE`
counter for both freed and leaked memory. The recorded stack frames always
belong to the resource allocation.

In its standard mode (`-ep`), the empty memory profiler looks for memory pages
filled with zero bytes. Such pages can occur due to deliberately setting memory
to zero, for instance by `calloc()`, `memset()`, or initializers. Zero-filled
pages can also be the result of memory allocated by `mmap` of `/dev/zero` but
unused until the profiler scans the memory.

If started as `-ei`, the profiler initializes allocated memory with a magic
pattern" (`0xAA`). As a result, only memory that is deliberately set to zero is
reported.

If started as `-eu`, the profiler initializes allocated memory as with the `-ei`
option. However, it records only pages filled with the magic byte. Thereyby, it
identifies allocated memory that has never been touched (but that also might
have never been mapped to physical memory).

## Regular expression collapsing.

If [pcre](http://www.pcre.org) is available at build time, you can now pass a
set of perl like regular expressions as an argument of `igprof-analyze` to
collapse nodes in the report. This is done via the following syntax:

    igprof-analyze -mr "s/<regex-to-match>/<substitution>/;s/<regex-to-match-2>/<substitution-2>/" <rest of the arguments>

for exaple you can do:
    
    igprof-analyze -mr "s/Py_.*/PYTHON/" ...

to change all the symbols coming from the Python API to be referred as
"PYTHON".

## Differentiate calls based on anchestors (new in 5.9.11)

The `-ma / --merge-ancestors` option has syntax:

    -ma "REGEX1[>REGEX2[>...[>REGEX<N>]]]/NEW_NAME"

with this option `igprof-analyse` goes trough nodes in the call tree and checks
if node is child of ancestors that matches to `REGEX<N>` list.  Node that
matches `REGEX<N>` and is child of all ancestors that matches previos regular
expressions will renamed as NEW_NAME. Also all child of the node `REGEX<N>` will
get the name `NEW_NAME:orginal_name`.

Ancestors got to match in order. `REGEX1` is the oldest and `REGEX2` is the 2nd
oldest.

For example program has function foo which calls bar and bar calls foobar and
at some other place the program calls only bar which then calls foobar.
`-ma "foo>bar>foobar/foobar: child of foo and bar"` would rename foobar at
the first case but leave foobar unchanged at the second case.

Node doesn't need to be direct child of ancestor. For example `-ma
"foo>foobar/foobar: has foo ancestor"` would rename foobar if foo is ancestor of
the foobar.

## Experimental energy profiling.

Experimental energy profiling is available if you build igprof on a machine
which has PAPI available. You can enable it by passing `-ng` as an option at
profile time.
