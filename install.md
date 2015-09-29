---
title: Installing IgProf
layout: default
related:
 - { name: Top, link: . }
 - { name: Downloads, link: "https://github.com/igprof/igprof/tags" }
 - { name: Bugs, link: "https://github.com/igprof/igprof/issues" }
 - { name: Project, link: "https://github.com/igprof/igprof/" }
---

# Installing IgProf via yum (experimental)

For user of Centos7 / CERN Centos 7 we now provide an **experimental**
yum repository, courtesy of <http://bintray.com>. To use it:

    curl -o /etc/yum.repos.d/igprof.repo https://bintray.com/igprof/slc7_x86-64-test/rpm
    yum update
    yum install igprof

if you have any problem with it, please open an issue.

# Building IgProf from sources

Building igprof requires recent [libatomic_ops][] and [libunwind][], plus recent
[autotools][] and [cmake][] 2.8.x or later for the build itself, but not running.
The recipe below includes a temporary build of cmake, but if your system
supplies it, you can safely omit building cmake.

We have verified igprof works on the following platforms, where we routinely
use it ourselves. There is a reasonable probability igprof will work out of
the box on other relatively recent linux distributions, but we have not
verified this.

 * [Scientific Linux 5](https://www.scientificlinux.org/) - a RHEL5 rebuild
   * 32 bit and 64bit, with gcc 4.1.2 system compiler
   * 32 bit and 64bit, with gcc 4.3.4 compiler
   * 64bit, with gcc 4.5.1, 4.6.x and 4.7.x, 4.8.x compiler
 * [Scientific Linux 6](https://www.scientificlinux.org/) - a RHEL6 rebuild
   * 64bit, with gcc 4.5.1, 4.6.x and 4.7.x, 4.8.x compiler

If you are a [docker](http://docker.io) fan, you can try to use the prebuild
docker image at [igprof/igprof](https://registry.hub.docker.com/u/igprof/igprof).

The build recipe itself is:

    # Set up one environment variable to simplify the build recipe;
    # no need to 'export' this, it's just a shortcut for path names.
    INSTAREA=/x/y/z   # Wherever you want to install the software
    IGPROF_VERSION=5.9.12
    LIBATOMIC_VERSION=7.2alpha4
    LIBUNWIND_VERSION=1.1
    CMAKE_VERSION=2.8.1

    # Get the source tarballs for libatomic_ops, libunwind and igprof
    wget http://www.hpl.hp.com/research/linux/atomic_ops/download/libatomic_ops-$LIBATOMIC_VERSION.tar.gz
    wget http://download.savannah.gnu.org/releases/libunwind/libunwind-$LIBUNWIND_VERSION.tar.gz
    wget -Oigprof-$IGPROF_VERSION.tar.gz https://github.com/igprof/igprof/archive/v$IGPROF_VERSION.tar.gz

    # Get a recent version of cmake
    wget http://www.cmake.org/files/v2.8/cmake-$CMAKE_VERSION.tar.gz

    # Build libatomic
    gtar xzvf libatomic_ops-$LIBATOMIC_VERSION.tar.gz
    cd libatomic_ops-$LIBATOMIC_VERSION
    ./configure --prefix=$INSTAREA
    make -j 10 install
    cd ../

    # Build libunwind
    gtar xzf libunwind-$LIBUNWIND_VERSION.tar.gz
    cd libunwind-$LIBUNWIND_VERSION
    ./configure CPPFLAGS="-I$INSTAREA/include" CFLAGS="-g -O3" --prefix=$INSTAREA --disable-block-signals
    make -j 10 install
    cd ../

    # Build cmake
    gtar xzf cmake-$CMAKE_VERSION.tar.gz
    cd cmake-$CMAKE_VERSION
    mkdir -p $INSTAREA/tmpcmake
    ./configure --prefix=$INSTAREA/tmpcmake --parallel=10
    make -j 10
    make -j 10 install
    cd ../
    export PATH=$INSTAREA/tmpcmake/bin:$PATH

    # Build igprof
    gtar xzf igprof-$IGPROF_VERSION.tar.gz
    cd igprof-$IGPROF_VERSION
    # In case you want to develop:
    # git clone https://github.com/igprof/igprof.git
    # cd igprof
    cmake -DCMAKE_INSTALL_PREFIX=$INSTAREA -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-g -O3" .
    make -j 10
    make -j 10 install
    cd ../

    # Clean up the temporary cmake build
    rm -fR $INSTAREA/tmpcmake

At this point should be able to set up `PATH` and `LD_LIBRARY_PATH` to point to
the `$INSTAREA` and begin to use igprof. Here is a simple example (used as a
tutorial to demonstrate problems) which you can use quickly to verify that
igprof is set up:

    // Store in a file vvvi-build-and-copy.cc
    // Compile: c++ -o vvvi-build-and-copy vvvi-build-and-copy.cc -ldl -lpthread
    #include <vector>
    #include <string>
    #include <dlfcn.h>

    int main (int, char **)
    {
      union { void *ptr; void (*dump)(const char *tofile); } u;
      u.ptr = dlsym(0, "igprof_dump_now");

      typedef std::vector<int> VI;
      typedef std::vector<VI> VVI;
      std::vector<VVI> vvvi, vvvi2;
      for (int i = 0, j, k; i < 10; ++i)
        for (vvvi.push_back(VVI()), j = 0; j < 10; ++j)
          for (vvvi.back().push_back(VI()), k = 0; k < 10; ++k)
            vvvi.back().back().push_back(k);

      if (u.dump) u.dump("|gzip -9c > ig-vvvi-build.gz");

      vvvi2 = vvvi;
      if (u.dump) u.dump("|gzip -9c > ig-vvvi-copy.gz");
      return vvvi2.size();
    }

If you run:

    export PATH=$INSTAREA/bin:$PATH
    export LD_LIBRARY_PATH=$INSTAREA/lib:$LD_LIBRARY_PATH
    igprof -mp -z -o ig-vvvi-build-and-copy.gz ./vvvi-build-and-copy

You should see that three profile statistics files have been written:

 * ig-vvvi-build.gz - statistics dumped while job is running (after build)
 * ig-vvvi-copy.gz - statistics dumped while job is running (after copy)
 o ig-vvvi-build-and-copy.gz - statistics from the end of the job

You can produce a report (for example) from the end-of-job profile statistics
with:

    igprof-analyse -d -v -g -r MEM_TOTAL ig-vvvi-build-and-copy.gz > vvvibc.res

If you then look at vvvibc.res, you should see something like:

    ----------------------------------------------------------------------
    Flat profile (cumulative >= 1%)

    % total     Total     Calls  Function
      100.0    42'934     1'091  <spontaneous> [1]
      100.0    42'934     1'091  _start [2]
      100.0    42'934     1'091  __libc_start_main [3]
      100.0    42'934     1'091  main [4]
    <... and so on ...>

If you have gotten to this point, your igprof installation should be set up
correctly and you should proceed to the full documentation of [how to run igprof](running.html).

[libatomic_ops]: http://www.hpl.hp.com/research/linux/atomic_ops/
[libunwind]: http://www.nongnu.org/libunwind/
[autotools]: http://www.gnu.org/savannah-checkouts/gnu/automake/manual/html_node/Autotools-Introduction.html
[cmake]: http://www.cmake.org
