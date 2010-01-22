PROJECT(IGPROF C CXX)
CMAKE_MINIMUM_REQUIRED(VERSION 2.4.6)

# Options.
OPTION(IGPROF_BUILD_TESTS "Build tests." OFF)

# Default to "release with debug info", i.e. "-O2 -g".
IF(NOT CMAKE_CONFIGURATION_TYPE AND NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING
      "Build type: None Debug Release RelWithDebInfo MinSizeRel."
      FORCE)
ENDIF()

# Flags we need.
ADD_DEFINITIONS(-D__STDC_FORMAT_MACROS)
ADD_DEFINITIONS(-D__STDC_LIMIT_MACROS)
IF(${CMAKE_SYSTEM_NAME} MATCHES Linux)
  ADD_DEFINITIONS(-D_GNU_SOURCE)
ENDIF()

# Use ANSI mode for C and stricter compile options with GCC.
SET(CMAKE_C_FLAGS "${CMAKE_ANSI_FLAGS} ${CMAKE_C_FLAGS}")
SET(CMAKE_REQUIRED_FLAGS ${CMAKE_ANSI_FLAGS})
IF(CMAKE_COMPILER_IS_GNUCC)
  ADD_DEFINITIONS(-ansi -pedantic -W -Wall -Wno-long-long -Werror)
ENDIF()

IF(UNIX)
  SET(IGPROF_LIBS ${IGPROF_LIBS} ${CMAKE_DL_LIBS})
ENDIF()

# Build targets.
INCLUDE_DIRECTORIES("${PROJECT_SOURCE_DIR}")
ADD_LIBRARY(igprof SHARED
            src/IgHook.cc
            src/IgHookTrace.cc
            src/IgProfBuffer.cc
            src/IgProf.cc
            src/IgProfFileDesc.cc
            src/IgProfMem.cc
            src/IgProfPerf.cc
            src/IgProfSymCache.cc
            src/IgProfTrace.cc
            src/IgTrace.cc
            src/IgTraceMem.cc
            src/IgTraceMMap.cc
            src/IgTraceThrow.cc)
TARGET_LINK_LIBRARIES(igprof ${IGPROF_LIBS} unwind)
ADD_EXECUTABLE(igprof-analyse src/IgProfAnalyse.cc)
TARGET_LINK_LIBRARIES(igprof-analyse classlib ${CMAKE_DL_LIBS} -lpcre -lz -lbz2 -lrt)
INSTALL(TARGETS igprof igprof-analyse
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib)
INSTALL(FILES
        src/igprof-analyse-old
        src/igprof-func
        src/igprof-navigator
        src/igprof-navigator-summary
        src/igprof-segment
        src/igprof-symbol-sizes
        src/igprof
        src/igtrace
        src/igtrace-mmap-analysis
        src/igtrace-mmap-summary
        DESTINATION bin
        PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
INSTALL(FILES src/IgResolveSymbols.h DESTINATION include/igprof)

# Tests.
IF(IGPROF_BUILD_TESTS)
  # FIXME: Build libraries from sources in test/*.cc.
  # FIXME: Run igprof-regression-tests
ENDIF()
