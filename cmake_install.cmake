# Install script for directory: /Users/lolgrep/code/xref/llvm

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xllvm-headersx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE DIRECTORY FILES
    "/Users/lolgrep/code/xref/llvm/include/llvm"
    "/Users/lolgrep/code/xref/llvm/include/llvm-c"
    FILES_MATCHING REGEX "/[^/]*\\.def$" REGEX "/[^/]*\\.h$" REGEX "/[^/]*\\.td$" REGEX "/[^/]*\\.inc$" REGEX "/license\\.txt$" REGEX "/\\.svn$" EXCLUDE)
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xllvm-headersx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE DIRECTORY FILES
    "/Users/lolgrep/code/xref/include/llvm"
    "/Users/lolgrep/code/xref/include/llvm-c"
    FILES_MATCHING REGEX "/[^/]*\\.def$" REGEX "/[^/]*\\.h$" REGEX "/[^/]*\\.gen$" REGEX "/[^/]*\\.inc$" REGEX "/cmakefiles$" EXCLUDE REGEX "/config\\.h$" EXCLUDE REGEX "/\\.svn$" EXCLUDE)
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/Users/lolgrep/code/xref/lib/Demangle/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/Support/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/TableGen/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/utils/TableGen/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/include/llvm/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/utils/FileCheck/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/utils/PerfectShuffle/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/utils/count/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/utils/not/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/utils/yaml-bench/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/projects/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/tools/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/runtimes/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/examples/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/utils/lit/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/test/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/utils/unittest/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/docs/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/cmake/modules/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/utils/llvm-lit/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/utils/benchmark/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/benchmarks/cmake_install.cmake")

endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/Users/lolgrep/code/xref/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
