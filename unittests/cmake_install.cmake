# Install script for directory: /Users/lolgrep/code/xref/llvm/unittests

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

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/Users/lolgrep/code/xref/unittests/ADT/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/Analysis/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/AsmParser/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/BinaryFormat/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/Bitcode/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/CodeGen/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/DebugInfo/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/Demangle/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/ExecutionEngine/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/FuzzMutate/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/IR/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/LineEditor/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/Linker/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/MC/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/MI/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/Object/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/ObjectYAML/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/Option/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/Remarks/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/Passes/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/ProfileData/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/Support/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/TextAPI/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/Target/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/Transforms/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/XRay/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/unittests/tools/cmake_install.cmake")

endif()

