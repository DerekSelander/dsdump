# Install script for directory: /Users/lolgrep/code/xref/llvm/lib

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
  include("/Users/lolgrep/code/xref/lib/IR/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/FuzzMutate/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/IRReader/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/CodeGen/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/BinaryFormat/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/Bitcode/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/Transforms/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/Linker/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/Analysis/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/LTO/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/MC/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/MCA/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/Object/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/ObjectYAML/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/Option/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/Remarks/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/DebugInfo/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/ExecutionEngine/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/Target/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/AsmParser/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/LineEditor/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/ProfileData/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/Passes/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/TextAPI/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/ToolDrivers/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/XRay/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/Testing/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/lib/WindowsManifest/cmake_install.cmake")

endif()

