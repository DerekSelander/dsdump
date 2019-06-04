# Install script for directory: /Users/lolgrep/code/xref/llvm/examples/Kaleidoscope

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
  include("/Users/lolgrep/code/xref/examples/Kaleidoscope/BuildingAJIT/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/examples/Kaleidoscope/Chapter2/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/examples/Kaleidoscope/Chapter3/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/examples/Kaleidoscope/Chapter4/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/examples/Kaleidoscope/Chapter5/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/examples/Kaleidoscope/Chapter6/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/examples/Kaleidoscope/Chapter7/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/examples/Kaleidoscope/Chapter8/cmake_install.cmake")
  include("/Users/lolgrep/code/xref/examples/Kaleidoscope/Chapter9/cmake_install.cmake")

endif()

