# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/etc/vaccine/src/../bpftool/src"
  "/etc/vaccine/build/bpftool/src/bpftool-build"
  "/etc/vaccine/build/bpftool"
  "/etc/vaccine/build/bpftool/tmp"
  "/etc/vaccine/build/bpftool/src/bpftool-stamp"
  "/etc/vaccine/build/bpftool/src"
  "/etc/vaccine/build/bpftool/src/bpftool-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/etc/vaccine/build/bpftool/src/bpftool-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/etc/vaccine/build/bpftool/src/bpftool-stamp${cfgdir}") # cfgdir has leading slash
endif()
