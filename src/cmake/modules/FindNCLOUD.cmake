# - Find nCloud
# Find the Linux Trace Toolkit - next generation with associated includes path.
#
# This module defines the following variables:
#    NCLOUD_FOUND       = Was nCloud found or not?
#    NCLOUD_LIBRARIES   = The list of libraries to link to when using nCloud
#    NCLOUD_INCLUDE_DIR = The path to nCloud include directory
#
# On can set NCLOUD_PREFIX before using find_package(nCloud) and the
# module with use the PATH as a hint to find nCloud.
#
# The hint can be given on the command line too:
#   cmake -DNCLOUD_PREFIX=/DATA/ERIC/nCloud /path/to/source

if (NOT NCLOUD_INCLUDE_DIR)
  find_path(NCLOUD_INCLUDE_DIR
    NAMES ncloud/client.h ncloud/define.h
    PATHS ${NCLOUD_PREFIX} ${PROJECT_SOURCE_DIR}/include
    PATH_SUFFIXES include 
    DOC "The nCloud include headers")
endif (NOT NCLOUD_INCLUDE_DIR)

if (NOT NCLOUD_LIBRARY_DIR)
  find_path(NCLOUD_LIBRARY_DIR
    NAMES libncloud_zmq.so
    PATHS ${NCLOUD_PREFIX}
    PATH_SUFFIXES lib/${CMAKE_LIBRARY_ARCHITECTURE} lib lib64
    DOC "The nCloud libraries")
endif (NOT NCLOUD_LIBRARY_DIR)

find_library(NCLOUD_LIBRARY ncloud_zmq PATHS ${NCLOUD_LIBRARY_DIR} NO_DEFAULT_PATH)
## Todo: check if functions required exist in the library

set(NCLOUD_LIBRARIES ${NCLOUD_LIBRARY})
message(STATUS "Found nCloud libraries: ${NCLOUD_LIBRARIES}")

# handle the QUIETLY and REQUIRED arguments and set PRELUDE_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(NCLOUD
  REQUIRED_VARS NCLOUD_INCLUDE_DIR NCLOUD_LIBRARY_DIR)
# VERSION FPHSA options not handled by CMake version < 2.8.2)
#                                  VERSION_VAR)
mark_as_advanced(NCLOUD_INCLUDE_DIR)
mark_as_advanced(NCLOUD_LIBRARY_DIR)
