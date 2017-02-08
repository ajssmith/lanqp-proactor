#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

# Find libuv include dirs and libraries.
#
# Sets the following variables:
#
#   Libuv_FOUND            - True if headers and requested libraries were found
#   Libuv_INCLUDE_DIRS     - Libuv include directories
#   Libuv_LIBRARIES        - Link these to use libuv.
#
# This module reads hints about search locations from variables::
#   LIBUV_ROOT             - Preferred installation prefix
#   LIBUV_INCLUDEDIR       - Preferred include directory e.g. <prefix>/include
#   LIBUV_LIBRARYDIR       - Preferred library directory e.g. <prefix>/lib

find_library(Libuv_LIBRARIES Names uv libuv HINTS ${LIBUV_LIBRARYDIR} ${LIBUV_ROOT})
find_path(Libuv_INCLUDE_DIRS NAMES uv.h HINTS ${LIBUV_INCLUDEDIR} ${LIBUV_ROOT} ${LIBUV_ROOT}/include ${CMAKE_INSTALL_PREFIX}/include PATHS /usr/include)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libuv DEFAULT_MSG Libuv_LIBRARIES Libuv_INCLUDE_DIRS)
