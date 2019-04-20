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
cmake_minimum_required(VERSION 2.8.7)

find_package(Proton REQUIRED)
find_library(pthread_lib pthread)
include(CheckIncludeFiles)
include(CheckCCompilerFlag)

set (lanqp-proactor_SOURCES
     src/bridge.c
     src/main.c
     src/netns.c
     src/threading.c
     src/tun_dev.c
     )

set_source_files_properties (
  ${lanqp-proactor_SOURCES}
  PROPERTIES
  COMPILE_FLAGS "${COMPILE_WARNING_FLAGS} ${WERROR} ${COMPILE_PLATFORM_FLAGS} ${LINK_TIME_OPTIMIZATION}"
  )

check_include_files("linux/if_tun.h" HAVE_LINUX_IF_TUN_H)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${Proton_INCLUDE_DIRS}
    )

add_executable(lanqp-proactor ${lanqp-proactor_SOURCES})
target_link_libraries(lanqp-proactor ${Proton_LIBRARIES})
target_link_libraries(lanqp-proactor ${ProtonCore_LIBRARIES})
target_link_libraries(lanqp-proactor ${ProtonProactor_LIBRARIES})
target_link_libraries(lanqp-proactor ${PLATFORM_LIBS})
target_link_libraries(lanqp-proactor pthread)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/lanqp-proactor
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_EXECUTE GROUP_READ WORLD_READ WORLD_WRITE WORLD_EXECUTE
        DESTINATION ${CMAKE_INSTALL_PREFIX}/local/bin)
