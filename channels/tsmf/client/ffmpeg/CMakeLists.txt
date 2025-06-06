# FreeRDP: A Remote Desktop Protocol Implementation
# FreeRDP cmake build script
#
# Copyright 2012 Marc-Andre Moreau <marcandre.moreau@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

define_channel_client_subsystem("tsmf" "ffmpeg" "decoder")

set(${MODULE_PREFIX}_SRCS tsmf_ffmpeg.c)

set(${MODULE_PREFIX}_LIBS freerdp ${FFMPEG_LIBRARIES})
if(APPLE)
  # For this to work on apple, we need to add some frameworks
  find_library(COREFOUNDATION_LIBRARY CoreFoundation)
  find_library(COREVIDEO_LIBRARY CoreVideo)
  find_library(COREVIDEODECODE_LIBRARY VideoDecodeAcceleration)

  list(APPEND ${MODULE_PREFIX}_LIBS ${COREFOUNDATION_LIBRARY} ${COREVIDEO_LIBRARY} ${COREVIDEODECODE_LIBRARY})
endif()

include_directories(..)
include_directories(SYSTEM ${FFMPEG_INCLUDE_DIRS})

add_channel_client_subsystem_library(${MODULE_PREFIX} ${MODULE_NAME} ${CHANNEL_NAME} "" TRUE "")
