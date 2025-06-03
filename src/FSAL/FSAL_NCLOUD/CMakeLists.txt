# SPDX-License-Identifier: LGPL-3.0-or-later
#/*
# * Copyright © 2019-2025, CUHK.
# * Author: Helen H. W. Chan <hwchan@cuhk.edu.hk>
# *
# * contributor : Helen H. W. Chan <hwchan@cuhk.edu.hk>
# *
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public License
# * as published by the Free Software Foundation; either version 3 of
# * the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful, but
# * WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# * Lesser General Public License for more details.
# *
# * You should have received a copy of the GNU Lesser General Public
# * License along with this library; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# * 02110-1301 USA
# *
# * -------------
# */
#/*
# * Copyright © 2019-2025, CUHK.
# * Author: Helen H. W. Chan <hwchan@cuhk.edu.hk>
# *
# * contributor : Helen H. W. Chan <hwchan@cuhk.edu.hk>
# *
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public License
# * as published by the Free Software Foundation; either version 3 of
# * the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful, but
# * WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# * Lesser General Public License for more details.
# *
# * You should have received a copy of the GNU Lesser General Public
# * License along with this library; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# * 02110-1301 USA
# *
# * -------------
# */

add_definitions(
  -D__USE_GNU
  -D_GNU_SOURCE
)

set( LIB_PREFIX 64 )

########### next target ###############

SET(fsalncloud_LIB_SRCS
   handle.c
   file.c
   xattrs.c
   ncloud_methods.h
   ncloud_methods.c
   main.c
   export.c
   ds/rbtree.c
)

#add_library(fsalncloud MODULE ${fsalncloud_LIB_SRCS})
add_library(fsalncloud SHARED ${fsalncloud_LIB_SRCS})
add_sanitizers(fsalncloud)

target_link_libraries(fsalncloud
  gos
  ${NCLOUD_LIBRARIES}
)

set_target_properties(fsalncloud PROPERTIES VERSION 4.2.0 SOVERSION 4)
install(TARGETS fsalncloud COMPONENT fsal DESTINATION ${FSAL_DESTINATION} )


########### install files ###############
