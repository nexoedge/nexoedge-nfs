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

#!/bin/bash

if [ $EUID -ne 0 ]; then
	echo "Please run as root"
	exit 1
fi

service  nfs-ganesha stop

cp ./nfs-ganesha.service ./nfs-ganesha-lock.service /etc/systemd/system/ && \
	systemctl daemon-reload && \
	systemctl enable nfs-ganesha && \
	systemctl enable nfs-ganesha-lock

if [ $? -eq 0 ]; then
	read -p "Start the service now (yes/no)?" ans
	if [ "$ans" == "yes" ]; then
		echo "Start the nfs-ganesha service now"
		service nfs-ganesha start
		if [ $? -ne 0 ]; then
			echo "Failed to start the service!"
		fi
	fi
else
	echo "Failed to install the systemd scripts!"
	rm /etc/systemd/system/nfs-ganesha.service  /etc/systemd/system/nfs-ganesha-lock.service
fi
