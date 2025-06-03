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

remotedir=/ncloud
#remotedir=/vfs

####
# File / folder ops
####
function makedir() {
	echo "> Make a new directory"
	sudo mkdir /mnt/ncloud/abc
}

function writefile() {
	echo "> Write a full file"
	sudo rm /mnt/ncloud/Doxyfile
	sudo cp Doxyfile /mnt/ncloud
}

function checkstats() {
	echo "> Check NFS capacity"
	df
	if [ -z "$(df -h | grep ${remotedir})" ]; then
		echo "Failed to mount NFS ${remotedir}"
		exit 1
	fi

	echo "> List NFS"
	sudo ls -lR /mnt/ncloud
}

####
# NFS source-code
####
function compile() {
	echo "> Make and install"
	make && sudo make install

	if [ $? -ne 0 ]; then exit 1; fi
}

####
# Server-side
####
function start() {
	echo "> Start ganesha.nfsd"
	sudo ldconfig
	sudo ganesha.nfsd -L /log.log

	echo "> Waiting for ganesha.nfsd to start"
	while [ -z "$(ps axu | grep gan)" ]; do sleep 3; done
	ps aux | grep ganesha.nfsd | grep -v grep

}

function shutdown() {
	echo "> Kill ganesha.nfsd"
	while [ ! -z "$(ps aux | grep ganesha.nfsd | grep -v grep)" ]; do
		sudo killall ganesha.nfsd
		sleep 1
	done
}

####
# Client-side
####
function mount() {
	echo "> Mount NFS"
	sudo mount 127.0.0.1:${remotedir} /mnt/ncloud
}

function unmount() {
	echo "> Unmount NFS"
	sudo umount /mnt/ncloud
}

####
# Main functions
####
function setup() {
	cleanup
	compile
	start
	mount
}

function cleanup() {
	unmount
	shutdown
}

####
# Main program
####

# setup
setup

# ops
checkstats
makedir

# check remount
unmount
mount
checkstats

# cleanup
cleanup
