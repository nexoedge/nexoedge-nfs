# Notes on NFS-Ganesha Development (for nCloud)

License: LGPL 3.0

## Compilation

- [Offical compilation guide][nfs-ganesha-compile]

The following information is based on CentOS 7:

1. Install the package: `$ sudo yum install gcc git cmake3 autoconf libtool bison flex libgssglue-devel openssl-devel nfs-utils-lib-devel doxygen redhat-lsb gcc-c++ userspace-rcu-devel`
2. Update the dependent source code: `$ git submodule update --init`
3. Setup build directory and compile: `$ mkdir build; cd build && cmake3 ../src && make`

[nfs-ganesha-compile]: https://github.com/nfs-ganesha/nfs-ganesha/wiki/Compiling

The following informaiton is based on Ubuntu 18.04:
1. Install the package: `$ sudo apt install g++ git cmake libkrb5-dev libgss-dev libbison-dev flex doxygen graphviz lsb-core
2. Update the dependent source code: `$ git submodule update --init`
3. Setup build directory and compile: `$ mkdir build; cd build && cmake ../src && make`

## Setup

1. Install NFS-Ganesha: in the build directory, `$ sudo make install`
2. Copy the example configuration `ganesha.conf` to `/etc/ganesha/`: in the `ncloud` which contains this readme, `$ sudo cp ganesha.conf /etc/ganesha/`
3. Install the `systemd` service script, and type 'yes' to the prompt to start the service: `$ sudo bash install_service.sh`
4. Check if NFS-Ganesha is running, the output should be non-empty: `$ ps aux | grep ganesha | grep -v grep`

### Others

### VFS Trial
Copy and paste the content sample configuration file `${ganesha_home}/src/config_samples/vfs.config` to `/etc/ganesha/ganesha.conf`.

Change the `Path` and `Pseudo` to `/`.

Add `Squash = None` to the `EXPORT` block.

Output the log to specific location, e.g., `/log/ganesha.log`: `$ sudo ganesha.nfsd -L /log/ganesha.log`.

Mount the drive `$sudo mount.nfs [ip]:/ [mountdir]`

### Example configuration
See `${ganesha_home}/ncloud/ganesha.conf`.

### Example Testing
See `${ganesha_home}/ncloud/test.sh`.

1. Copy `${ganesha_home}/ncloud/ganesha.conf` to `/etc/ganesha/ganesha.conf`.
2. Run `${ganesha_home}/ncloud/test.sh`.

### Trouble shooting
1. Error: `nfs_Init_svc :DISP :FATAL :Cannot get udp netconfig, cannot get an entry for udp in netconfig file.
    - Solution: Check file /etc/netconfig...` ocurrs, install `libtirpc`: `$ sudo yum install libtirpc` (see the issue https://github.com/nfs-ganesha/nfs-ganesha/issues/67 for details)
2. Error: `vfs_lookup_path :FSAL :CRIT :Could not get handle for path [path], error Operation not permitted`
    - Solution: Check if `rpcbind` is running (esp. for docker): `$ sudo yum install rpcbind; sudo rpcbind` (see the issue https://github.com/rootfs/nfs-ganesha-docker/issues/1` for details)
