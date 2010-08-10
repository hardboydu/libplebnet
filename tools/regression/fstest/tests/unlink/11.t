#!/bin/sh
# $FreeBSD$

desc="unlink returns EACCES or EPERM if the directory containing the file is marked sticky, and neither the containing directory nor the file to be removed are owned by the effective user ID"

dir=`dirname $0`
. ${dir}/../misc.sh

echo "1..68"

n0=`namegen`
n1=`namegen`
n2=`namegen`

expect 0 mkdir ${n2} 0755
cdir=`pwd`
cd ${n2}

expect 0 mkdir ${n0} 0755
expect 0 chown ${n0} 65534 65534
expect 0 chmod ${n0} 01777

# User owns both: the sticky directory and the file to be removed.
expect 0 -u 65534 -g 65534 create ${n0}/${n1} 0644
expect 0 -u 65534 -g 65534 unlink ${n0}/${n1}
# User owns the file to be removed, but doesn't own the sticky directory.
expect 0 -u 65533 -g 65533 create ${n0}/${n1} 0644
expect 0 -u 65533 -g 65533 unlink ${n0}/${n1}
# User owns the sticky directory, but doesn't own the file to be removed.
expect 0 -u 65533 -g 65533 create ${n0}/${n1} 0644
expect 0 -u 65534 -g 65534 unlink ${n0}/${n1}
# User doesn't own the sticky directory nor the file to be removed.
expect 0 -u 65534 -g 65534 create ${n0}/${n1} 0644
expect "EACCES|EPERM" -u 65533 -g 65533 unlink ${n0}/${n1}
expect 0 unlink ${n0}/${n1}

# User owns both: the sticky directory and the fifo to be removed.
expect 0 -u 65534 -g 65534 mkfifo ${n0}/${n1} 0644
expect 0 -u 65534 -g 65534 unlink ${n0}/${n1}
# User owns the fifo to be removed, but doesn't own the sticky directory.
expect 0 -u 65533 -g 65533 mkfifo ${n0}/${n1} 0644
expect 0 -u 65533 -g 65533 unlink ${n0}/${n1}
# User owns the sticky directory, but doesn't own the fifo to be removed.
expect 0 -u 65533 -g 65533 mkfifo ${n0}/${n1} 0644
expect 0 -u 65534 -g 65534 unlink ${n0}/${n1}
# User doesn't own the sticky directory nor the fifo to be removed.
expect 0 -u 65534 -g 65534 mkfifo ${n0}/${n1} 0644
expect "EACCES|EPERM" -u 65533 -g 65533 unlink ${n0}/${n1}
expect 0 unlink ${n0}/${n1}

# User owns both: the sticky directory and the block device to be removed.
expect 0 mknod ${n0}/${n1} b 0644 1 2
expect 0 chown ${n0}/${n1} 65534 65534
expect 0 -u 65534 -g 65534 unlink ${n0}/${n1}
# User owns the block device to be removed, but doesn't own the sticky directory.
expect 0 mknod ${n0}/${n1} b 0644 1 2
expect 0 chown ${n0}/${n1} 65533 65533
expect 0 -u 65533 -g 65533 unlink ${n0}/${n1}
# User owns the sticky directory, but doesn't own the block device to be removed.
expect 0 mknod ${n0}/${n1} b 0644 1 2
expect 0 chown ${n0}/${n1} 65533 65533
expect 0 -u 65534 -g 65534 unlink ${n0}/${n1}
# User doesn't own the sticky directory nor the block directory to be removed.
expect 0 mknod ${n0}/${n1} b 0644 1 2
expect 0 chown ${n0}/${n1} 65534 65534
expect "EACCES|EPERM" -u 65533 -g 65533 unlink ${n0}/${n1}
expect 0 unlink ${n0}/${n1}

# User owns both: the sticky directory and the character device to be removed.
expect 0 mknod ${n0}/${n1} b 0644 1 2
expect 0 chown ${n0}/${n1} 65534 65534
expect 0 -u 65534 -g 65534 unlink ${n0}/${n1}
# User owns the character device to be removed, but doesn't own the sticky directory.
expect 0 mknod ${n0}/${n1} b 0644 1 2
expect 0 chown ${n0}/${n1} 65533 65533
expect 0 -u 65533 -g 65533 unlink ${n0}/${n1}
# User owns the sticky directory, but doesn't own the character device to be removed.
expect 0 mknod ${n0}/${n1} b 0644 1 2
expect 0 chown ${n0}/${n1} 65533 65533
expect 0 -u 65534 -g 65534 unlink ${n0}/${n1}
# User doesn't own the sticky directory nor the character directory to be removed.
expect 0 mknod ${n0}/${n1} b 0644 1 2
expect 0 chown ${n0}/${n1} 65534 65534
expect "EACCES|EPERM" -u 65533 -g 65533 unlink ${n0}/${n1}
expect 0 unlink ${n0}/${n1}

# User owns both: the sticky directory and the socket to be removed.
expect 0 -u 65534 -g 65534 bind ${n0}/${n1}
expect 0 -u 65534 -g 65534 unlink ${n0}/${n1}
# User owns the socket to be removed, but doesn't own the sticky directory.
expect 0 -u 65533 -g 65533 bind ${n0}/${n1}
expect 0 -u 65533 -g 65533 unlink ${n0}/${n1}
# User owns the sticky directory, but doesn't own the socket to be removed.
expect 0 -u 65533 -g 65533 bind ${n0}/${n1}
expect 0 -u 65534 -g 65534 unlink ${n0}/${n1}
# User doesn't own the sticky directory nor the character directory to be removed.
expect 0 -u 65534 -g 65534 bind ${n0}/${n1}
expect "EACCES|EPERM" -u 65533 -g 65533 unlink ${n0}/${n1}
expect 0 unlink ${n0}/${n1}

# User owns both: the sticky directory and the symlink to be removed.
expect 0 -u 65534 -g 65534 symlink test ${n0}/${n1}
expect 0 -u 65534 -g 65534 unlink ${n0}/${n1}
# User owns the symlink to be removed, but doesn't own the sticky directory.
expect 0 -u 65533 -g 65533 symlink test ${n0}/${n1}
expect 0 -u 65533 -g 65533 unlink ${n0}/${n1}
# User owns the sticky directory, but doesn't own the symlink to be removed.
expect 0 -u 65533 -g 65533 symlink test ${n0}/${n1}
expect 0 -u 65534 -g 65534 unlink ${n0}/${n1}
# User doesn't own the sticky directory nor the symlink to be removed.
expect 0 -u 65534 -g 65534 symlink test ${n0}/${n1}
expect "EACCES|EPERM" -u 65533 -g 65533 unlink ${n0}/${n1}
expect 0 unlink ${n0}/${n1}

expect 0 rmdir ${n0}

cd ${cdir}
expect 0 rmdir ${n2}
