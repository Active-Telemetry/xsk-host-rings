#!/bin/bash
ROOT=`pwd`
BUILD=$ROOT/.build

# Create build directory
mkdir -p $BUILD

# Linux
if [ ! -f $BUILD/net-next/arch/x86/boot/bzImage ]; then
    cd $BUILD
    echo "Building linux(net-next) from source."
    git clone --depth 1 git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next.git
    cd net-next
    if [ ! -f .config ]; then
        make ARCH=x86_64 x86_64_defconfig 
        # make ARCH=x86_64 menuconfig
        sed -i 's/# CONFIG_DEBUG_INFO.*/CONFIG_DEBUG_INFO=y/g' .config
        sed -i 's/# CONFIG_EXT_FS.*/CONFIG_EXT_FS=y/g' .config
        sed -i 's/# CONFIG_BLK_DEV_RAM.*/CONFIG_BLK_DEV_RAM=y\nCONFIG_BLK_DEV_RAM_COUNT=16\nCONFIG_BLK_DEV_RAM_SIZE=65535/g' .config
        sed -i 's/# CONFIG_VIRTIO_PCI.*/CONFIG_VIRTIO_PCI=y\nCONFIG_VIRTIO_NET=y/g' .config
        sed -i 's/# CONFIG_BPF_SYSCALL.*/CONFIG_BPF_SYSCALL=y\nCONFIG_XDP_SOCKETS=y/g' .config
        sed -i 's/=m/=y/g' .config
        yes "" | make oldconfig
    fi
    make -j8
    rc=$?; if [[ $rc != 0 ]]; then exit $rc; fi
    make INSTALL_HDR_PATH=./_install headers_install
    rc=$?; if [[ $rc != 0 ]]; then exit $rc; fi
    make -C tools/lib/bpf
    rc=$?; if [[ $rc != 0 ]]; then exit $rc; fi
    cd $BUILD
fi

# Busybox rootfs
if [ ! -f $BUILD/busybox/_install/bin/busybox  ]; then
    cd $BUILD
    echo "Building busybox from source."
    git clone git://git.busybox.net/busybox
    cd busybox
    yes "" | make defconfig
    sed -i 's/# CONFIG_STATIC .*/CONFIG_STATIC=y/g' .config
    make install DESTDIR=$BUILD/busybox/_install
    rc=$?; if [[ $rc != 0 ]]; then exit $rc; fi
    cd $BUILD
fi

# Ethtool
if [ ! -f $BUILD/ethtool/_install/usr/sbin/ethtool ]; then
    cd $BUILD
    echo "Building ethtool from source."
    git clone git://git.kernel.org/pub/scm/network/ethtool/ethtool.git
    cd ethtool
    ./autogen.sh
    ./configure --prefix=/usr LDFLAGS=-static
    make DESTDIR=_install install
    rc=$?; if [[ $rc != 0 ]]; then exit $rc; fi
    cd $BUILD
fi

# xsk-host.c
cd $BUILD
gcc -fno-builtin -static -o $BUILD/xsk-host \
    -I$BUILD/net-next/_install/include \
    -I$BUILD/net-next/tools/lib/ \
    $BUILD/../xsk-host.c \
    $BUILD/net-next/tools/lib/bpf/libbpf.a \
    /usr/lib/x86_64-linux-gnu/libelf.a \
    /usr/lib/x86_64-linux-gnu/libz.a \
    -lpthread
rc=$?; if [ $rc != 0 ]; then exit $rc; fi

# Generate initrd
dd if=/dev/zero of=$BUILD/ramdisk-ext2 bs=1k count=32k
mke2fs -i 1024 -b 1024 -m 3 -F -v $BUILD/ramdisk-ext2
mkdir $BUILD/rootfs
sudo mount -o loop $BUILD/ramdisk-ext2 $BUILD/rootfs
cd $BUILD/rootfs
sudo rsync -p -a $BUILD/busybox/_install/ ./
sudo rsync -p -a $BUILD/ethtool/_install/ ./
mkdir -p etc dev proc sys tmp lib
ln -sf /dev/null dev/tty2
ln -sf /dev/null dev/tty3
ln -sf /dev/null dev/tty4
echo -e """
::sysinit:/bin/mount -t proc proc /proc
::sysinit:/bin/mount -t sysfs sysfs /sys
::sysinit:/bin/mount -t tmpfs tmpfs /tmp
::sysinit:/bin/mount -t debugfs none /sys/kernel/debug
::sysinit:/bin/mount -t cgroup2 cgroup /sys/fs/cgroup
::sysinit:/sbin/ifconfig lo 172.0.0.1
::sysinit:/usr/sbin/ethtool -L eth0 combined 1
::sysinit:/sbin/ifconfig eth0 promisc up
::sysinit:/sbin/ifconfig eth0 192.168.100.2
::sysinit:/usr/bin/xsk-host eth0
::sysinit:/usr/bin/timeout .1 cat /sys/kernel/debug/tracing/trace_pipe
ttyS0::respawn:/bin/sh
::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/swapoff -a
::shutdown:/bin/umount -a -r
::restart:/sbin/init
""" > etc/inittab
cd ..
cp $BUILD/xsk-host $BUILD/rootfs/usr/bin/
sudo umount $BUILD/rootfs
sudo rm -fr $BUILD/rootfs

# Run in QEMU
last=`ip tuntap show 2>/dev/null | grep "^tap" | sort -V | awk 'END{print $1}' | sed 's/[^0-9]*//g'`
tap="tap$((last + 1))"
sudo ip tuntap add dev $tap mode tap multi_queue user `whoami`
sudo ip link set dev $tap up
sudo ip addr add dev $tap 192.168.100.1/24
qemu-system-x86_64 \
    -no-kvm -display none \
    -kernel $BUILD/net-next/arch/x86/boot/bzImage \
    -initrd $BUILD/ramdisk-ext2 \
    -smp 4 \
    -m 4096 \
    -append "root=/dev/ram0 console=ttyS0 nokaslr" \
    -netdev tap,id=mynet0,ifname=$tap,script=no,downscript=no,queues=`nproc` \
    -device virtio-net-pci,netdev=mynet0,mac=52:55:00:d1:55:01,mq=on \
    -serial stdio \
    -monitor unix:/tmp/qemu-monitor,server,nowait

# Cleanup
sudo ip link delete dev $tap
