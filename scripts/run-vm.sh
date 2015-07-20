#! /bin/bash

pushd qemu

qemu-system-arm -M vexpress-a9 -cpu cortex-a9 -m 1024M -kernel ../elfbac-arm/arch/arm/boot/zImage -dtb ../elfbac-arm/arch/arm/boot/dts/vexpress-v2p-ca9.dtb -sd rootfs.img -append "rootwait console=ttyAMA0 root=/dev/mmcblk0p1 rw single" -nographic $@
