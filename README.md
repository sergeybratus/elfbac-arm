# ELFbac ARM

This repository is (currently) split into three components. The modified kernel
lives in linux/, and is a git subtree tracking the main linux repository on
github.

Companion tools for working with ELFbac policies live in elfbac-tools/. The main
tool now is elfbac-ld, which is a wrapper around the GNU linker to lay out
sections properly and to link in an ELFbac policy as described by a JSON file.

A sample program exists in elfbac-tools/sample/ to see how this works. You can
run it in the VM or on the host with qemu-arm-static.

Scripts to create a vexpress-a9 qemu vm have been placed in scripts/, along with
a kernel config for that machine. Requires a debian-based (Ubuntu probably)
machine with the arm-linux-gnueabihf toolchain and qemu installed.

gdbinit in scripts is symlinked to .gdbinit there, so running gdb-multiarch from
the scripts directory will start gdb and connect to a waiting vm (started with
-S -s). Will need to add that path to your load path in ~/.gdbinit for this to
work.

# Transcript from new Ubuntu install

    sudo apt-get install gcc-arm-linux-gnueabihf gdb-multiarch qemu-system-arm debootstrap python-virtualenv
    cd linux
    export ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf-
    cp ../scripts/config_vexpress_a9 .config
    make oldconfig
    make
    cd ../scripts
    ./make-vm.sh
    cd ../elfbac-tools
    mkdir venv
    virtualenv --no-site-packages venv
    source venv/bin/activate
    pip install -r requirements.txt
    cd ../scripts
    ./run-vm.sh -S -s
    gdb-multiarch

