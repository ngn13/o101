#!/bin/bash -e

if [ -z "$1" ]; then
  echo "usage: $0 <path to kernel image>"
  exit 1
fi

qemu-system-x86_64 -hda root.raw -m 4G -nographic                                         \
        -append "root=/dev/sda rw console=ttyS0 loglevel=5"                               \
        -netdev user,id=user.0,hostfwd=tcp::2222-:22 -device e1000,netdev=user.0          \
        -cpu kvm64,+smep,+smap                                                            \
        -kernel "$1" --enable-kvm
