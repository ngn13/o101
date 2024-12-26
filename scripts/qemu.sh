#!/bin/bash

if ! source "./scripts/common.sh"; then
  echo "Failed to import common.sh, please the scripts from the repository's root directory"
  exit 1
fi

if [ -z "${1}" ]; then
  error "Please specify a kernel image"
  exit 1
fi

ram=$(grep MemTotal /proc/meminfo | awk '{print $2}')
ram=$(expr "${ram}" / 1024) # kb to mb
ram=$(expr "${ram}" / 1024) # mb to gb

if [ "${ram}" \< 2 ]; then
  error "You need at least 2GB host memory, if you want less please edit this script (${0})"
  exit 1
fi

qemu-system-x86_64 -hda "${IMAGE}" -m "$(expr "${ram}" / 2)G" -nographic         \
        -append "root=/dev/sda rw console=ttyS0 loglevel=5"                      \
        -netdev user,id=user.0,hostfwd=tcp::2222-:22 -device e1000,netdev=user.0 \
        -cpu kvm64,+smep,+smap                                                   \
        -kernel "${1}" --enable-kvm
