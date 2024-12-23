#!/bin/bash

if ! source "./scripts/common.sh"; then
  echo "Failed to import common.sh, please the scripts from the repository's root directory"
  exit 1
fi

if ! type "pacstrap" > /dev/null; then
  error "Please install arch-install-scripts"
  exit 1
fi

./scripts/glibc.sh
check_ret "Failed to obtain the glibc"

info "Creating the root disk image"
mkdir -p "${MNTDIR}"
rm -f "${IMAGE}"

truncate -s 6G "${IMAGE}"
check_ret "Failed to truncate the root disk image"

mkfs.ext4 "${IMAGE}"
check_ret "Failed to format root disk image"

info "Running the base system installation script (needs root)"
$SUDO ./scripts/install.sh
check_ret "Install script failed"
