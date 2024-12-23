#!/bin/bash

if ! source "./scripts/common.sh"; then
  echo "Failed to import common.sh, please the scripts from the repository's root directory"
  exit 1
fi

if [ "$UID" -ne 0 ]; then
  error "Please run this script as root"
fi

mount "${IMAGE}" "${MNTDIR}"
check_ret "Failed to mount the root disk image"

set -e

info "Installing base system"
debootstrap stable "${MNTDIR}" http://deb.debian.org/debian/
cp -r "${SRCDIR}/"0x* "${MNTDIR}/root"
rm -f "${MNTDIR}/root"/0x*/*.elf "${MNTDIR}/root"/0x*/*.py

info "Installing additional packages inside chroot"
chroot "${MNTDIR}" /bin/bash -c "apt install -y vim cowsay dhcpcd openssh-server gdb tmux python3-pwntools python3-capstone python3-pkg-resources wget"
chroot "${MNTDIR}" /bin/bash -c "wget https://kali.download/kali/pool/main/p/python-filebytes/python3-filebytes_0.10.2-0kali1_all.deb"
chroot "${MNTDIR}" /bin/bash -c "wget https://http.kali.org/kali/pool/main/r/ropper/ropper_1.13.8-0kali1_all.deb"
chroot "${MNTDIR}" /bin/bash -c "apt install -y ./python3-filebytes_0.10.2-0kali1_all.deb"
chroot "${MNTDIR}" /bin/bash -c "apt install -y ./ropper_1.13.8-0kali1_all.deb"
chroot "${MNTDIR}" /bin/bash -c "rm *.deb"

info "Running chroot commands"
chroot "${MNTDIR}" /bin/bash -c "echo root:o101root | chpasswd"
chroot "${MNTDIR}" /bin/bash -c "echo o101 > /etc/hostname"
chroot "${MNTDIR}" /bin/bash -c "systemctl enable dhcpcd"
chroot "${MNTDIR}" /bin/bash -c "systemctl enable ssh"

info "Copying config files"
cp "${SRCDIR}/files/sshd"    "${MNTDIR}/etc/ssh/sshd_config"
cp "${SRCDIR}/files/profile" "${MNTDIR}/root/.profile"
cp "${SRCDIR}/files/bashrc"  "${MNTDIR}/root/.bashrc"
cp "${SRCDIR}/files/vimrc"   "${MNTDIR}/root/.vimrc"

install -m755 "${SRCDIR}/files/aslr.sh" "${MNTDIR}/bin/toggle-aslr"

cp "${SRCDIR}/files/noaslr.service" "${MNTDIR}/usr/lib/systemd/system/noaslr.service"
chroot "${MNTDIR}" /bin/bash -c "systemctl enable noaslr"

set +e

umount "${MNTDIR}"
check_ret "Failed to unmount the root disk image"

info "Installation completed"
