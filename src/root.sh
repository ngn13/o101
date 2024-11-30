#!/bin/bash -e 

if [ "$EUID" -eq 0 ]; then
  SUDO=""
elif type "doas" > /dev/null; then
  SUDO="doas"
elif type "sudo" > /dev/null; then
  SUDO="sudo"
else 
  echo ">> Install sudo, doas or run the script as root"
  exit 1
fi

if ! type "pacstrap" > /dev/null; then
  echo ">> Please install arch-install-scripts"
  exit 1
fi

echo ">> Creating the root disk image"
rm -f root.raw
truncate -s 6G root.raw
mkfs.ext4 root.raw
mkdir -p mnt 
$SUDO mount root.raw mnt

echo ">> Installing base system"
$SUDO debootstrap stable mnt http://deb.debian.org/debian/
$SUDO bash -c "cp -r 0x* mnt/root"
$SUDO bash -c "rm -f mnt/root/0x*/*.elf mnt/root/0x*/*.py"

echo ">> Installing additional packages inside chroot"
$SUDO chroot mnt /bin/bash -c "apt install -y vim cowsay dhcpcd openssh-server gdb tmux python3-pwntools python3-capstone python3-pkg-resources wget"
$SUDO chroot mnt /bin/bash -c "wget https://kali.download/kali/pool/main/p/python-filebytes/python3-filebytes_0.10.2-0kali1_all.deb"
$SUDO chroot mnt /bin/bash -c "wget https://http.kali.org/kali/pool/main/r/ropper/ropper_1.13.8-0kali1_all.deb"
$SUDO chroot mnt /bin/bash -c "apt install -y ./python3-filebytes_0.10.2-0kali1_all.deb"
$SUDO chroot mnt /bin/bash -c "apt install -y ./ropper_1.13.8-0kali1_all.deb"
$SUDO chroot mnt /bin/bash -c "rm *.deb"

echo ">> Running chroot commands"
$SUDO chroot mnt /bin/bash -c "echo root:o101root | chpasswd"
$SUDO chroot mnt /bin/bash -c "echo o101 > /etc/hostname"
$SUDO chroot mnt /bin/bash -c "systemctl enable dhcpcd"
$SUDO chroot mnt /bin/bash -c "systemctl enable ssh"

echo ">> Copying config files"
$SUDO cp files/sshd    mnt/etc/ssh/sshd_config
$SUDO cp files/profile mnt/root/.profile
$SUDO cp files/bashrc  mnt/root/.bashrc
$SUDO cp files/vimrc   mnt/root/.vimrc

$SUDO cp files/noaslr.service mnt/usr/lib/systemd/system/noaslr.service
$SUDO install -m755 files/aslr.sh mnt/bin/toggle-aslr
$SUDO chroot mnt /bin/bash -c "systemctl enable noaslr"

$SUDO umount mnt
echo ">> Installation completed!"
