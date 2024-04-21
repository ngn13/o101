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
rm -rf root.raw
truncate -s 6G root.raw
mkfs.ext4 root.raw
mkdir -p mnt 
$SUDO mount root.raw mnt

echo ">> Installing base system"
$SUDO pacstrap mnt base base-devel vim cowsay dhcpcd openssh gdb tmux python-pwntools ropper
$SUDO bash -c "cp -r 0x* mnt/root"
$SUDO bash -c "rm -f mnt/root/0x*/0x* mnt/root/0x*/*.py mnt/root/0x*/*.s mnt/root/0x*/.gitignore"

echo ">> Running chroot commands"
$SUDO chroot mnt /bin/bash -c "echo root:o101root | chpasswd"
$SUDO chroot mnt /bin/bash -c "echo o101 > /etc/hostname"
$SUDO chroot mnt /bin/bash -c "systemctl enable dhcpcd"
$SUDO chroot mnt /bin/bash -c "systemctl enable sshd"

echo ">> Copying config files"
$SUDO cp files/sshd    mnt/etc/ssh/sshd_config
$SUDO cp files/sshd    mnt/etc/ssh/sshd_config
$SUDO cp files/profile mnt/root/.profile
$SUDO cp files/bashrc  mnt/root/.bashrc
$SUDO cp files/vimrc   mnt/root/.vimrc

$SUDO cp files/noaslr.service mnt/usr/lib/systemd/system/noaslr.service
$SUDO install -m755 files/aslr.sh mnt/bin/toggle-aslr
$SUDO chroot mnt /bin/bash -c "systemctl enable noaslr"

$SUDO umount mnt
echo ">> Installation completed!"
