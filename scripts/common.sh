#!/bin/bash

# paths
DISTDIR="./dist"
SRCDIR="./src"
MNTDIR="${DISTDIR}/mnt"
IMAGE="${DISTDIR}/root.raw"

# glibc vars
glibc_hash="2abc038f5022949cb67e996c3cae0e7764f99b009f0b9b7fd954dfc6577b599e"
glibc_version="2.40"

glibc_dir="glibc-${glibc_version}"
glibc_archive="${glibc_dir}.tar.gz"

# colors
FG_YELLOW="\e[0;33m"
FG_BLUE="\e[0;34m"
FG_RED="\e[0;31m"
FG_RESET="\e[0m"
FG_BOLD="\e[1m"

# logging
info(){
  echo -e "${FG_BOLD}${FG_BLUE}[*] ${FG_RESET}${FG_BOLD}${1}${FG_RESET}"
}

warn(){
  echo -e "${FG_BOLD}${FG_YELLOW}[!] ${FG_RESET}${FG_BOLD}${1}${FG_RESET}"
}

error(){
  echo -e "${FG_BOLD}${FG_RED}[-] ${FG_RESET}${FG_BOLD}${1}${FG_RESET}"
}

# check for sudo, doas or root
if [ "$EUID" -eq 0 ]; then
  SUDO=""
elif type "doas" > /dev/null; then
  SUDO="doas"
elif type "sudo" > /dev/null; then
  SUDO="sudo"
else
  error "Install sudo, doas or run the script as root"
  exit 1
fi

# check the base directory (scripts should be run from the repo root)
if [ "$(basename "${PWD}")" == "scripts" ] || [ "$(basename "${PWD}")" == "src" ]; then
  error "Please run the scripts from the root of the repository"
  exit 1
fi

# check the return value of the previous command
check_ret (){
  if [ $? -ne 0 ]; then
    if [ ! -z "${1}" ]; then
      error "${1}"
    fi
    exit 1
  fi
}

# compares SHA256 hash of a given file with a provided hash
check_sha256() {
  local hash=$(sha256sum "${1}" | cut -d " " -f 1)
  if [[ "${hash}" == "${2}" ]]; then
    info "Good hash for $1"
    return 0
  else
    error "Bad hash for $1"
    return 1
  fi
}

# create the dist directory
mkdir -p "${DISTDIR}"
check_ret "Failed to create the dist directory"
