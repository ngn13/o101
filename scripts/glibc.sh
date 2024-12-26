#!/bin/bash

if ! source "./scripts/common.sh"; then
  echo "Failed to import common.sh, please the scripts from the repository's root directory"
  exit 1
fi

glibc_patches=(
  "c621d4f" # malloc: Split _int_free() into 3 sub functions
  "c69e8cc" # malloc: Avoid func call for tcache quick path in free()
  "e2436d6" # malloc: send freed small chunks to smallbin
  "1c4cebb" # malloc: Optimize small memory clearing for calloc
  "a9944a5" # malloc: add indirection for malloc(-like) functions in tests [BZ #32366]
  "226e3b0" # malloc: Add tcache path for calloc
  "tcache_put_log" # add logging to tcache_put
)

apply_patches(){
  for patch in "${glibc_patches[@]}"; do
    info "Applying patch: ${patch}"
    pushd "${glibc_dir}" > /dev/null
      patch -p1 < "../../${SRCDIR}/files/glibc_patches/${patch}.patch"
    popd > /dev/null
    check_ret "Failed to apply the patch"
  done
}

pushd "${DISTDIR}" > /dev/null
  rm -rf "${glibc_dir}"
  check_ret "Failed to remove the glibc directory"

  if [ ! -f "${glibc_archive}" ]; then
    wget "https://ftp.gnu.org/gnu/glibc/${glibc_archive}"
    check_ret "Failed to download glibc ${glibc_version} archive"
   else
    warn "glibc already seems to be downloaded, not re-downloading"
  fi

  check_sha256 "${glibc_archive}" "${glibc_hash}"

  tar xf "${glibc_archive}"
  check_ret "Failed to extract the glibc ${glibc_version} archive"

  apply_patches
popd > /dev/null
