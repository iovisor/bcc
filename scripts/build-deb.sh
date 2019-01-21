#!/bin/bash

# helper script to be invoked by jenkins/buildbot

# $1 [optional]: the build type - release | nightly | test
buildtype=${1:-test}

set -x
set -e

PARALLEL=${PARALLEL:-1}
TMP=$(mktemp -d /tmp/debuild.XXXXXX)

function cleanup() {
  [[ -d $TMP ]] && rm -rf $TMP
}
trap cleanup EXIT

# populate submodules
git submodule update --init --recursive

. scripts/git-tag.sh

git archive HEAD --prefix=bcc/ --format=tar -o $TMP/bcc_$revision.orig.tar

# archive submodules
pushd src/cc/libbpf
git archive HEAD --prefix=bcc/src/cc/libbpf/ --format=tar -o $TMP/bcc_libbpf_$revision.orig.tar
popd

pushd $TMP

# merge all archives into bcc_$revision.orig.tar.gz
tar -A -f bcc_$revision.orig.tar bcc_libbpf_$revision.orig.tar
gzip bcc_$revision.orig.tar

tar xf bcc_$revision.orig.tar.gz
cd bcc

debuild=debuild
if [[ "$buildtype" = "test" ]]; then
  # when testing, use faster compression options
  debuild+=" --preserve-envvar PATH"
  echo -e '#!/bin/bash\nexec /usr/bin/dpkg-deb -z1 "$@"' \
    | sudo tee /usr/local/bin/dpkg-deb
  sudo chmod +x /usr/local/bin/dpkg-deb
  dch -b -v $revision-$release "$git_subject"
fi
if [[ "$buildtype" = "nightly" ]]; then
  dch -v $revision-$release "$git_subject"
fi

DEB_BUILD_OPTIONS="nocheck parallel=${PARALLEL}" $debuild -us -uc
popd

cp $TMP/*.deb .
