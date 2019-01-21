#!/bin/bash

set -x
set -e

TMP=$(mktemp -d /tmp/rpmbuild.XXXXXX)

function cleanup() {
  [[ -d $TMP ]] && rm -rf $TMP
}
trap cleanup EXIT

mkdir $TMP/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

llvmver=3.7.1

# populate submodules
git submodule update --init --recursive

. scripts/git-tag.sh

git archive HEAD --prefix=bcc/ --format=tar -o $TMP/SOURCES/bcc.tar

# archive submodules
pushd src/cc/libbpf
git archive HEAD --prefix=bcc/src/cc/libbpf/ --format=tar -o $TMP/SOURCES/bcc_libbpf.tar
popd

# merge all archives into bcc.tar.gz
pushd $TMP/SOURCES
tar -A -f bcc.tar bcc_libbpf.tar
gzip bcc.tar
popd

sed \
  -e "s/^\(Version:\s*\)@REVISION@/\1$revision/" \
  -e "s/^\(Release:\s*\)@GIT_REV_COUNT@/\1$release/" \
  SPECS/bcc.spec > $TMP/SPECS/bcc.spec

pushd $TMP
rpmbuild $RPM_WITH_OPTS --define "_topdir `pwd`" -ba SPECS/bcc.spec
popd

cp $TMP/RPMS/*/*.rpm .
cp $TMP/SRPMS/*.rpm .
