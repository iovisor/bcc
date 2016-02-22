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
# only the most recent tag
git_tag_latest=$(git describe --abbrev=0)
git_rev_count=$(git rev-list $git_tag_latest.. --count)
release=0
if [[ "$git_rev_count" != "0" ]]; then
  release=$(git log --pretty='g%h' -n 1)
fi
revision=${git_tag_latest:1}

git archive HEAD --prefix=bcc/ --format=tar.gz -o $TMP/SOURCES/$git_tag_latest.tar.gz
wget -P $TMP/SOURCES http://llvm.org/releases/$llvmver/{cfe,llvm}-$llvmver.src.tar.xz

sed \
  -e "s/^\(Version:\s*\)@REVISION@/\1$revision/" \
  -e "s/^\(Release:\s*\)@GIT_REV_COUNT@/\1$release/" \
  SPECS/bcc+clang.spec > $TMP/SPECS/bcc.spec

pushd $TMP
rpmbuild --define "_topdir `pwd`" -ba SPECS/bcc.spec
popd

cp $TMP/RPMS/*/*.rpm .
cp $TMP/SRPMS/*.rpm .
