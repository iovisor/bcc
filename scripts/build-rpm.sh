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

. scripts/git-tag.sh

git archive HEAD --prefix=bcc/ --format=tar.gz -o $TMP/SOURCES/bcc.tar.gz

sed \
  -e "s/^\(Version:\s*\)@REVISION@/\1$revision/" \
  -e "s/^\(Release:\s*\)@GIT_REV_COUNT@/\1$release/" \
  SPECS/bcc.spec > $TMP/SPECS/bcc.spec

pushd $TMP
rpmbuild $RPM_WITH_OPTS --define "_topdir `pwd`" -ba SPECS/bcc.spec
popd

cp $TMP/RPMS/*/*.rpm .
cp $TMP/SRPMS/*.rpm .
