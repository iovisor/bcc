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

. scripts/git-tag.sh

git archive HEAD --prefix=bcc/ --format=tar.gz -o $TMP/bcc_$revision.orig.tar.gz

pushd $TMP
tar xf bcc_$revision.orig.tar.gz
cd bcc

if [[ "$buildtype" = "test" ]]; then
  dch -b -v $revision-$release "$git_subject"
fi
if [[ "$buildtype" = "nightly" ]]; then
  dch -v $revision-$release "$git_subject"
fi

DEB_BUILD_OPTIONS="nocheck parallel=${PARALLEL}" debuild -us -uc
popd

cp $TMP/*.deb .
