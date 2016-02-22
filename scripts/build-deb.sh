#!/bin/bash

set -x
set -e

PARALLEL=${PARALLEL:-1}
TMP=$(mktemp -d /tmp/debuild.XXXXXX)

function cleanup() {
  [[ -d $TMP ]] && rm -rf $TMP
}
trap cleanup EXIT

git_tag_latest=$(git describe --abbrev=0)
git_rev_count=$(git rev-list $git_tag_latest.. --count)
git_rev_count=$[$git_rev_count+1]
git_subject=$(git log --pretty="%s" -n 1)
release=$git_rev_count
if [[ "$release" != "1" ]]; then
  release="${release}.git.$(git log --pretty='%h' -n 1)"
fi
revision=${git_tag_latest:1}

git archive HEAD --prefix=bcc/ --format=tar.gz -o $TMP/bcc_$revision.orig.tar.gz

pushd $TMP
tar xf bcc_$revision.orig.tar.gz
cd bcc
dch -v $revision-$release "$git_subject"
DEB_BUILD_OPTIONS="nocheck parallel=${PARALLEL}" debuild -us -uc
popd

cp $TMP/*.deb .
