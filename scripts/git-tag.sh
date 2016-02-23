git_tag_latest=$(git describe --abbrev=0)
git_rev_count=$(git rev-list $git_tag_latest.. --count)
git_rev_count=$[$git_rev_count+1]
git_subject=$(git log --pretty="%s" -n 1)
release=$git_rev_count
if [[ "$release" != "1" ]]; then
  release="${release}.git.$(git log --pretty='%h' -n 1)"
fi
revision=${git_tag_latest:1}
