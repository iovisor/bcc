#!/bin/bash
set -e
# Builds debian packages using docker wrapper

function help() {
  message=$1
  echo "USAGE: build.sh DOCKER_REPO DOCKER_TAG OS_TAG [DISTRO]"
  echo "hint: ${message}"
}

docker_repo=$1
docker_tag=$2
os_tag=$3
distro=${4:-ubuntu}

[ -z "${docker_repo}" ] && help "You must specify repo, eg: quay.io/iovisoc/bcc" && exit 1
[ -z "${docker_tag}" ] && help "You must specify tag, eg: bionic-release-master, latest, SHA, git tag, etc " && exit 1
[ -z "${os_tag}" ] && help "You must specify os tag, eg: 18.04, bionic, etc " && exit 1


# The main docker image build,
echo "Building ${distro} ${os_tag} release docker image for ${docker_repo}:${docker_tag}"
docker build -t ${docker_repo}:${docker_tag} --build-arg OS_TAG=${os_tag} -f docker/Dockerfile.${distro} .

echo "Copying build artifacts to $(pwd)/output"
mkdir -p output
docker run -v $(pwd)/output:/output ${docker_repo}:${docker_tag} /bin/bash -c "cp /root/bcc/* /output"
