FROM debian:stretch

MAINTAINER Brenden Blanco <bblanco@gmail.com>

RUN DEBIAN_RELEASE=stretch && \
    # Adding non-free repo for netperf
    echo "deb http://deb.debian.org/debian ${DEBIAN_RELEASE} non-free" > \
        /etc/apt/sources.list.d/debian-non-free.list && \
    apt-get -qq update && \
    apt-get -y install pbuilder aptitude

COPY ./ /root/bcc

WORKDIR /root/bcc

RUN /usr/lib/pbuilder/pbuilder-satisfydepends && \
    ./scripts/build-deb.sh
