FROM ubuntu:bionic

MAINTAINER Brenden Blanco <bblanco@gmail.com>

RUN apt-get -qq update && \
    apt-get -y install pbuilder aptitude

COPY ./ /root/bcc

WORKDIR /root/bcc

RUN /usr/lib/pbuilder/pbuilder-satisfydepends && \
    ./scripts/build-deb.sh
