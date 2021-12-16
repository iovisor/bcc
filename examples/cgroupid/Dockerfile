# builder image
FROM ubuntu:18.04 as builder
RUN apt-get update && \
apt-get upgrade -y && \
apt-get install -y --no-install-recommends \
    gcc build-essential && \
apt-get purge --auto-remove && \
apt-get clean

ADD cgroupid.c /cgroupid.c
ADD Makefile /Makefile
RUN make

# Main image
FROM amd64/alpine:3.8 as base
COPY --from=builder /cgroupid /bin
