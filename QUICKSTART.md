# Quick Start Guide

A Docker container is provided for user to try out [bcc](https://github.com/iovisor/bcc).

From your host shell:
```bash
docker run -it --rm \
  --privileged \
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  -v /etc/localtime:/etc/localtime:ro \
  --workdir /usr/share/bcc/tools \
  zlim/bcc
```

Now, from the container shell, you can try the various pre-installed bcc tools.

For examples, please refer to the [tutorial](docs/tutorial.md#1-general-performance).

If you wish to install bcc on your host, please refer to [INSTALL.md](INSTALL.md).
