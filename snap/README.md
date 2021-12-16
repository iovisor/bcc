# bcc snap

This is an unconfined snap of the BPF Compiler Collection (BCC), a toolkit for
creating efficient kernel tracing and manipulation programs.

First, install snapcraft, e.g. on Ubuntu:

sudo snap install snapcraft --classic

Clone the bcc repo (if you haven't done so already) and create the snap:

    git clone https://github.com/iovisor/bcc.git
    snapcraft

Install the snap by running (`--dangerous` is required as the snap is
not coming from the Snap Store):

    sudo snap install --dangerous bcc_*.snap

One may need to ensure the snap interfaces are connected for the snap
using:

    sudo snap connect bcc:mount-observe
    sudo snap connect bcc:system-observe
    sudo snap connect bcc:system-trace

Now run a bcc tool, for example, to run opensnoop use:

    sudo bcc.opensnoop

Note that this may fail to build and run if you do not have the kernel
headers installed or perhaps the kernel config is not set up correctly.

This snap has been tested using the mainly 4.8 and 4.9 kernels built
with the Ubuntu Yakkety and Zesty kernel configs as well as the default
Ubuntu 4.8 Yakkey and 4.9 Zesty kernels.

Contact Colin Ian King <colin.king@canonical.com> for support on this
bcc snap.

Thu 15 Dec 17:08:29 GMT 2016
