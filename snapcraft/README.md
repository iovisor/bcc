# bcc snap

This is an unconfined snap of the BPF Compiler Collection (BCC), a toolkit for
creating efficient kernel tracing and manipulation programs.

First, install snapcraft, e.g. on Ubuntu:

sudo apt install snapcraft

Clone the bcc repo (if you haven't done so already) and create the snap:

git clone https://github.com/iovisor/bcc.git
cd snapcraft
make

Note: running `make` just gets the version from the current bcc gito
repository and uses this in the snapcraft yaml file to version the bcc
snap. The Makefile basically runs snapcraft to snap up bcc.

Install the snap by running:

sudo snap install --devmode bcc_*.snap

One may need to ensure the snap plugins are enabled for the snap using:

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
