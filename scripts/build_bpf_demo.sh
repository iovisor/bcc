#!/bin/bash

#set -x
set -e

function usage() {
  cat <<DELIM__
usage: $(basename $0) [options]

Options:
  -b, --bridge BRNAME   Which linux bridge to attach to
  -c, --cpu NUM         Number of CPUs to reserve to the instance (default 4)
  -g, --github_token X  HTTP Github oauth token (for buildbots)
  -k, --kickstart KS    Path to kickstart file to use (required)
  -m, --mirror URL      URL at which to reach netinstallable packages
  -M, --mem NUM         Number of MB to reserve to the instance (default 4094)
  -n, --name NAME       Name of the instance (required)
  -p, --password PASS   Password to set in the VM
  -s, --size NUM        Size in GB to reserve for the virtual HDD (default 40GB)
DELIM__
}

TEMP=$(getopt -o b:c:k:m:M:n:p:s: --long bridge:,cpu:,kickstart:,mirror:,mem:,name:,password:size: -- "$@")
if [[ $? -ne 0 ]]; then
  usage
  exit 1
fi

eval set -- "$TEMP"

while true; do
  case "$1" in
    -b|--bridge) BRIDGE="$2"; shift 2 ;;
    -c|--cpu) CPU="$2"; shift 2 ;;
    -k|--kickstart) KICKSTART="$2"; shift 2 ;;
    -n|--name) NAME="$2"; shift 2 ;;
    -m|--mirror) MIRROR="$2"; shift 2 ;;
    -M|--mem) MEM="$2"; shift 2 ;;
    -p|--password) PASSWORD="$2"; shift 2 ;;
    -s|--size) SIZE="$2"; shift 2 ;;
    --) shift; break ;;
    *) usage; exit 1
      ;;
  esac
done
[[ ! -f "$KICKSTART" ]] && { usage; exit 1; }
[[ -z "$NAME" ]] && { usage; exit 1; }

PASSWORD=${PASSWORD:-"iovisor"}
BRIDGE=${BRIDGE:-virbr0}
MIRROR=${MIRROR:-http://mirror.pnl.gov/fedora/linux/releases/22}
MEM=${MEM:-4094}
CPU=${CPU:-4}
SIZE=${SIZE:-40}

if [[ "$(id -u)" != "0" ]]; then
  sudo="sudo"
fi

if ! which virt-install &> /dev/null; then
  echo "Error: virt-install is not installed"
  exit 1
fi

libvirt_dir=/var/lib/libvirt/images
img_name=$NAME
tmpdir=$(mktemp -d /tmp/virt-install_XXXXX)
tmp_ks_file=$tmpdir/$img_name.ks

function cleanup() {
  set +e
  [[ -d "$tmpdir" ]] && rm -fr "$tmpdir"
  local destroy_kvm=n
  [[ -f "/etc/libvirt/qemu/$img_name.xml" ]] && read -p "Destroy libvirt VM (y/n)? " destroy_kvm
  if [[ "$destroy_kvm" != n* ]]; then
    virsh destroy $img_name
    virsh undefine $img_name
    virsh vol-delete $img_name.img --pool default
    $sudo rm -f $libvirt_dir/$img_name.img
  fi
}
trap cleanup EXIT

ruby <<DELIM__
require 'erb'
@password="$PASSWORD"
@name="$NAME"
@domain="example.com"
@github_access_token="$GITHUB_ACCESS_TOKEN"
@mirror="$MIRROR"
File.open('$tmp_ks_file', 'w') do |f|
  f.puts ERB.new(File.open('$KICKSTART', 'rb').read, nil, '-').result()
end
DELIM__

tree=$MIRROR/Server/x86_64/os/
virt-install --connect=qemu:///system \
    --network=bridge:$BRIDGE \
    --initrd-inject=$tmp_ks_file \
    --controller type=scsi,model=virtio-scsi \
    --extra-args="ks=file:/$(basename $tmp_ks_file) console=tty0 console=ttyS0,115200" \
    --name=$img_name \
    --disk $libvirt_dir/$img_name.img,cache=none,format=qcow2,size=$SIZE,bus=scsi \
    --ram $MEM \
    --vcpus=$CPU \
    --check-cpu \
    --accelerate \
    --hvm \
    --location=$tree \
    --nographics

echo "SUCCESS"
exit 0
