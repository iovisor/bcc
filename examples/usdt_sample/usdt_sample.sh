#!/usr/bin/bash

# sudo apt-get install linux-headers-$(uname -r) "llvm-13*" libclang-13-dev luajit luajit-5.1-dev libelf-dev python3-setuptools libdebuginfod-dev arping netperf iperf
# mkdir -p build && cd build
# cmake .. -DPYTHON_CMD=python3
# make -j4
# sudo make install

gcc --version
rm -rf examples/usdt_sample/build_gcc
mkdir -p examples/usdt_sample/build_gcc && pushd examples/usdt_sample/build_gcc
cmake ..
make
popd

# sudo dnf install systemtap-sdt-dev  # For Ubuntu 21.10, other distro's might have differently named packages.
# dtrace -h -s usdt_sample_lib1/src/lib1_sdt.d -o usdt_sample_lib1/include/usdt_sample_lib1/lib1_sdt.h
# dtrace -G -s usdt_sample_lib1/src/lib1_sdt.d -o lib1_sdt.o

python3 tools/tplist.py -l examples/usdt_sample/build_gcc/usdt_sample_lib1/libusdt_sample_lib1.so
readelf -n examples/usdt_sample/build_gcc/usdt_sample_lib1/libusdt_sample_lib1.so

examples/usdt_sample/build_gcc/usdt_sample_app1/usdt_sample_app1 "usdt" 1 30 10 1 50 &
pid=$!

echo "argdist.py - Using non-sdt probes"
sudo python3 tools/argdist.py -p ${pid} -i 5 -C "u:$(pwd)/examples/usdt_sample/build_gcc/usdt_sample_lib1/libusdt_sample_lib1.so:operation_start():char*:arg2#input" -z 32 &
sleep 30
sudo pkill -f "\\-p.${pid}"
echo "argdist.py - Using sdt probes"
sudo python3 tools/argdist.py -p ${pid} -i 5 -C "u:$(pwd)/examples/usdt_sample/build_gcc/usdt_sample_lib1/libusdt_sample_lib1.so:operation_start_sdt():char*:arg2#input" -z 32 &
sleep 30
sudo pkill -f "\\-p.${pid}"
sudo python3 examples/usdt_sample/scripts/latency.py -p=${pid} -f="usdt_20" &
sleep 30
sudo pkill -f "\\-p.${pid}"
sudo python3 examples/usdt_sample/scripts/latency.py -p=${pid} -f="usdt_20" -s &
sleep 30
sudo pkill -f "\\-p.${pid}"
sudo python3 examples/usdt_sample/scripts/lat_dist.py -p=${pid} -i=5 -f="usdt_20" &
sleep 30
sudo pkill -f "\\-p.${pid}"
sudo python3 examples/usdt_sample/scripts/lat_dist.py -p=${pid} -i=5 -f="usdt_20" -s &
sleep 30
sudo pkill -f "\\-p.${pid}"
sudo python3 examples/usdt_sample/scripts/lat_avg.py -p=${pid} -i=5 -c=10 -f="usdt_20" &
sleep 30
sudo pkill -f "\\-p.${pid}"
sudo python3 examples/usdt_sample/scripts/lat_avg.py -p=${pid} -i=5 -c=10 -f="usdt_20" -s &
sleep 30
sudo pkill -f "\\-p.${pid}"

sudo pkill -f "examples/usdt_sample/build_.*/usdt_sample_app1/usdt_sample_app1"

clang --version
rm -rf examples/usdt_sample/build_clang
mkdir -p examples/usdt_sample/build_clang && pushd examples/usdt_sample/build_clang
cmake .. -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
make
popd

python3 tools/tplist.py -l examples/usdt_sample/build_clang/usdt_sample_lib1/libusdt_sample_lib1.so
readelf -n examples/usdt_sample/build_clang/usdt_sample_lib1/libusdt_sample_lib1.so

examples/usdt_sample/build_clang/usdt_sample_app1/usdt_sample_app1 "usdt" 1 30 10 1 50 &
pid=$!

echo "argdist.py - Using non-sdt probes"
sudo python3 tools/argdist.py -p ${pid} -i 5 -C "u:$(pwd)/examples/usdt_sample/build_clang/usdt_sample_lib1/libusdt_sample_lib1.so:operation_start():char*:arg2#input" -z 32 &
sleep 30
sudo pkill -f "\\-p.${pid}"
echo "argdist.py - Using sdt probes"
sudo python3 tools/argdist.py -p ${pid} -i 5 -C "u:$(pwd)/examples/usdt_sample/build_clang/usdt_sample_lib1/libusdt_sample_lib1.so:operation_start_sdt():char*:arg2#input" -z 32 &
sleep 30
sudo pkill -f "\\-p.${pid}"
sudo python3 examples/usdt_sample/scripts/latency.py -p=${pid} -f="usdt_20" &
sleep 30
sudo pkill -f "\\-p.${pid}"
sudo python3 examples/usdt_sample/scripts/latency.py -p=${pid} -f="usdt_20" -s &
sleep 30
sudo pkill -f "\\-p.${pid}"
sudo python3 examples/usdt_sample/scripts/lat_dist.py -p=${pid} -i=5 -f="usdt_20" &
sleep 30
sudo pkill -f "\\-p.${pid}"
sudo python3 examples/usdt_sample/scripts/lat_dist.py -p=${pid} -i=5 -f="usdt_20" -s &
sleep 30
sudo pkill -f "\\-p.${pid}"
sudo python3 examples/usdt_sample/scripts/lat_avg.py -p=${pid} -i=5 -c=10 -f="usdt_20" &
sleep 30
sudo pkill -f "\\-p.${pid}"
sudo python3 examples/usdt_sample/scripts/lat_avg.py -p=${pid} -i=5 -c=10 -f="usdt_20" -s &
sleep 30
sudo pkill -f "\\-p.${pid}"

sudo pkill -f "examples/usdt_sample/build_.*/usdt_sample_app1/usdt_sample_app1"
