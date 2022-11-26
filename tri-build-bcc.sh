
# Step 1. Check necessary kernel config options

git co -b v0.25.0 711f0302

mkdir build && cd build

cmake ..

# Using more threads to speedup the compilation
NUM_CPUS=$(grep -c ^processor /proc/cpuinfo)
THREADS=1
if [ $NUM_CPUS -gt 8 ]; then
    THREADS=8
elif [ $NUM_CPUS -gt 2 ]; then
    THREADS=$NUM_CPUS
fi
make -j $THREADS

sudo make install

cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install
popd

# Fix "/usr/bin/python: bad interpreter: No such file or directory" error
sudo ln -s /usr/bin/python3 /usr/bin/python
