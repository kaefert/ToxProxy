#! /bin/bash


_HOME2_=$(dirname $0)
export _HOME2_
_HOME_=$(cd $_HOME2_;pwd)
export _HOME_


echo $_HOME_
cd $_HOME_
mkdir -p build

export _SRC_=$_HOME_/build/
export _INST_=$_HOME_/inst/

echo $_SRC_
echo $_INST_

mkdir -p $_SRC_
mkdir -p $_INST_

export LD_LIBRARY_PATH=$_INST_/lib/
export PKG_CONFIG_PATH=$_INST_/lib/pkgconfig


if [ 1 ==  2 ]; then

sudo apt-get -y install cmake
sudo apt-get -y install ffmpeg
sudo apt-get -y install libavcodec-dev
sudo apt-get -y install libavdevice-dev
sudo apt-get -y install libexif-dev
sudo apt-get -y install libsodium-dev
sudo apt-get -y install libsqlcipher-dev
sudo apt-get -y install libvpx-dev
sudo apt-get -y install libxv-dev libvdpau-dev libxcb-shm0-dev
sudo apt-get -y install libxv-dev libvdpau-dev libxcb-shm0-dev
sudo apt-get -y install libva-dev
sudo apt-get -y install libopus-dev libvpx-dev
sudo apt-get -y install libopus-dev libx264-dev
sudo apt-get -y install libopus-dev libsodium-dev

sudo apt-get -y install libncursesw5-dev
sudo apt-get -y install libcurl4-gnutls-dev


fi


# build toxcore -------------

if [ "$1""x" == "1x" ]; then

    cd $_SRC_
    rm -Rf ./c-toxcore/
    git clone https://github.com/zoff99/c-toxcore
    cd c-toxcore/
    git checkout "zoff99/zoxcore_local_fork"


    export CFLAGS=" -DMIN_LOGGER_LEVEL=LOGGER_LEVEL_INFO -D_GNU_SOURCE -g -O3 -I$_INST_/include/ -fPIC -Wall -Wextra -Wno-unused-function -Wno-unused-parameter -Wno-unused-variable -Wno-unused-but-set-variable "
    export LDFLAGS=" -O3 -L$_INST_/lib -fPIC "
    ./autogen.sh
    ./configure \
      --prefix=$_INST_ \
      --disable-soname-versions --disable-testing --enable-logging --disable-shared

    make -j $(nproc) || exit 1
    make install

fi

# build toxic -------------

cd $_HOME_
cd src

export CFLAGS=" -fPIC -std=gnu99 -I$_INST_/include/ -L$_INST_/lib -O3 -g -fstack-protector-all "
gcc $CFLAGS \
ToxProxy.c \
$_INST_/lib/libtoxcore.a \
-lopus \
-lvpx \
-lx264 \
-lavcodec \
-lavutil \
-lm \
-l:libsodium.a \
-lpthread \
-o ToxProxy

ls -hal ToxProxy
file ToxProxy
ldd ToxProxy


