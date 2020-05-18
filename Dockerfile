# ============================================================================
# ToxProxy
# Copyright (C) 2019 - 2020 Zoff <zoff@zoff.cc>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# ============================================================================
#
# --------------------------------------------------------
#
# command to build:             docker build -t zoff99/toxproxy .
# command to prep :             mkdir -p ./dockerdata/
# command to run  :             docker run --rm --volume=$(pwd)/dockerdata:/home/pi/src/db -d zoff99/toxproxy
#
# --------------------------------------------------------

FROM ubuntu:18.04
LABEL maintainer="zoff99"
LABEL vendor1="https://github.com/zoff99/ToxProxy"

WORKDIR /home/pi/
COPY src /home/pi/src/

ENV _INST_ /home/pi/inst
ENV _SRC_ /home/pi/src

RUN apt-get update && \
            apt-get install -y --force-yes --no-install-recommends \
            clang \
            cmake \
            libconfig-dev \
            libgtest-dev \
            pkg-config \
            zip grep file ca-certificates autotools-dev autoconf automake \
            git bc wget rsync make pkg-config libtool \
            ssh gzip tar unzip \
            coreutils && \
            apt-get install -y --force-yes --no-install-recommends \
            libsodium-dev \
            libx264-dev \
            libavcodec-dev \
            libavutil-dev \
            libvpx-dev \
            libopus-dev \
            libsqlite3-dev \
            sqlite3

RUN         mkdir -p "$_INST_" ; mkdir -p "$_SRC_" ; \
            cd "$_SRC_" ; \
            git clone https://github.com/zoff99/c-toxcore

RUN         cd "$_SRC_"/c-toxcore/ ; \
            git checkout zoff99/zoxcore_local_fork

RUN         cd "$_SRC_"/c-toxcore/ ; \
            git checkout 5e5c6ad18092b3d73cc5cc8643ddb18adb659a72 || echo "commit seems gone, using latest commit"

RUN         cd "$_SRC_"/c-toxcore/ ; \
            ./autogen.sh ; \
            export CFLAGS_=" -D_GNU_SOURCE -I$_INST_/include/ -O3 -g -fstack-protector-all " ; \
            export CFLAGS="$CFLAGS_" ; \
            export LDFLAGS="-L$_INST_/lib" ; \
            ./configure \
                --prefix=$_INST_ \
                --disable-soname-versions --disable-testing --disable-shared

RUN         cd "$_SRC_"/c-toxcore/ ; \
            make -j$(nproc) || exit 1

RUN         cd "$_SRC_"/c-toxcore/ ; make install

RUN         cd /home/pi/src/ ; \
            export CFLAGS=" -Wall -Wextra -Wno-unused-parameter -flto -fPIC -std=gnu99 -I$_INST_/include/ -L$_INST_/lib -O3 -g -fstack-protector-all " ; \
            gcc $CFLAGS \
                ToxProxy.c \
                $_INST_/lib/libtoxcore.a \
                $_INST_/lib/libtoxav.a \
                $_INST_/lib/libtoxencryptsave.a \
                -l:libopus.a \
                -l:libvpx.a \
                -l:libx264.a \
                -l:libavcodec.a \
                -l:libavutil.a \
                -l:libsodium.a \
                -lm \
                -ldl \
                -lpthread \
                -o ToxProxy || exit 1

ENTRYPOINT pwd ; cd /home/pi/src/ ; while [ true ]; do ./ToxProxy ; sleep 5 ; done
