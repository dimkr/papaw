#!/bin/sh -xe

# This file is part of papaw.
#
# Copyright (c) 2020, 2021 Dima Krasner
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

toolchains="arm-any32-linux-musleabi armeb-any32-linux-musleabi i386-any32-linux-musl x86_64-any64-linux-musl mips-any32-linux-musl mipsel-any32-linux-musl"

for i in $toolchains
do
    meson --cross-file=$i -Dcompression=$1 --buildtype=release build-$1-$i
    ninja -C build-$1-$i
    /opt/x-tools/$i/bin/$i-strip -s -R.note -R.comment build-$1-$i/papaw
    install -D -m 755 build-$1-$i/papaw artifacts/papaw-$1-${i%%-*}
done

install -m 755 build-$1-arm-any32-linux-musleabi/papawify artifacts/papawify-$1
install -m 755 build-$1-arm-any32-linux-musleabi/unpapawify artifacts/unpapawify-$1

for i in $toolchains
do
    unset CFLAGS
    unset LDFLAGS
    . /opt/x-tools/$i/activate
    /bin/echo -e "#include <stdio.h>\nint main() {printf(\"%s%s\\\n\", \"hel\", \"lo\"); return 0;}" | $i-gcc $CFLAGS -x c -o artifacts/hello-${i%%-*} - $LDFLAGS
    python3 artifacts/papawify-$1 artifacts/papaw-$1-${i%%-*} artifacts/hello-${i%%-*} artifacts/hello-$1-${i%%-*}
done
