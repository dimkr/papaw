#!/bin/sh -xe

# This file is part of papaw.
#
# Copyright (c) 2019 Dima Krasner
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

if [ ! -f sh-packed ]
then
    # build with the oldest version of Meson we support
    CC=gcc-8 meson build-old -Dci=true
    ninja -C build-old

    test x`./build-old/test_putser` = xhello

    # pack /bin/sh and run the CI flow using the packed executable
    ./papawify build-old/papaw /bin/sh sh-packed
    export LD_PRELOAD=`pwd`/build-old/libpapaw.so
    exec ./sh-packed -xe $0
fi

unset LD_PRELOAD

# by default, packed executables should not exit when attached with ptrace()
test x`strace -o /dev/null ./build-old/test_putser` = xhello

# packed executables generate coredumps by default
echo /tmp/core > /proc/sys/kernel/core_pattern
ulimit -c unlimited
test x`./build-old/test_crasher` = x
test -n "`ls /tmp/core*`"

# packed executables that call papaw_hide_exe() run from RAM have an empty
# executable
./build-old/test_sleeper &
pid=$!
sleep 1
test -z "`grep test_sleeper /proc/$pid/maps`"
test ! -s /proc/$pid/exe

# ensure papaw does not leak file descriptors
test "`ls /proc/$pid/fd | wc -l`" -le "`ls /proc/$$/fd | wc -l`"

# ensure LD_PRELOAD is unset and papaw_hide_exe() was not called by libpapaw.so
test -z "`grep libpapaw /proc/$pid/maps`"

# regression test: papaw_hide_exe() used to work only if argv[0] is the basename
ln -s test_sleeper ./build-old/test_argv
./build-old/test_argv &
pid=$!
sleep 1
test -z "`grep test_argv /proc/$pid/maps`"
test ! -s /proc/$pid/exe

# the packed /bin/sh calls papaw_hide_exe() too, through LD_PRELOAD
test -z "`grep sh-packed /proc/$$/maps`"
test ! -s /proc/$$/exe

# make sure unpacking works
./unpapawify sh-packed sh-unpacked
cmp /bin/sh sh-unpacked

# packed executables can be deleted while running
rm -f sh-packed

# packed executables should exit if traced and allow_ptrace=false
meson configure build-old -Dallow_ptrace=false
ninja -C build-old
test -n "`strace ./build-old/test_putser 2>&1 | grep 'WEXITSTATUS(s) == 1'`"

# packed executables don't generate coredumps if allow_coredumps=false
meson configure build-old -Dallow_coredumps=false
ninja -C build-old
rm -f /tmp/core*
test x`./build-old/test_crasher` = x
test -z "`ls /tmp/core* 2>/dev/null`"

# the payload should be extracted to dir_prefix
here=`pwd`
meson configure build-old -Ddir_prefix=$here
ninja -C build-old
test -n "`strace -qqe mkdir ./build-old/test_putser 2>&1 | grep $here`"

# make sure there are no file descriptor leaks
valgrind -q --leak-check=full --error-exitcode=1 --malloc-fill=1 --free-fill=1 --track-fds=yes ./build-old/test_putser

# build with clang 8 and ASan
CC=clang-8 meson build-clang -Dci=true
ninja -C build-clang
test x`./build-clang/test_putser` = xhello
meson configure build-clang -Db_sanitize=address
./build-clang/test_putser

# make sure things still work when submodules are updated
git submodule update --remote --recursive
test x`./build-old/test_putser` = xhello

# make sure uncompressed binaries work
test x`./build-old/test_uncompressed` = xhello

# make sure unpacking of uncompressed binaries works
./unpapawify build-old/test_uncompressed putser-unpacked
cmp build-old/putser putser-unpacked

# build with the latest version of Meson
. /opt/meson/bin/activate
meson build-latest -Dci=true
ninja -C build-latest
