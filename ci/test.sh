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

if [ ! -f sh-packed-$1 ]
then
    meson build-$1 -Dcompression=$1 -Dci=true
    ninja -C build-$1

    test x`./build-$1/test_putser` = xhello

    # pack the shell and run the CI flow using the packed executable
    ./build-$1/papawify build-$1/papaw /bin/dash sh-packed-$1
    export LD_PRELOAD=`pwd`/build-$1/libpapaw.so
    exec ./sh-packed-$1 -xe $0 $1
fi

unset LD_PRELOAD

# by default, packed executables should not exit when attached with ptrace()
test x`strace -o /dev/null ./build-$1/test_putser` = xhello

# packed executables generate coredumps by default
echo /tmp/core > /proc/sys/kernel/core_pattern
ulimit -c unlimited
test x`./build-$1/test_crasher` = x
test -n "`ls /tmp/core*`"

# packed executables that call papaw_hide_exe() run from RAM have an empty
# executable
./build-$1/test_sleeper &
pid=$!
sleep 1
test -z "`grep test_sleeper /proc/$pid/maps`"
test ! -s /proc/$pid/exe

# ensure papaw does not leak file descriptors
test "`ls /proc/$pid/fd | wc -l`" -le "`ls /proc/$$/fd | wc -l`"

# ensure LD_PRELOAD is unset and papaw_hide_exe() was not called by libpapaw.so
test -z "`grep libpapaw /proc/$pid/maps`"

# regression test: papaw_hide_exe() used to work only if argv[0] is the basename
ln -s test_sleeper ./build-$1/test_argv
./build-$1/test_argv &
pid=$!
sleep 1
test -z "`grep test_argv /proc/$pid/maps`"
test ! -s /proc/$pid/exe

# the packed /bin/sh calls papaw_hide_exe() too, through LD_PRELOAD
test -z "`grep sh-packed-$1 /proc/$$/maps`"
test ! -s /proc/$$/exe

# make sure unpacking works
./build-$1/unpapawify sh-packed-$1 sh-unpacked-$1
cmp /bin/dash sh-unpacked-$1

# packed executables can be deleted while running
rm -f sh-packed-$1

# packed executables should exit if traced and allow_ptrace=false
meson configure build-$1 -Dallow_ptrace=false
ninja -C build-$1
test -n "`strace ./build-$1/test_putser 2>&1 | grep 'WEXITSTATUS(s) == 1'`"

# packed executables don't generate coredumps if allow_coredumps=false
meson configure build-$1 -Dallow_coredumps=false
ninja -C build-$1
rm -f /tmp/core*
test x`./build-$1/test_crasher` = x
test -z "`ls /tmp/core* 2>/dev/null`"

# make sure there are no compression-related strings
test -z "`strings -a ./build-$1/test_putser | grep -i -e $1 -e miniz -e zlib -e zstandard -e zstd -e huff -e rle -e copy -e license -e papaw`"

# the payload should be extracted to dir_prefix
here=`pwd`
meson configure build-$1 -Ddir_prefix=$here
ninja -C build-$1
test -n "`strace -qqe mkdir ./build-$1/test_putser 2>&1 | grep $here`"

# make sure binwalk fails to identify the payload format
test `binwalk -M ./build-$1/test_putser | grep 0x | wc -l` -eq 1

# make sure there are no file descriptor leaks
valgrind -q --leak-check=full --error-exitcode=1 --malloc-fill=1 --free-fill=1 --track-fds=yes ./build-$1/test_putser

# build with clang and ASan
CC=clang meson build-clang-$1 -Dcompression=$1 -Dci=true
ninja -C build-clang-$1
test x`./build-clang-$1/test_putser` = xhello
meson configure build-clang-$1 -Db_sanitize=address
./build-clang-$1/test_putser

# make sure things still work when submodules are updated
git submodule update --remote --recursive
test x`./build-$1/test_putser` = xhello

# make sure uncompressed binaries work
test x`./build-$1/test_uncompressed` = xhello

# make sure unpacking of uncompressed binaries works
./build-$1/unpapawify build-$1/test_uncompressed putser-unpacked
cmp build-$1/putser putser-unpacked
