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

# build with the oldest version of Meson we support
CC=gcc-8 meson build-old
ninja -C build-old

test x`./build-old/test_putser` = xhello

# packed executables should exit when attached with ptrace()
test -n "`strace ./build-old/test_putser 2>&1 | grep 'WEXITSTATUS(s) == 1'`"

# packed executables don't generate coredumps by default
echo /tmp/core > /proc/sys/kernel/core_pattern
test x`./build-old/test_crasher` = x
test -z "`ls /tmp/core* 2>/dev/null`"

# packed executables that call papaw_hide_exe() run from RAM have an empty
# executable
./build-old/test_sleeper &
pid=$!
test -z "`grep test_sleeper /proc/$pid/maps`"
test ! -s /proc/$pid/exe

# packed executables should not exit if traced but allow_ptrace=true
meson configure build-old -Dallow_ptrace=true
ninja -C build-old
test x`./build-old/test_putser` = xhello

# packed executables should generate coredumps if allow_coredumps=true
meson configure build-old -Dallow_coredumps=true
ninja -C build-old
test x`./build-old/test_crasher` = x
test -n "`ls /tmp/core*`"

# the payload should be extracted to dir_prefix
here=`pwd`
meson configure build-old -Ddir_prefix=$here
ninja -C build-old
test -n "`strace -qqe mkdir ./build-old/test_putser 2>&1 | grep $here`"

# make sure there are no file descriptor leaks
valgrind -q --leak-check=full --error-exitcode=1 --malloc-fill=1 --free-fill=1 --track-fds=yes ./build-old/test_putser

# build with clang 8 and ASan
CC=clang-8 meson build-clang -Db_sanitize=address
ninja -C build-clang
./build-clang/test_putser

# build with the latest version of Meson
. /opt/meson/bin/activate
meson build-latest
ninja -C build-latest
