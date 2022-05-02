# This file is part of papaw.
#
# Copyright (c) 2020, 2021, 2022 Dima Krasner
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

FROM ghcr.io/dimkr/containers/c-dev:clang

RUN apt-get -qq update && apt-get -y install binwalk
RUN for i in x86_64-any64-linux-musl aarch64-any64-linux-musl arm-any32-linux-musleabi armeb-any32-linux-musleabi mips-any32-linux-musl mipsel-any32-linux-musl i386-any32-linux-musl; do wget -qO- https://github.com/dimkr/toolchains/releases/latest/download/$i.tar.gz | tar -xzf - -C /; done
