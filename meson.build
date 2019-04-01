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

project('papaw', 'c', version: '0.1', license: 'MIT')

cflags = ['-Os', '-fomit-frame-pointer', '-ffunction-sections', '-fdata-sections', '-fmerge-all-constants']
ldflags = ['-Wl,--gc-sections', '-Wl,--sort-common', '-Wl,-s']

if meson.get_compiler('c').has_argument('-Wno-tautological-constant-out-of-range-compare')
    cflags += ['-Wno-tautological-constant-out-of-range-compare']
endif

config_cflags = [
    '-DPAPAW_PREFIX="@0@"'.format(get_option('dir_prefix'))
]

if get_option('allow_coredumps')
    config_cflags += ['-DPAPAW_ALLOW_COREDUMPS']
endif

if get_option('allow_ptrace')
    config_cflags += ['-DPAPAW_ALLOW_PTRACE']
endif

papaw = executable('papaw',
                   'papaw.c',
                   include_directories: [include_directories('xz-embedded/userspace'), include_directories('xz-embedded/linux/include/linux')],
                   c_args: cflags + ['-fvisibility=hidden', '-Wno-unused-function'] + config_cflags,
                   link_args: ldflags)

papaw_includes = include_directories('.')

libpapaw = static_library('papaw',
                          'exe.c',
                          include_directories: papaw_includes,
                          c_args: cflags,
                          install: true)

install_headers('papaw.h')

if get_option('ci')
    libpapaw_so = shared_library('papaw',
                                  'exe.c',
                                  c_args: cflags + ['-DPAPAW_SHARED_LIBRARY'])

    putser = executable('putser',
                        'putser.c',
                        c_args: cflags,
                        link_args: ldflags)

    test_putser = custom_target('test_putser',
                                output : 'test_putser',
                                input : putser,
                                command : [join_paths(meson.source_root(), 'papawify'), papaw, '@INPUT@', '@OUTPUT@'],
                                build_by_default: true,
                                depends: papaw)

    crasher = executable('crasher',
                         'crasher.c',
                         c_args: cflags,
                         link_args: ldflags)

    test_crasher = custom_target('test_crasher',
                                 output : 'test_crasher',
                                 input : crasher,
                                 command : [join_paths(meson.source_root(), 'papawify'), papaw, '@INPUT@', '@OUTPUT@'],
                                 build_by_default: true,
                                 depends: papaw)

    sleeper = executable('sleeper',
                         'sleeper.c',
                         c_args: cflags,
                         link_args: ldflags,
                         link_with: libpapaw)

    test_sleeper = custom_target('test_sleeper',
                                 output : 'test_sleeper',
                                 input : sleeper,
                                 command : [join_paths(meson.source_root(), 'papawify'), papaw, '@INPUT@', '@OUTPUT@'],
                                 build_by_default: true,
                                 depends: papaw)
endif
