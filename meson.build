# This file is part of papaw.
#
# Copyright (c) 2019, 2020, 2021, 2022 Dima Krasner
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

project('papaw', 'c', version: '0.2', license: 'MIT')

cflags = ['-Os', '-fomit-frame-pointer', '-ffunction-sections', '-fdata-sections', '-fmerge-all-constants', '-DNDEBUG']
ldflags = ['-Wl,--gc-sections', '-Wl,--sort-common', '-Wl,-s']

cc = meson.get_compiler('c')

if cc.has_function('mprotect')
    cflags += ['-DHAVE_MPROTECT']
endif

if cc.has_function('mlock')
    cflags += ['-DHAVE_MLOCK']
endif

if cc.has_function('truncate')
    cflags += ['-DHAVE_TRUNCATE']
endif

if cc.has_function('prctl') and cc.has_header_symbol('sys/prctl.h', 'PR_SET_NAME')
    cflags += ['-DHAVE_PRCTL']
endif

if cc.has_argument('-Wno-tautological-constant-out-of-range-compare')
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

cfg = configuration_data()

compression_sources = []
compression_cflags = ['-DPAPAW_XZ']
compression_includes = [include_directories('xz-embedded/userspace'), include_directories('xz-embedded/linux/include/linux')]
cfg.set('COMPRESSION_CMD', '"xz", "-c", "--check=none", "--lzma2=preset=9e,dict=512KiB"')
cfg.set('OBFUSCATION', 'obfuscated = b"\\0\\0\\0\\x08\\0" + compressed[5:-2] + b"\\0\\0"')
cfg.set('DEOBFUSCATION', 'deobfuscated = b"\\3757zXZ" + obfuscated[5:-2] + b"YZ"')
cfg.set('DECOMPRESSION_CMD', '"xz", "-d"')

compression = get_option('compression')
if compression == 'lzma'
    compression_cflags = ['-DPAPAW_LZMA']
    compression_includes = []
    cfg.set('COMPRESSION_CMD', '"xz", "-c", "--format=lzma", "--lzma1=preset=9e,dict=512KiB"')
    cfg.set('OBFUSCATION', 'compressed[:5] + b"\\x08" + compressed[5:]')
    cfg.set('DEOBFUSCATION', 'deobfuscated = obfuscated[:5] + obfuscated[6:]')
elif compression == 'minlzma'
    compression_cflags = ['-DPAPAW_MINLZMA']
elif compression == 'zstd'
    compression_cflags = ['-DPAPAW_ZSTD']
    compression_includes = []
    compression_sources += [
        custom_target('zstddeclib_obfuscated',
                      input: custom_target('zstddeclib',
                                           input: 'zstd/build/single_file_libs/zstddeclib-in.c',
                                           output: 'zstddeclib.h',
                                           command: [
                                               join_paths(meson.current_source_dir(), 'zstd/build/single_file_libs/combine.sh'),
                                               '-r',
                                               join_paths(meson.current_source_dir(), 'zstd/lib'),
                                               '-r',
                                               join_paths(meson.current_source_dir(), 'zstd/lib/common'),
                                               '-r',
                                               join_paths(meson.current_source_dir(), 'zstd/lib/decompress'),
                                               '-o',
                                               '@OUTPUT@',
                                               '@INPUT@'
                                           ]),
                      output: 'zstddeclib_obfuscated.h',
                      command: ['sed', 's/0xFD2FB528/0x00000008/', '@INPUT@'],
                      capture: true)
    ]
    cfg.set('COMPRESSION_CMD', '"zstd", "-q", "-c", "-19", "--no-check"')
    cfg.set('OBFUSCATION', 'obfuscated = b"\\x08\\0\\0\\x00" + compressed[4:]')
    cfg.set('DEOBFUSCATION', 'deobfuscated = b"\\x28\\xb5\\x2f\\xfd" + obfuscated[4:]')
    cfg.set('DECOMPRESSION_CMD', '"zstd", "-d"')
elif compression == 'deflate'
    compression_cflags = ['-DPAPAW_DEFLATE']
    compression_includes = []
    cfg.set('COMPRESSION_CMD', '"python3", "-c", "import sys, zlib; o = zlib.compressobj(9, zlib.DEFLATED, -15, 9, zlib.Z_DEFAULT_STRATEGY); sys.stdout.buffer.write(o.compress(open(sys.argv[1], \'rb\').read())); sys.stdout.buffer.write(o.flush())"')
    cfg.set('OBFUSCATION', 'compressed')
    cfg.set('DEOBFUSCATION', 'deobfuscated = obfuscated')
    cfg.set('DECOMPRESSION_CMD', '"python3", "-c", "import sys, zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read(), -15))"')
endif

papaw = executable('papaw',
                   ['papaw.c'] + compression_sources,
                   include_directories: compression_includes,
                   c_args: cflags + ['-fvisibility=hidden'] + compression_cflags + config_cflags,
                   link_args: ldflags)

papawu = executable('papawu',
                    'papaw.c',
                    c_args: cflags + config_cflags,
                    link_args: ldflags)

papaw_includes = include_directories('.')

libpapaw = static_library('papaw',
                          'exe.c',
                          include_directories: papaw_includes,
                          c_args: cflags + ['-D_GNU_SOURCE'],
                          install: true)

papaw_dependency = declare_dependency(include_directories: papaw_includes,
                                      link_with: libpapaw)
install_headers('papaw.h')

papawify = configure_file(input: 'papawify.in',
                          output: 'papawify',
                          configuration: cfg)

unpapawify = configure_file(input: 'unpapawify.in',
                            output: 'unpapawify',
                            configuration: cfg)

if get_option('ci')
    libpapaw_so = shared_library('papaw',
                                 'exe.c',
                                 c_args: cflags + ['-D_GNU_SOURCE', '-DPAPAW_SHARED_LIBRARY'])

    putser = executable('putser',
                        'ci/putser.c',
                        c_args: cflags,
                        link_args: ldflags)

    test_putser = custom_target('test_putser',
                                output : 'test_putser',
                                input : putser,
                                command : ['python3', papawify, papaw, '@INPUT@', '@OUTPUT@'],
                                build_by_default: true,
                                depends: papaw)

    test_uncompressed = custom_target('test_uncompressed',
                                      output : 'test_uncompressed',
                                      input : putser,
                                      command : ['python3', papawify, '-u', papawu, '@INPUT@', '@OUTPUT@'],
                                      build_by_default: true,
                                      depends: papawu)

    crasher = executable('crasher',
                         'ci/crasher.c',
                         c_args: cflags,
                         link_args: ldflags)

    test_crasher = custom_target('test_crasher',
                                 output : 'test_crasher',
                                 input : crasher,
                                 command : ['python3', papawify, papaw, '@INPUT@', '@OUTPUT@'],
                                 build_by_default: true,
                                 depends: papaw)

    sleeper = executable('sleeper',
                         'ci/sleeper.c',
                         c_args: cflags,
                         link_args: ldflags,
                         link_with: libpapaw)

    test_sleeper = custom_target('test_sleeper',
                                 output : 'test_sleeper',
                                 input : sleeper,
                                 command : ['python3', papawify, papaw, '@INPUT@', '@OUTPUT@'],
                                 build_by_default: true,
                                 depends: papaw)
endif
