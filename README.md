```
 _ __   __ _ _ __   __ ___      __
| '_ \ / _` | '_ \ / _` \ \ /\ / /
| |_) | (_| | |_) | (_| |\ V  V /
| .__/ \__,_| .__/ \__,_| \_/\_/
|_|         |_|
```

## Overview

papaw is a permissively-licensed packer for executables which contain statically linked, third-party components of various licenses and run on various devices, with limited disk space.

papaw reduces the size of executables and makes executables capable of replacing themselves on disk, while optionally providing very basic anti-debugging protection to discourage those attempting some trivial reverse-engineering techniques.

It is designed to be portable across different devices, therefore it avoids machine-specific assembly and the use of fexecve() or other, newer system calls which could be used to simplify it.

## Implementation

papaw consists of a small executable (~15-20K) containing [XZ Embedded](https://tukaani.org/xz/embedded.html). It extracts a LZMA2-compressed executable appended to it by the papawify script.

The payload executable is extracted to a temporary file that is deleted once it starts running. When running as root, this is done by mounting a tmpfs file system and lazily unmounting it.

## Usage

papaw uses [Meson](http://mesonbuild.com/) as its build system. To pack an executable using papaw, build papaw, then use papawify to pack the executable.

papaw can be used as a Meson subproject; in that case, custom_target() is the recommended way to run papawify.

## Legal Information

papaw is free and unencumbered software released under the terms of the MIT license; see COPYING for the license text.

The ASCII art logo at the top was made using [FIGlet](http://www.figlet.org/).
