/*
 * This file is part of papaw.
 *
 * Copyright (c) 2019, 2020 Dima Krasner
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <sys/mount.h>
#include <limits.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <errno.h>
#ifndef PAPAW_ALLOW_COREDUMPS
#   include <sys/resource.h>
#endif
#ifndef PAPAW_ALLOW_PTRACE
#   include <sys/ptrace.h>
#endif

#ifdef PAPAW_XZ
#   define MINIZ_NO_ARCHIVE_APIS
#   define MINIZ_NO_ZLIB_APIS
#   include "miniz/miniz.c"

#   define XZ_EXTERN static

#   include "xz-embedded/userspace/xz_config.h"
static void *xalloc(size_t);
static void xfree(void *);
#   undef kmalloc
#   define kmalloc(size, flags) xalloc(size)
#   undef kfree
#   define kfree xfree
#   undef vmalloc
#   define vmalloc xalloc
#   undef vfree
#   define vfree xfree

#   include "xz-embedded/linux/lib/xz/xz_dec_lzma2.c"
#   include "xz-embedded/linux/lib/xz/xz_dec_stream.c"
#elif defined(PAPAW_LZMA)
#   include "lzma/C/LzmaDec.c"
#   define LZMA_HEADER_SIZE LZMA_PROPS_SIZE + 8
#elif defined(PAPAW_ZSTD)
#   include "zstddeclib.h"
#endif

#ifdef PAPAW_XZ

static uint32_t xz_crc32(const uint8_t *buf, size_t size, uint32_t crc)
{
    return (uint32_t)mz_crc32((mz_ulong)crc, buf, size);
}

#endif

#if defined(PAPAW_LZMA) || defined(PAPAW_XZ)

#   ifdef PAPAW_XZ
static void *xalloc(size_t size)
#   else
static void *xalloc(const ISzAlloc *p, size_t size)
#   endif
{
    unsigned char *ptr;

    if (size > SIZE_MAX - sizeof(size_t))
        return NULL;

    ptr = mmap(NULL,
               size + sizeof(size_t),
               PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS,
               -1,
               0);
    if (ptr == MAP_FAILED)
        return NULL;

    *(size_t *)ptr = size;

    return ptr + sizeof(size_t);
}

#   ifdef PAPAW_XZ
static void xfree(void *address)
#   else
static void xfree(const ISzAlloc *p, void *address)
#   endif
{
    unsigned char *ptr;

    if (address != NULL) {
        ptr = (unsigned char *)address - sizeof(size_t);
        munmap(ptr, *(size_t *)ptr + sizeof(size_t));
    }
}

#endif

static bool extract(const int out,
                    const uint32_t clen,
                    const unsigned char *data,
                    const uint32_t olen)
{
#ifdef PAPAW_XZ
    struct xz_buf xzbuf;
    struct xz_dec *xz;
#elif defined(PAPAW_LZMA)
    SizeT inlen = clen - LZMA_HEADER_SIZE, outlen = olen;
    unsigned char *p;
    ELzmaStatus status;
    const ISzAlloc alloc = {xalloc, xfree};
#elif defined(PAPAW_ZSTD)
    unsigned char *p;
#endif
    void *map;

    if (ftruncate(out, (off_t)olen) < 0)
        return false;

#if defined(PAPAW_XZ) || defined(PAPAW_LZMA) || defined(PAPAW_ZSTD)
    if (clen != olen)
        goto decompress;
#endif

    map = mmap(NULL, (size_t)olen, PROT_WRITE, MAP_SHARED, out, 0);
    if (map == MAP_FAILED) {
        return false;
    }

    memcpy(map, data, clen);
    munmap(map, (size_t)olen);
    return true;

#ifdef PAPAW_XZ
decompress:
    xzbuf.out = mmap(NULL, (size_t)olen, PROT_WRITE, MAP_SHARED, out, 0);
    if (xzbuf.out == MAP_FAILED)
        return false;

    xzbuf.in = data;
    xzbuf.in_pos = 0;
    xzbuf.in_size = clen;
    xzbuf.out_pos = 0;
    xzbuf.out_size = olen;

    xz = xz_dec_init(XZ_SINGLE, 0);
    if (!xz) {
        munmap(xzbuf.out, (size_t)olen);
        return false;
    }

    if ((xz_dec_run(xz, &xzbuf) != XZ_STREAM_END) || (xzbuf.out_size != olen)) {
        xz_dec_end(xz);
        munmap(xzbuf.out, (size_t)olen);
        return false;
    }

    xz_dec_end(xz);
    munmap(xzbuf.out, (size_t)olen);

    return true;
#elif defined(PAPAW_LZMA)
decompress:
    if (clen < LZMA_HEADER_SIZE)
        return false;

    p = mmap(NULL, (size_t)olen, PROT_WRITE, MAP_SHARED, out, 0);
    if (p == MAP_FAILED)
        return false;

    if ((LzmaDecode(p,
                    &outlen,
                    data + LZMA_HEADER_SIZE,
                    &inlen,
                    data,
                    LZMA_PROPS_SIZE,
                    LZMA_FINISH_ANY,
                    &status,
                    &alloc) != SZ_OK) ||
        (outlen != olen)) {
        munmap(p, (size_t)olen);
        return false;
    }

    munmap(p, (size_t)olen);
    return true;
#elif defined(PAPAW_ZSTD)
decompress:
    p = mmap(NULL, (size_t)olen, PROT_WRITE, MAP_SHARED, out, 0);
    if (p == MAP_FAILED)
        return false;

    if (ZSTD_isError(ZSTD_decompress(p,
                                     (size_t)olen,
                                     data,
                                     (size_t)clen))) {
        munmap(p, (size_t)olen);
        return false;
    }

    munmap(p, (size_t)olen);
    return true;
#endif
}

static bool start_child(const char *dir, const char *path, const uid_t uid)
{
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 0};
    sigset_t set, oset;
    ssize_t out;
    int pfds[2], status;
    pid_t pid, reaped;
#ifndef PAPAW_ALLOW_PTRACE
    pid_t ppid = -1;
#endif

    /*
     * we don't need the child if we have no directory to delete and don't need
     * to call ptrace()
     */
#ifdef PAPAW_ALLOW_PTRACE
    if (uid == 0)
        return true;
#endif

    /* block SIGCHLD */
    if ((sigemptyset(&set) < 0) ||
        (sigaddset(&set, SIGCHLD) < 0) ||
        (sigprocmask(SIG_BLOCK, &set, &oset) < 0))
        return false;

    /* create a pipe and set O_CLOEXEC on the write end */
    if (pipe(pfds) < 0)
        return false;

    if (fcntl(pfds[1], F_SETFD, FD_CLOEXEC) < 0) {
        return false;
    }

    /* inherit the read end to a child process */
    pid = fork();
    if (pid < 0) {
        close(pfds[1]);
        close(pfds[0]);
        return false;
    }

    if (pid == 0) {
        close(pfds[1]);

#ifndef PAPAW_ALLOW_PTRACE
        if (uid == 0) {
            ppid = getppid();

            /*
             * make sure no debugger is attached to the parent during the
             * writing and the execution of the the payload; if we can't attach,
             * the parent won't write the payload
             */
            if ((ptrace(PTRACE_ATTACH, ppid) < 0) && (errno == EPERM))
                _exit(EXIT_FAILURE);

            /* resume the parent */
            if (kill(ppid, SIGCONT) < 0)
                _exit(EXIT_FAILURE);
        }
#endif

        /* daemonize the child */
        if (setsid() < 0)
            _exit(EXIT_FAILURE);

        pid = fork();
        if (pid < 0)
            _exit(EXIT_FAILURE);
        else if (pid > 0)
            _exit(EXIT_SUCCESS);

        /* wait until the parent calls execv() or exits */
        out = read(pfds[0], &status, sizeof(status));

        if (uid == 0) {
#ifndef PAPAW_ALLOW_PTRACE
            ptrace(PTRACE_DETACH, ppid);
#endif
        }
        else {
            if (unlink(path) == 0)
                rmdir(dir);
        }

        if (out < 0)
            _exit(EXIT_FAILURE);

        _exit(EXIT_SUCCESS);

        /* init will reap the daemonized child */
    }

    close(pfds[0]);

    /* reap the child */
    reaped = waitpid(pid, &status, 0);
    if (reaped < 0) {
        if (errno != ECHILD) {
            close(pfds[1]);
            return false;
        }
    } else if ((reaped != pid) ||
               !WIFEXITED(status) ||
               (WEXITSTATUS(status) != EXIT_SUCCESS)) {
        close(pfds[1]);
        return false;
    }

    /* unqueue the SIGCHLD signal */
    do {
        if (sigtimedwait(&set, NULL, &ts) < 0) {
            if (errno == EAGAIN)
                break;

            return false;
        }
    } while (1);

    /* unblock SIGCHLD */
    if (sigprocmask(SIG_SETMASK, &oset, NULL) < 0)
        return false;

    return true;
}

static char *itoa(char *s, int i)
{
    if (i > 10)
        s = itoa(s, i / 10);
    else
        s[1] = '\0';

    *s = '0' + i % 10;
    return s + 1;
}

struct foot {
    uint32_t olen;
    uint32_t clen;
} __attribute__((packed));

int main(int argc, char *argv[])
{
    struct stat stbuf;
    static char exe[PATH_MAX],
                dir[sizeof(PAPAW_PREFIX"/.2147483647")],
                path[sizeof(dir) + 1 + NAME_MAX];
#ifndef PAPAW_ALLOW_COREDUMPS
    struct rlimit lim;
#endif
    int self, wr, r = -1;
    void *p;
    struct foot *lens;
    size_t off;
    ssize_t out;
    size_t len;
    uint32_t clen, olen;
    bool ok;
    const char *prog;
    uid_t uid;

#ifndef PAPAW_ALLOW_COREDUMPS
    /*
     * disable generation of coredumps: it's easy to intentionally corrupt the
     * payload of a packed executable to trigger a segfault, then extract the
     * decompressed executable from the coredump; the payload can re-enable
     * coredumps if desired
     */
    if (getrlimit(RLIMIT_CORE, &lim) < 0)
        return false;

    lim.rlim_cur = 0;
    if (setrlimit(RLIMIT_CORE, &lim) < 0)
        return false;
#endif

    /* store the packed executable path in an environment variable */
    out = readlink("/proc/self/exe", exe, sizeof(exe));
    if ((out <= 0) || (out >= sizeof(exe)))
        return EXIT_FAILURE;
    exe[out] = '\0';

    if (setenv("   ", exe, 1) < 0)
        return EXIT_FAILURE;

    /* create a directory */
    memcpy(dir, PAPAW_PREFIX"/.", sizeof(PAPAW_PREFIX"/.") - 1);
    len = itoa(dir + sizeof(PAPAW_PREFIX"/.") - 1, (int)(getpid() % INT_MAX)) - dir;
    if (mkdir(dir, 0700) < 0)
        return EXIT_FAILURE;

    prog = strrchr(argv[0], '/');
    if (prog)
        ++prog;
    else
        prog = argv[0];

    memcpy(path, dir, len);
    path[len] = '/';
    strncpy(path + len + 1, prog, sizeof(path) - len - 1);
    path[sizeof(path) - 1] = '\0';

    if (setenv("    ", path, 1) < 0) {
        rmdir(dir);
        return EXIT_FAILURE;
    }

    uid = geteuid();

    /*
     * spawn a process that will check if a debugger is attached, or delete the
     * executable after execv()
     */
    if (!start_child(dir, path, uid)) {
        rmdir(dir);
        return EXIT_FAILURE;
    }

    /* map the executable to memory */
    self = open(exe, O_RDONLY);
    if (self < 0)
        return EXIT_FAILURE;

    if ((fstat(self, &stbuf) < 0) || (stbuf.st_size <= sizeof(*lens))) {
        close(self);
        return EXIT_FAILURE;
    }

    p = mmap(NULL, (size_t)stbuf.st_size, PROT_READ, MAP_PRIVATE, self, 0);
    if (p == MAP_FAILED) {
        close(self);
        return EXIT_FAILURE;
    }

    /* extract the {de,compressed} size of the payload */
    off = stbuf.st_size - sizeof(*lens);
    lens = (struct foot *)(p + off);
    clen = ntohl(lens->clen);
    olen = ntohl(lens->olen);
    if ((clen >= stbuf.st_size) ||
        (clen > ULONG_MAX) ||
#ifdef PAPAW_LZMA
        (clen <= LZMA_HEADER_SIZE) ||
#else
        (clen == 0) ||
#endif
        (clen > SSIZE_MAX) ||
        (olen == 0) ||
        (olen > SSIZE_MAX)) {
        munmap(p, (size_t)stbuf.st_size);
        close(self);
        return EXIT_FAILURE;
    }

    /* mount a tmpfs on it */
    if ((uid == 0) &&
        (mount(NULL,
               dir,
               "tmpfs",
               MS_NOATIME | MS_NODIRATIME | MS_NODEV,
               NULL) < 0)) {
        rmdir(dir);
        munmap(p, (size_t)stbuf.st_size);
        close(self);
        return EXIT_FAILURE;
    }

    wr = open(path, O_CREAT | O_RDWR, 0755);
    if (wr < 0) {
        if ((uid != 0) || (umount2(dir, MNT_DETACH) == 0))
            rmdir(dir);
        return EXIT_FAILURE;
    }

    if (uid == 0) {
        /*
         * open the executable for reading: we cannot run it while it's opened
         * for writing, but we need a file descriptor so we can run the
         * executable through /proc/self/fd/%d once we unmount the tmpfs and the
         * path is no longer accessible
         */
        r = open(path, O_RDONLY);
        if (r < 0) {
            close(wr);
            if (umount2(dir, MNT_DETACH) == 0)
                rmdir(dir);
            return EXIT_FAILURE;
        }

        if (fcntl(r, F_SETFD, FD_CLOEXEC) < 0) {
            close(r);
            close(wr);
            if (umount2(dir, MNT_DETACH) == 0)
                rmdir(dir);
            return EXIT_FAILURE;
        }

        /* unmount the file system while keeping the file open */
        if (umount2(dir, MNT_DETACH) < 0) {
            close(r);
            close(wr);
            return EXIT_FAILURE;
        }

        rmdir(dir);
    }

    /* decompress and extract the executable to the file */
    ok = extract(wr, clen, p + off - clen, olen);

    munmap(p, (size_t)stbuf.st_size);
    close(self);
    close(wr);

    if (!ok) {
        if (uid == 0)
            close(r);
        else if (unlink(path) == 0)
            rmdir(dir);
        return EXIT_FAILURE;
    }

    if (uid == 0) {
        memcpy(path, "/proc/self/fd/", sizeof("/proc/self/fd/") - 1);
        itoa(path + sizeof("/proc/self/fd/") - 1, r);
    }

    execv(path, argv);

    return EXIT_FAILURE;
}
