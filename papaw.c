/*
 * This file is part of papaw.
 *
 * Copyright (c) 2019 Dima Krasner
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
#include <elf.h>
#include <inttypes.h>
#include <sys/mount.h>
#include <limits.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <errno.h>

#define MINIZ_NO_ARCHIVE_APIS
#define MINIZ_NO_ZLIB_APIS
#include "miniz/miniz.c"

#define XZ_EXTERN static
#include "xz-embedded/linux/lib/xz/xz_dec_lzma2.c"
#include "xz-embedded/linux/lib/xz/xz_dec_stream.c"

#define DIR_TEMPLATE PAPAW_PREFIX".XXXXXX"

static uint32_t xz_crc32(const uint8_t *buf, size_t size, uint32_t crc)
{
    return (uint32_t)mz_crc32((mz_ulong)crc, buf, size);
}

static bool extract(const char *path,
                    const uint32_t clen,
                    const unsigned char *data,
                    const uint32_t olen)
{
    struct xz_buf xzbuf;
    unsigned char *buf, *p;
    struct xz_dec *xz;
    ssize_t now;
    uint32_t rem;
    int out;

    buf = malloc(olen);
    if (!buf)
        return false;

    xzbuf.in = data;
    xzbuf.in_pos = 0;
    xzbuf.in_size = clen;
    xzbuf.out = buf;
    xzbuf.out_pos = 0;
    xzbuf.out_size = olen;

    xz = xz_dec_init(XZ_SINGLE, 0);
    if (!xz) {
        free(buf);
        return false;
    }

    if ((xz_dec_run(xz, &xzbuf) != XZ_STREAM_END) || (xzbuf.out_size != olen)) {
        xz_dec_end(xz);
        free(buf);
        return false;
    }

    xz_dec_end(xz);

    out = open(path, O_CREAT | O_RDWR, 0755);
    if (out < 0) {
        free(buf);
        return false;
    }

    p = xzbuf.out;
    rem = xzbuf.out_size;
    do {
        now = write(out, p, rem);
        if (now < 0) {
            close(out);
            unlink(path);
            free(buf);
            return false;
        }

        p += now;
        rem -= now;
    } while (rem > 0);

    close(out);
    free(buf);
    return true;
}

static bool start_unmounter(const char *dir, const char *path)
{
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 0};
    sigset_t set, oset;
    ssize_t out;
    int pfds[2], status;
    pid_t pid, reaped;

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

    /* daemonize the child */
    if (pid == 0) {
        close(pfds[1]);

        if (setsid() < 0)
            _exit(EXIT_FAILURE);

        pid = fork();
        if (pid < 0)
            _exit(EXIT_FAILURE);
        else if (pid > 0)
            _exit(EXIT_SUCCESS);

        /* wait until the parent calls execv() or exits */
        out = read(pfds[0], &status, sizeof(status));

        /* lazily unmount the tmpfs */
        if (umount2(dir, MNT_DETACH) == 0)
            rmdir(dir);

        if (out < 0)
            _exit(EXIT_FAILURE);

        _exit(EXIT_SUCCESS);

        /* init will reap the daemonized child */
    }

    close(pfds[0]);

    /* reap the child */
    reaped = waitpid(pid, &status, 0);
    if (((reaped < 0) && (errno != ECHILD)) ||
        (reaped != pid) ||
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

struct foot {
    uint32_t olen;
    uint32_t clen;
} __attribute__((packed));

int main(int argc, char *argv[])
{
    struct stat stbuf;
    static char exe[PATH_MAX],
                dir[] = DIR_TEMPLATE,
                path[sizeof(dir) + 1 + NAME_MAX];
    int self;
    void *p;
    struct foot *lens;
    size_t off;
    ssize_t out;
    uint32_t clen, olen;
    bool ok;
    const char *prog;

    /* store the packed executable path in an environment variable */
    out = readlink("/proc/self/exe", exe, sizeof(exe));
    if ((out <= 0) || (out >= sizeof(exe)))
        return EXIT_FAILURE;
    exe[out] = '\0';

    if (setenv("   ", exe, 1) < 0)
        return EXIT_FAILURE;

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
        (clen > SSIZE_MAX) ||
        (olen > SSIZE_MAX)) {
        munmap(p, (size_t)stbuf.st_size);
        close(self);
        return EXIT_FAILURE;
    }

    /* create a directory */
    if (!mkdtemp(dir)) {
        munmap(p, (size_t)stbuf.st_size);
        close(self);
        return EXIT_FAILURE;
    }

    /* mount a tmpfs on it */
    if (mount(NULL,
              dir,
              "tmpfs",
              MS_NOATIME | MS_NODIRATIME | MS_NODEV,
              NULL) < 0) {
        unlink(dir);
        munmap(p, (size_t)stbuf.st_size);
        close(self);
        return EXIT_FAILURE;
    }

    prog = strrchr(argv[0], '/');
    if (prog)
        ++prog;
    else
        prog = argv[0];

    memcpy(path, dir, sizeof(dir) - 1);
    path[sizeof(dir) - 1] = '/';
    strncpy(path + sizeof(dir), prog, sizeof(path) - sizeof(dir));
    path[sizeof(path) - 1] = '\0';

    /* decompress and extract the executable to the tmpfs */
    ok = extract(path, clen, p + off - clen, olen);

    munmap(p, (size_t)stbuf.st_size);
    close(self);

    if (!ok) {
        if (umount2(dir, MNT_DETACH) == 0)
            rmdir(dir);
        return EXIT_FAILURE;
    }

    /* spawn a process that will lazily unmount the tmpfs after execv() */
    if (!start_unmounter(dir, path)) {
        unlink(path);
        if (umount2(dir, MNT_DETACH) == 0)
            rmdir(dir);
        return EXIT_FAILURE;
    }

    execv(path, argv);

    return EXIT_FAILURE;
}
