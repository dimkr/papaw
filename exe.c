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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <stdbool.h>
#ifndef PAPAW_SHARED_LIBRARY
#   include <papaw.h>
#endif

#ifdef PAPAW_SHARED_LIBRARY
static
#endif
void papaw_hide_exe(void)
{
    static char buf[192], path[128];
    const char *self, *selfbase = NULL, *pathbase;
    void *copy;
    FILE *fp;
    unsigned long start, end;
    size_t len;
    uid_t uid;
    int prot;
    char r, w, x, p;
    bool found = false, remapped = true;

    self = getenv("    ");
    if (!self)
        return;

    /* try only once */
    unsetenv("    ");

    /*
     * when the tmpfs is unmounted, /proc/self/exe points to /x for /tmp/x, so
     * we compare only the file name when we look for mapped regions of the
     * executable
     */
    uid = geteuid();
    if (uid == 0) {
        selfbase = strrchr(self, '/');
        if (!selfbase)
            return;
        ++selfbase;
    }

    fp = fopen("/proc/self/maps", "r");
    if (!fp)
        return;

    while (fgets(buf, sizeof(buf), fp)) {
        if ((sscanf(buf,
                    "%lx-%lx %c%c%c%c %*x %*x:%*x %*u %128s",
                    &start, &end,
                    &r, &w, &x, &p,
                    path) != 7) ||
            (p != 'p'))
            continue;

        if (uid == 0) {
            pathbase = strrchr(path, '/');
            if (!pathbase)
                continue;

            ++pathbase;
            if (strcmp(pathbase, selfbase))
                continue;
        }
        else {
            /* if non-root, /proc/self/exe does not change */
            if (strcmp(path, self))
                continue;
        }

        found = true;

        len = (size_t)(end - start);

        prot = PROT_WRITE;
        if (r == 'r')
            prot |= PROT_READ;
        if (x == 'x')
            prot |= PROT_EXEC;

        /* allocate a memory region */
        copy = mmap(NULL, len, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (copy == MAP_FAILED) {
            remapped = false;
            continue;
        }

        memcpy(copy, (void *)start, len);

        /*
         * if the original memory region is read-only, make the copy read-only
         * once we're done writing to it
         */
        if (w != 'w') {
            prot &= ~PROT_WRITE;
            if (mprotect(copy, len, prot) < 0) {
                munmap(copy, len);
                remapped = false;
                continue;
            }
        }

        /* replace the original memory region with the copy */
        if (mremap(copy,
                   len,
                   len,
                   MREMAP_FIXED | MREMAP_MAYMOVE,
                   (void *)start) != (void *)start) {
            munmap(copy, len);
            remapped = false;
        }

        /*
         * ask the kernel not to swap out the copy, so it cannot be read from
         * disk by running the packed executable with very little free RAM
         */
        if (mlock((void *)start, len) < 0) {
            munmap(copy, len);
            remapped = false;
        }
    }

    fclose(fp);

    if (found && remapped)
        truncate("/proc/self/exe", 0);
}

#ifdef PAPAW_SHARED_LIBRARY

__attribute__((constructor))
static void init(void)
{
    papaw_hide_exe();
}

#endif
