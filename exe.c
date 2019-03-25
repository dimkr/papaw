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

#include "papaw.h"

void papaw_hide_exe(void)
{
    static char buf[192];
    const char *path;
    void *copy;
    FILE *fp;
    unsigned long start, end, offset, len;
    int prot;
    char r, w, x, p, slash;
    bool remapped = true;
    unsigned int i;

    path = getenv("   ");
    if (!path)
        return;

    fp = fopen("/proc/self/maps", "r");
    if (!fp)
        return;

    /* assumption: /proc/self/exe has only 3 mappings and they are the first */
    for (i = 0; (i < 3) && fgets(buf, sizeof(buf), fp); ++i) {
        if ((sscanf(buf, "%lx-%lx %c%c%c%c %lx %*x:%*x %*u %c", &start, &end, &r, &w, &x, &p, &offset, &slash) != 8) ||
            (p != 'p') ||
            (slash != '/'))
            continue;

        len = end - start;

        prot = PROT_WRITE;
        if (r == 'r')
            prot |= PROT_READ;
        if (x == 'x')
            prot |= PROT_EXEC;

        /* allocate a memory region */
        copy = mmap(NULL, (size_t)len, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
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
            if (mprotect(copy, (size_t)len, prot) < 0) {
                munmap(copy, (size_t)len);
                remapped = false;
                continue;
            }
        }

        /* replace the original memory region with the copy */
        if (mremap(copy, (size_t)len, (size_t)len, MREMAP_FIXED | MREMAP_MAYMOVE, (void *)start) != (void *)start) {
            munmap(copy, (size_t)len);
            remapped = false;
        }
    }

    fclose(fp);

    if (remapped)
        truncate("/proc/self/exe", 0);
}
