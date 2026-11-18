#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Private QA only: halt before the real receipt rename, after runtime fsync.
 * Never alter, remove, publish or manufacture an execution receipt. */
int rename(const char *old_path, const char *new_path) {
    int (*real_rename)(const char *, const char *) = dlsym(RTLD_NEXT, "rename");
    const char *root = getenv("FORGEFLOW_QA_RECEIPT_ROOT");
    const char *marker = getenv("FORGEFLOW_QA_RECEIPT_MARKER");
    const char *base = strrchr(new_path, '/');
    if (root && marker && base && !strcmp(base + 1, "launch-receipt.json") &&
        !strncmp(new_path, root, strlen(root)) && new_path[strlen(root)] == '/') {
        int fd = open(marker, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) _exit(121);
        if (dprintf(fd, "%ld\n%s\n%s\n", (long)getpid(), old_path, new_path) < 0 || fsync(fd)) _exit(122);
        close(fd);
        raise(SIGSTOP);
        /* A resume must not accidentally publish the receipt under test. */
        for (;;) pause();
    }
    if (!real_rename) { errno = ENOSYS; return -1; }
    return real_rename(old_path, new_path);
}
