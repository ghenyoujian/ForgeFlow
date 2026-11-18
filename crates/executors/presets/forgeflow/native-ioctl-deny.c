/* Project-owned complement to the unchanged official Landlock launcher. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__x86_64__)
#define NATIVE_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define NATIVE_ARCH AUDIT_ARCH_AARCH64
#else
#error Unqualified syscall architecture
#endif
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error Unqualified syscall argument byte order
#endif

static int fail(const char *message) {
  fprintf(stderr, "forgeflow-ioctl-deny: %s: %s\n", message, strerror(errno));
  return 125;
}
static int deny_ioctl(void) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NATIVE_ARCH, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#if defined(__x86_64__)
    /* x32 shares the architecture marker; reject its alternate syscall ABI. */
    BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000U, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 5),
    /* ABI5 also exempts FIONBIO. Node needs it for its existing stdio pipes.
     * Permit that exact request only; high command bits must also be zero. */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FIONBIO, 0, 2),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1]) + 4),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog program = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])), .filter = filter,
  };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return fail("no_new_privs");
  if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) != 0) return fail("seccomp filter");
  return 0;
}
static int ioctl_errno(void) {
  int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
  if (fd < 0) return -1;
  int value = 0;
  errno = 0;
  (void)ioctl(fd, FIONREAD, &value);
  int observed = errno;
  close(fd);
  return observed;
}
int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--check-ioctl") == 0)
    return ioctl_errno() == EPERM ? 0 : fail("inherited ioctl denial missing");
  long abi = syscall(444, NULL, 0, 1);
  if (abi < 3) { errno = ENOTSUP; return fail("Landlock ABI3 required"); }
  if (argc == 2 && strcmp(argv[1], "--probe") == 0) {
    struct rlimit no_core = { .rlim_cur = 0, .rlim_max = 0 };
    if (setrlimit(RLIMIT_CORE, &no_core) != 0) return fail("probe core limit");
    int before = ioctl_errno();
    if (deny_ioctl()) return 125;
    int after = ioctl_errno();
    int permitted = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int nonblocking = 1;
    if (permitted < 0 || ioctl(permitted, FIONBIO, &nonblocking) != 0 || !(fcntl(permitted, F_GETFL) & O_NONBLOCK))
      return fail("documented FIONBIO exemption refused");
    close(permitted);
    pid_t child = fork();
    if (child < 0) return fail("probe fork");
    if (child == 0) { execl("/proc/self/exe", "forgeflow-ioctl-deny", "--check-ioctl", NULL); _exit(125); }
    int status = 0;
    if (waitpid(child, &status, 0) != child) return fail("probe wait");
    if (after != EPERM || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      errno = EPERM; return fail("actual ioctl or descendant probe failed");
    }
#if defined(__x86_64__)
    child = fork();
    if (child < 0) return fail("compat probe fork");
    if (child == 0) { (void)syscall(0x40000000U | __NR_ioctl, -1, FIONREAD, NULL); _exit(0); }
    if (waitpid(child, &status, 0) != child || !WIFSIGNALED(status) || WTERMSIG(status) != SIGSYS) {
      errno = EPERM; return fail("compat syscall escaped architecture filter");
    }
#endif
    printf("{\"schema_version\":\"forgeflow.native-ioctl-guard.v1\",\"landlock_abi\":%ld,\"ioctl_before_errno\":%d,\"ioctl_after_errno\":%d,\"child_exec_ioctl_denied\":true,\"allowed_fionbio\":true,\"no_new_privs\":true,\"architecture\":\"native-only\",\"compat_syscalls\":\"KILL_PROCESS\",\"x32_probe_killed\":%s}\n", abi, before, after,
#if defined(__x86_64__)
      "true"
#else
      "null"
#endif
    );
    return 0;
  }
  if (argc < 3 || strcmp(argv[1], "--") != 0) { errno = EINVAL; return fail("expected -- exact argv"); }
  if (deny_ioctl()) return 125;
  execvp(argv[2], argv + 2);
  return fail("exec");
}
