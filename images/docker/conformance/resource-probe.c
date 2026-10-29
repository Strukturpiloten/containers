/* Repository-owned, bounded probes. No network, unbounded allocation or fork loop. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/magic.h>
#include <linux/nsfs.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

static pid_t children[64];
static volatile sig_atomic_t child_count;
static volatile sig_atomic_t cancelled;

/* Read-only PID namespace ancestry, never namespace entry or namespace creation. */
static int pid_ancestry(const char *target, const char *ancestor) {
    const char *ids[] = {target, ancestor};
    int descriptors[2] = {-1, -1};
    struct stat expected, current;
    char path[64], output[1024];
    size_t used = 0;
    int result = 11;
    const char *stage = "arguments";
    for (int n = 0; n < 2; ++n) {
        char *end;
        errno = 0;
        long pid = strtol(ids[n], &end, 10);
        if (errno || !*ids[n] || *end || pid <= 0 || pid > INT_MAX) goto done;
        for (const char *digit = ids[n]; *digit; ++digit) if (!isdigit((unsigned char)*digit)) goto done;
        snprintf(path, sizeof(path), "/proc/%ld/ns/pid", pid);
        stage = "open-namespace";
        descriptors[n] = open(path, O_RDONLY | O_CLOEXEC);
        if (descriptors[n] < 0) goto done;
    }
    stage = "ancestor-stat";
    if (fstat(descriptors[1], &expected) != 0) goto done;
    for (int depth = 0; depth < 32; ++depth) {
        struct statfs filesystem;
        stage = "namespace-stat-or-type";
        if (fstat(descriptors[0], &current) != 0 ||
            fstatfs(descriptors[0], &filesystem) != 0 || filesystem.f_type != NSFS_MAGIC) goto done;
        int count = snprintf(output + used, sizeof(output) - used, "%spid:[%llu]",
                             used ? " " : "", (unsigned long long)current.st_ino);
        if (count < 0 || (size_t)count >= sizeof(output) - used) goto done;
        used += (size_t)count;
        if (current.st_ino == expected.st_ino && current.st_dev == expected.st_dev) {
            if (depth == 0) { stage = "same-namespace"; errno = 0; goto done; }
            if (printf("%s\n", output) >= 0 && fflush(stdout) == 0) result = 0;
            goto done;
        }
        stage = "NS_GET_PARENT";
        int parent = ioctl(descriptors[0], NS_GET_PARENT);
        if (parent < 0) goto done;
        close(descriptors[0]);
        descriptors[0] = parent;
    }
    stage = "ancestor-not-found-within-bound"; errno = 0;
done:
    if (result != 0) fprintf(stderr, "resource-ancestry: %s failed errno=%d\n", stage, errno);
    for (int n = 0; n < 2; ++n) if (descriptors[n] >= 0) close(descriptors[n]);
    return result;
}

static void cancel_children(int sig) {
    (void)sig;
    cancelled = 1;
    for (sig_atomic_t n = 0; n < child_count; ++n) kill(children[n], SIGTERM);
}

static long pid_events(void) {
    FILE *stream = fopen("/sys/fs/cgroup/pids.events", "r");
    char key[32];
    long value = -1;
    if (!stream) return -1;
    if (fscanf(stream, "%31s %ld", key, &value) != 2 || strcmp(key, "max") != 0) value = -1;
    fclose(stream);
    return value;
}

/* Closed, bounded self-readback. Emitted only after the gate releases. */
static int read_text(const char *path, char *buffer, size_t capacity) {
    FILE *stream = fopen(path, "r");
    if (!stream) { fprintf(stderr, "resource-evidence: open %s failed errno=%d\n", path, errno); return 0; }
    size_t count = fread(buffer, 1, capacity - 1, stream);
    int extra = fgetc(stream);
    int valid = count > 0 && extra == EOF && !ferror(stream) && !memchr(buffer, '\0', count);
    fclose(stream);
    if (!valid) { fprintf(stderr, "resource-evidence: bounded read %s missing or malformed\n", path); return 0; }
    while (count && buffer[count - 1] == '\n') --count;
    buffer[count] = '\0';
    return count > 0;
}

static int status_field(const char *status, const char *key, char *value, size_t capacity) {
    size_t length = strlen(key);
    for (const char *line = status; line && *line; ) {
        const char *end = strchr(line, '\n');
        if (strncmp(line, key, length) == 0) {
            size_t count = end ? (size_t)(end - line - length) : strlen(line + length);
            if (count == 0 || count >= capacity) return 0;
            memcpy(value, line + length, count);
            value[count] = '\0';
            return 1;
        }
        line = end ? end + 1 : NULL;
    }
    fprintf(stderr, "resource-evidence: status field %s missing\n", key);
    return 0;
}

static int append_field(char *output, size_t *used, const char *phase, const char *key, const char *value) {
    if (strchr(value, '\n') || strchr(value, '\r')) return 0;
    int count = snprintf(output + *used, 4096 - *used, "allocator-%s-%s=%s\n", phase, key, value);
    if (count < 0 || (size_t)count >= 4096 - *used) return 0;
    *used += (size_t)count;
    return 1;
}

static int append_link(char *output, size_t *used, const char *phase, const char *key, const char *path) {
    char value[1024];
    ssize_t count = readlink(path, value, sizeof(value) - 1);
    if (count <= 0 || count >= (ssize_t)sizeof(value) - 1) {
        fprintf(stderr, "resource-evidence: bounded link %s failed errno=%d\n", path, errno); return 0;
    }
    value[count] = '\0';
    return append_field(output, used, phase, key, value);
}

static int memory_evidence(const char *phase) {
    char output[4096], value[1024], status[4096], path[128];
    size_t used = 0;
    struct stat scope;
    struct statfs filesystem;
    snprintf(value, sizeof(value), "%ld", (long)getpid());
    if (!append_field(output, &used, phase, "pid", value) ||
        !read_text("/proc/self/status", status, sizeof(status)) ||
        !status_field(status, "Uid:", value, sizeof(value)) ||
        !append_field(output, &used, phase, "uids", value) ||
        !status_field(status, "NSpid:", value, sizeof(value)) ||
        !append_field(output, &used, phase, "nspid", value) ||
        !read_text("/proc/self/stat", value, sizeof(value))) return 0;
    char *close = strrchr(value, ')'), *saved = NULL, *token = NULL;
    if (!close || close[1] != ' ') return 0;
    for (int field = 0; field <= 19; ++field) {
        token = strtok_r(field == 0 ? close + 2 : NULL, " ", &saved);
        if (!token) return 0;
    }
    for (const char *digit = token; *digit; ++digit) if (!isdigit((unsigned char)*digit)) return 0;
    if (!append_field(output, &used, phase, "starttime", token) ||
        !read_text("/proc/self/cgroup", value, sizeof(value)) ||
        !append_field(output, &used, phase, "cgroup", value) ||
        !append_link(output, &used, phase, "exe", "/proc/self/exe") ||
        !append_link(output, &used, phase, "pidns", "/proc/self/ns/pid") ||
        !append_link(output, &used, phase, "cgroupns", "/proc/self/ns/cgroup") ||
        !append_link(output, &used, phase, "userns", "/proc/self/ns/user")) return 0;
    if (stat("/sys/fs/cgroup", &scope) != 0) {
        fprintf(stderr, "resource-evidence: accounting inode read failed errno=%d\n", errno); return 0;
    }
    if (statfs("/sys/fs/cgroup", &filesystem) != 0) {
        fprintf(stderr, "resource-evidence: accounting filesystem read failed errno=%d\n", errno); return 0;
    }
    if (filesystem.f_type != CGROUP2_SUPER_MAGIC) {
        fprintf(stderr, "resource-evidence: accounting filesystem was not cgroup2\n"); return 0;
    }
    snprintf(value, sizeof(value), "%llu", (unsigned long long)scope.st_ino);
    if (!append_field(output, &used, phase, "scope-inode", value)) return 0;
    snprintf(value, sizeof(value), "%lx", (unsigned long)filesystem.f_type);
    if (!append_field(output, &used, phase, "mount-type", value)) return 0;
    const char *files[] = {"memory.max", "memory.current", "memory.swap.max", "memory.swap.current", "memory.events"};
    for (size_t n = 0; n < sizeof(files) / sizeof(files[0]); ++n) {
        snprintf(path, sizeof(path), "/sys/fs/cgroup/%s", files[n]);
        if (!read_text(path, value, sizeof(value))) return 0;
        if (strcmp(files[n], "memory.events") == 0)
            for (char *character = value; *character; ++character) if (*character == '\n') *character = ';';
        if (!append_field(output, &used, phase, files[n], value)) return 0;
    }
    if (!append_field(output, &used, phase, "complete", "yes")) return 0;
    return fwrite(output, 1, used, stdout) == used && fflush(stdout) == 0;
}

/* A stable, child-free gate: no shell/sleep PIDs churn during cgroup snapshots. */
static int wait_for_start(const char *path) {
    struct timespec start, now;
    struct timespec interval = { .tv_sec = 0, .tv_nsec = 100000000 };
    struct stat status;
    if (path[0] != '/' || strlen(path) > 4096 || clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 9;
    for (;;) {
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 9;
        if (now.tv_sec - start.tv_sec > 10 ||
            (now.tv_sec - start.tv_sec == 10 && now.tv_nsec >= start.tv_nsec)) return 9;
        if (stat(path, &status) == 0) return S_ISREG(status.st_mode) ? 0 : 9;
        if (errno != ENOENT) return 9;
        if (nanosleep(&interval, NULL) != 0 && errno != EINTR) return 9;
    }
}

/* Separate, diagnostic-only protocol. One alarm encloses every gate and hold. */
static volatile sig_atomic_t witness_child;
static volatile sig_atomic_t witness_cancelled;
static void witness_cancel(int sig) {
    witness_cancelled = sig;
    if (witness_child > 0) kill((pid_t)witness_child, SIGKILL);
}
static int witness_field(const char *phase, const char *key, const char *value) {
    if (strchr(value, '\r')) return 0;
    char bounded[4096];
    size_t length = strlen(value);
    if (!length || length >= sizeof(bounded)) return 0;
    memcpy(bounded, value, length + 1);
    for (size_t n = 0; n < length; ++n) if (bounded[n] == '\n') bounded[n] = ';';
    return printf("leaf-witness-%s-%s=%s\n", phase, key, bounded) >= 0;
}
static int witness_snapshot(const char *phase, pid_t child, const char *child_stat) {
    char value[4096], path[128];
    struct stat scope;
    struct statfs filesystem;
    if (stat("/sys/fs/cgroup", &scope) != 0 || statfs("/sys/fs/cgroup", &filesystem) != 0 ||
        filesystem.f_type != CGROUP2_SUPER_MAGIC) return 0;
    snprintf(value, sizeof(value), "%llu:%llu", (unsigned long long)scope.st_dev,
        (unsigned long long)scope.st_ino);
    if (!witness_field(phase, "scope-identity", value)) return 0;
    snprintf(value, sizeof(value), "%ld", (long)getpid());
    if (!witness_field(phase, "controller-pid", value) ||
        !read_text("/proc/self/stat", value, sizeof(value)) ||
        !witness_field(phase, "controller-stat", value) ||
        !read_text("/proc/self/cgroup", value, sizeof(value)) ||
        !witness_field(phase, "controller-cgroup", value)) return 0;
    const char *names[] = {"pid", "cgroup", "user"};
    for (size_t n = 0; n < sizeof(names) / sizeof(names[0]); ++n) {
        snprintf(path, sizeof(path), "/proc/self/ns/%s", names[n]);
        ssize_t count = readlink(path, value, sizeof(value) - 1);
        if (count <= 0 || count >= (ssize_t)sizeof(value) - 1) return 0;
        value[count] = '\0';
        char key[32]; snprintf(key, sizeof(key), "controller-%sns", names[n]);
        if (!witness_field(phase, key, value)) return 0;
    }
    snprintf(value, sizeof(value), "%ld", (long)child);
    if (!witness_field(phase, "child-pid", value) || !witness_field(phase, "child-stat", child_stat)) return 0;
    const char *files[] = {"memory.max", "memory.current", "memory.swap.max", "memory.swap.current",
        "memory.events", "memory.events.local", "memory.oom.group", "pids.max"};
    for (size_t n = 0; n < sizeof(files) / sizeof(files[0]); ++n) {
        snprintf(path, sizeof(path), "/sys/fs/cgroup/%s", files[n]);
        if (!read_text(path, value, sizeof(value)) || !witness_field(phase, files[n], value)) return 0;
        if ((strcmp(files[n], "memory.oom.group") == 0 && strcmp(value, "0") != 0) ||
            (strcmp(files[n], "memory.max") == 0 && strcmp(value, "33554432") != 0) ||
            (strcmp(files[n], "memory.swap.max") == 0 && strcmp(value, "0") != 0) ||
            (strcmp(files[n], "pids.max") == 0 && strcmp(value, "16") != 0)) return 0;
    }
    return witness_field(phase, "complete", "yes") && fflush(stdout) == 0;
}
static int witness_gate(const char *path) {
    struct stat status;
    const struct timespec interval = {.tv_sec = 0, .tv_nsec = 10000000};
    while (!witness_cancelled) {
        if (stat(path, &status) == 0) return S_ISREG(status.st_mode);
        if (errno != ENOENT) return 0;
        if (nanosleep(&interval, NULL) != 0 && errno != EINTR) return 0;
    }
    return 0;
}
static int memory_witness(const char *start) {
    if (getpid() != 1) return 12; /* Namespace PID1 death must not orphan an allocator. */
    if (start[0] != '/' || strlen(start) > 4000) return 2;
    char after[4096], finish[4096], child_stat[4096], path[128];
    snprintf(after, sizeof(after), "%s.after", start);
    snprintf(finish, sizeof(finish), "%s.finish", start);
    int pipefd[2], status = 0, result = 12, reaped = 0;
    sigset_t blocked, previous;
    sigemptyset(&blocked); sigaddset(&blocked, SIGTERM); sigaddset(&blocked, SIGINT); sigaddset(&blocked, SIGALRM);
    struct sigaction action; memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (sigaction(SIGCHLD, &action, NULL) != 0) return 12; /* Always own a waitable child. */
    action.sa_handler = witness_cancel; action.sa_mask = blocked;
    if (sigprocmask(SIG_BLOCK, &blocked, &previous) != 0) return 12;
    /* The owned cancellation/alarm handlers must not inherit a blocked delivery mask. */
    sigdelset(&previous, SIGTERM); sigdelset(&previous, SIGINT); sigdelset(&previous, SIGALRM);
    if (sigaction(SIGTERM, &action, NULL) != 0 || sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGALRM, &action, NULL) != 0 || pipe(pipefd) != 0) {
        sigprocmask(SIG_SETMASK, &previous, NULL); return 12;
    }
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        close(pipefd[0]); close(pipefd[1]); sigprocmask(SIG_SETMASK, &previous, NULL); return 12;
    }
    alarm(10);
    pid_t child = fork();
    if (child == 0) {
        close(pipefd[1]);
        signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL); signal(SIGALRM, SIG_DFL); signal(SIGPIPE, SIG_DFL);
        sigprocmask(SIG_SETMASK, &previous, NULL);
        char release;
        if (read(pipefd[0], &release, 1) != 1 || release != 'x') _exit(12);
        close(pipefd[0]);
        volatile unsigned char *blocks[128];
        for (int n = 0; n < 128; ++n) {
            blocks[n] = malloc(1024 * 1024);
            if (!blocks[n]) _exit(3);
            for (int offset = 0; offset < 1024 * 1024; offset += 4096) blocks[n][offset] = 1;
        }
        for (int n = 0; n < 128; ++n) free((void *)blocks[n]);
        _exit(4);
    }
    witness_child = child > 0 ? child : 0;
    sigprocmask(SIG_SETMASK, &previous, NULL);
    close(pipefd[0]);
    if (child < 0) { close(pipefd[1]); return 12; }
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)child);
    if (!read_text(path, child_stat, sizeof(child_stat)) || !witness_gate(start) ||
        !witness_snapshot("before", child, child_stat)) goto done;
    if (write(pipefd[1], "x", 1) != 1) goto done;
    close(pipefd[1]); pipefd[1] = -1;
    while (!reaped) {
        /* Signals cannot observe a stale PID between waitpid and ownership retirement. */
        if (sigprocmask(SIG_BLOCK, &blocked, &previous) != 0) goto done;
        pid_t waited = waitpid(child, &status, WNOHANG);
        int wait_error = errno;
        if (waited == child || (waited < 0 && wait_error == ECHILD)) { witness_child = 0; reaped = 1; }
        sigprocmask(SIG_SETMASK, &previous, NULL);
        if (waited < 0 && wait_error != EINTR) goto done;
        if (!reaped) { const struct timespec interval = {.tv_sec = 0, .tv_nsec = 10000000}; nanosleep(&interval, NULL); }
    }
    if (witness_cancelled) goto done;
    if (!witness_field("result", "child-reaped", "yes")) goto done;
    char termination[32];
    snprintf(termination, sizeof(termination), "%d", WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    if (!witness_field("result", "child-signal", termination) ||
        !witness_field("result", "child-signaled", WIFSIGNALED(status) ? "yes" : "no") ||
        !witness_snapshot("after", child, child_stat)) goto done;
    int ready = open(after, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (ready < 0) goto done;
    close(ready);
    if (witness_gate(finish) && !witness_cancelled) result = 0; /* Observation completion only. */
done:
    if (pipefd[1] >= 0) close(pipefd[1]);
    if (!reaped) {
        sigprocmask(SIG_BLOCK, &blocked, &previous);
        if (witness_child > 0) kill(child, SIGKILL);
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
        witness_child = 0; /* Includes ECHILD: numeric kill authority is retired while blocked. */
        sigprocmask(SIG_SETMASK, &previous, NULL);
    }
    alarm(0);
    return witness_cancelled ? 12 : result;
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "memory-witness") == 0 && strcmp(argv[2], "--wait-for-start") == 0)
        return memory_witness(argv[3]);
    if (argc == 4 && strcmp(argv[1], "--pid-ancestry") == 0) {
        alarm(2);
        return pid_ancestry(argv[2], argv[3]);
    }
    if (argc != 2 && argc != 4 && argc != 5) return 2;
    if (strcmp(argv[1], "memory") != 0 && strcmp(argv[1], "pids") != 0) return 2;
    int evidence = argc == 5;
    if (evidence && (strcmp(argv[1], "memory") != 0 || strcmp(argv[4], "--memory-evidence") != 0)) return 2;
    if (argc >= 4) {
        if (strcmp(argv[2], "--wait-for-start") != 0) return 2;
        int gate = wait_for_start(argv[3]);
        if (gate != 0) return gate;
    }
    alarm(10);
    if (strcmp(argv[1], "memory") == 0) {
        if (evidence && !memory_evidence("before")) return 10;
        volatile unsigned char *blocks[128];
        for (int n = 0; n < 128; ++n) {
            blocks[n] = malloc(1024 * 1024);
            if (!blocks[n]) return 3; /* Allocation refusal is NOT OOM-kill evidence. */
            for (int offset = 0; offset < 1024 * 1024; offset += 4096) blocks[n][offset] = 1;
        }
        if (evidence && !memory_evidence("after")) return 10;
        for (int n = 0; n < 128; ++n) free((void *)blocks[n]);
        return 4; /* Surviving 128 MiB does not demonstrate the strict no-swap/OOM contract. */
    }
    if (strcmp(argv[1], "pids") == 0) {
        int refused = 0;
        long before = pid_events();
        if (before < 0) return 7;
        signal(SIGTERM, cancel_children);
        signal(SIGINT, cancel_children);
        signal(SIGALRM, cancel_children);
        for (int n = 0; n < 64 && !cancelled; ++n) {
            pid_t child = fork();
            if (child == 0) { signal(SIGTERM, SIG_DFL); sleep(2); _exit(0); }
            if (child < 0) {
                refused = errno == EAGAIN ? 1 : -1;
                break;
            }
            children[child_count++] = child;
        }
        while (wait(NULL) > 0 || errno == EINTR) {}
        long after = pid_events();
        if (cancelled) return 8;
        if (refused < 0) return 5;
        if (refused && after > before) {
            printf("bounded-pid-refusal events-before=%ld events-after=%ld\n", before, after);
            return 0;
        }
        return 6;
    }
    return 2;
}
