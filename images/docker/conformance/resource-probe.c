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

int main(int argc, char **argv) {
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
