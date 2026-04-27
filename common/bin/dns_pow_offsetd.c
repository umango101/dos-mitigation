#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <sys/types.h>
 
#define DEFAULT_MAP_PATH "/sys/fs/bpf/tc/globals/offset_map"
#define DEFAULT_INTERVAL_US 2000
 
static int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}
 
static int bpf_obj_get(const char *path) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)(unsigned long)path;
    return sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}
 
static int bpf_map_update(int fd, const void *key, const void *value, uint64_t flags) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key    = (uint64_t)(unsigned long)key;
    attr.value  = (uint64_t)(unsigned long)value;
    attr.flags  = flags;
    return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}
 
static volatile sig_atomic_t stop = 0;
static void on_signal(int sig) { (void)sig; stop = 1; }
 
static int64_t compute_offset_ms(void) {
    struct timespec wall, mono;
    clock_gettime(CLOCK_REALTIME,  &wall);
    clock_gettime(CLOCK_MONOTONIC, &mono);
    int64_t wall_ms = (int64_t)wall.tv_sec * 1000 + wall.tv_nsec / 1000000;
    int64_t mono_ms = (int64_t)mono.tv_sec * 1000 + mono.tv_nsec / 1000000;
    return wall_ms - mono_ms;
}
 
int main(int argc, char *argv[]) {
    const char *map_path = DEFAULT_MAP_PATH;
    long interval_us = DEFAULT_INTERVAL_US;
    int verbose = 0;
 
    static struct option long_opts[] = {
        { "map",      required_argument, 0, 'm' },
        { "interval", required_argument, 0, 'i' },
        { "verbose",  no_argument,       0, 'v' },
        { "help",     no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
 
    int opt, idx;
    while ((opt = getopt_long(argc, argv, "m:i:vh", long_opts, &idx)) != -1) {
        switch (opt) {
            case 'm': map_path = optarg; break;
            case 'i': interval_us = strtol(optarg, NULL, 10); break;
            case 'v': verbose = 1; break;
            case 'h':
            default:
                fprintf(stderr,
                        "Usage: %s [--map PATH] [--interval USEC] [--verbose]\n",
                        argv[0]);
                return opt == 'h' ? 0 : 1;
        }
    }
    if (interval_us < 100) {
        fprintf(stderr, "interval too small (min 100us)\n");
        return 1;
    }
 
    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        fprintf(stderr, "open map %s: %s\n", map_path, strerror(errno));
        fprintf(stderr,
                "Hint: load the dns_pow tc program first (which pins the map)\n");
        return 1;
    }
 
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
 
    if (verbose)
        fprintf(stderr, "dns_pow_offsetd: refreshing %s every %ld us\n",
                map_path, interval_us);
 
    uint32_t key = 0;
    struct timespec sleep_ts;
    sleep_ts.tv_sec  = interval_us / 1000000;
    sleep_ts.tv_nsec = (interval_us % 1000000) * 1000;
 
    while (!stop) {
        int64_t off = compute_offset_ms();
        if (bpf_map_update(map_fd, &key, &off, 0 /*BPF_ANY*/) < 0) {
            fprintf(stderr, "map update: %s\n", strerror(errno));
            // Don't exit — try again next tick. Kernel may be momentarily busy.
        } else if (verbose) {
            fprintf(stderr, "offset_ms = %lld\n", (long long)off);
        }
        nanosleep(&sleep_ts, NULL);
    }
 
    if (verbose) fprintf(stderr, "dns_pow_offsetd: exiting\n");
    return 0;
}
