/*
 * FreeBSD 15.1 Migration Compatibility Checker — raw-syscall C port
 *
 * Linux x86-64 only. No libc calls are used: file, directory, socket,
 * output, and process operations use Linux syscalls invoked with inline asm.
 * The program uses fixed-size static storage rather than malloc/calloc.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -Werror -std=c11 -ffreestanding -fno-builtin \
 *       -fno-stack-protector -fno-pie -fno-asynchronous-unwind-tables \
 *       -fno-unwind-tables -nostdlib -static -no-pie \
 *       -Wl,-e,_start freebsd_compat_checker_raw.c -o freebsd_compat_checker
 *
 * Usage:
 *   ./freebsd_compat_checker [--save report.txt]
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>

#if !defined(__x86_64__)
#error "This source uses the Linux x86-64 syscall ABI and inline assembly."
#endif

/* ----------------------- Raw syscall ABI ----------------------- */
static inline long sc0(long n) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n) : "rcx", "r11", "memory");
    return r;
}
static inline long sc1(long n, long a1) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
    return r;
}
static inline long sc2(long n, long a1, long a2) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
    return r;
}
static inline long sc3(long n, long a1, long a2, long a3) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
    return r;
}
static inline long sc4(long n, long a1, long a2, long a3, long a4) {
    register long r10 __asm__("r10") = a4;
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx", "r11", "memory");
    return r;
}
static inline long sc5(long n, long a1, long a2, long a3, long a4, long a5) {
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8) : "rcx", "r11", "memory");
    return r;
}

/* Linux x86-64 syscall numbers. */
enum {
    SYS_read = 0, SYS_write = 1, SYS_close = 3, SYS_poll = 7,
    SYS_statfs = 137, SYS_uname = 63, SYS_geteuid = 107,
    SYS_socket = 41, SYS_connect = 42, SYS_getsockopt = 55,
    SYS_exit = 60, SYS_openat = 257, SYS_getdents64 = 217,
    SYS_readlinkat = 267
};
#define AT_FDCWD       (-100)
#define O_RDONLY       0
#define O_WRONLY       1
#define O_CREAT        0100
#define O_TRUNC        01000
#define O_NONBLOCK     04000
#define O_DIRECTORY    0200000
#define O_CLOEXEC      02000000
#define O_PATH         010000000
#define EINTR_VALUE    4
#define EINPROGRESS_VALUE 115
#define AF_INET_VALUE  2
#define SOCK_STREAM_VALUE 1
#define SOCK_NONBLOCK_VALUE 00004000
#define SOCK_CLOEXEC_VALUE 02000000
#define POLLOUT_VALUE  0x0004
#define SOL_SOCKET_VALUE 1
#define SO_ERROR_VALUE 4
#define MAX_ITEMS      256
#define FILE_CAP       131072
#define OUTPUT_CAP     262144
#define REPORT_CAP     131072
#define PATH_CAP       768
#define NAME_CAP       256
#define DETAIL_CAP     640
#define RECOMMEND_CAP  1200

/* ----------------------- Tiny C string helpers ----------------------- */
static size_t slen(const char *s) {
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) ++n;
    return n;
}
static bool seq(const char *a, const char *b) {
    size_t i = 0;
    if (!a || !b) return a == b;
    while (a[i] && b[i] && a[i] == b[i]) ++i;
    return a[i] == b[i];
}
static bool starts(const char *s, const char *prefix) {
    size_t i = 0;
    while (prefix[i]) { if (s[i] != prefix[i]) return false; ++i; }
    return true;
}
static bool contains(const char *s, const char *needle) {
    size_t n = slen(needle);
    if (!n) return true;
    for (size_t i = 0; s[i]; ++i) {
        size_t j = 0;
        while (j < n && s[i + j] && s[i + j] == needle[j]) ++j;
        if (j == n) return true;
    }
    return false;
}
static bool is_space(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'; }
static void copystr(char *dst, size_t cap, const char *src) {
    if (!cap) return;
    size_t i = 0;
    if (src) while (src[i] && i + 1 < cap) { dst[i] = src[i]; ++i; }
    dst[i] = 0;
}
static char *trim(char *s) {
    size_t n = slen(s), left = 0;
    while (left < n && is_space(s[left])) ++left;
    while (n > left && is_space(s[n - 1])) --n;
    if (left) {
        size_t i = 0;
        while (left + i < n) { s[i] = s[left + i]; ++i; }
        s[i] = 0;
    } else s[n] = 0;
    return s;
}
static uint64_t parse_u64(const char *s, bool *ok) {
    uint64_t v = 0;
    size_t i = 0;
    while (is_space(s[i])) ++i;
    if (s[i] < '0' || s[i] > '9') { if (ok) *ok = false; return 0; }
    while (s[i] >= '0' && s[i] <= '9') {
        uint64_t d = (uint64_t)(s[i] - '0');
        if (v > (UINT64_MAX - d) / 10) { if (ok) *ok = false; return 0; }
        v = v * 10 + d; ++i;
    }
    if (ok) *ok = true;
    return v;
}
/* ----------------------- Tiny formatting/output helpers ----------------------- */
typedef struct { char *buf; size_t cap; size_t len; } Builder;
static void b_char(Builder *b, char c) {
    if (b->len + 1 < b->cap) { b->buf[b->len++] = c; b->buf[b->len] = 0; }
}
static void b_strn(Builder *b, const char *s, size_t n) {
    if (!s) return;
    for (size_t i = 0; i < n && s[i]; ++i) b_char(b, s[i]);
}
static void b_str(Builder *b, const char *s) { b_strn(b, s, slen(s)); }
static void b_u64(Builder *b, uint64_t v) {
    char tmp[32]; size_t n = 0;
    do { tmp[n++] = (char)('0' + (v % 10)); v /= 10; } while (v && n < sizeof(tmp));
    while (n) b_char(b, tmp[--n]);
}
static void b_i64(Builder *b, int64_t v) {
    if (v < 0) { b_char(b, '-'); b_u64(b, (uint64_t)(-(v + 1)) + 1); }
    else b_u64(b, (uint64_t)v);
}
static void b_vfmt(Builder *b, const char *f, va_list ap) {
    for (size_t i = 0; f[i]; ++i) {
        if (f[i] != '%') { b_char(b, f[i]); continue; }
        ++i;
        if (!f[i]) break;
        if (f[i] == '%') { b_char(b, '%'); continue; }
        if (f[i] == '.' && f[i + 1] == '*') {
            i += 2;
            int precision = va_arg(ap, int);
            if (f[i] == 's') { const char *s = va_arg(ap, const char *); if (precision < 0) precision = 0; b_strn(b, s, (size_t)precision); }
            continue;
        }
        bool ll = false;
        if (f[i] == 'l' && f[i + 1] == 'l') { ll = true; i += 2; }
        else if (f[i] == 'l') { ll = true; ++i; }
        switch (f[i]) {
            case 's': b_str(b, va_arg(ap, const char *)); break;
            case 'c': b_char(b, (char)va_arg(ap, int)); break;
            case 'd': case 'i': b_i64(b, ll ? va_arg(ap, long long) : (long long)va_arg(ap, int)); break;
            case 'u': b_u64(b, ll ? va_arg(ap, unsigned long long) : (unsigned long long)va_arg(ap, unsigned int)); break;
            default: b_char(b, '%'); b_char(b, f[i]); break;
        }
    }
}
static void b_fmt(Builder *b, const char *f, ...) {
    va_list ap; va_start(ap, f); b_vfmt(b, f, ap); va_end(ap);
}
static void fmt_to(char *dst, size_t cap, const char *f, ...) {
    if (!cap) return;
    Builder b = { dst, cap, 0 }; dst[0] = 0;
    va_list ap; va_start(ap, f); b_vfmt(&b, f, ap); va_end(ap);
}
static void b_pct_tenths(Builder *b, uint64_t tenths) {
    b_u64(b, tenths / 10); b_char(b, '.'); b_char(b, (char)('0' + (tenths % 10))); b_char(b, '%');
}
static long write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        long r = sc3(SYS_write, fd, (long)(buf + off), (long)(len - off));
        if (r == -EINTR_VALUE) continue;
        if (r < 0) return r;
        if (r == 0) return -1;
        off += (size_t)r;
    }
    return (long)off;
}
static void say(const char *s) { (void)write_all(1, s, slen(s)); }

/* ----------------------- Raw filesystem helpers ----------------------- */
static long open_path(const char *path, long flags, long mode) {
    return sc4(SYS_openat, AT_FDCWD, (long)path, flags, mode);
}
static void close_fd(long fd) { if (fd >= 0) (void)sc1(SYS_close, fd); }
static bool path_exists(const char *path) {
    long fd = open_path(path, O_PATH | O_CLOEXEC, 0);
    if (fd < 0) return false;
    close_fd(fd); return true;
}
static long read_path(const char *path, char *buf, size_t cap) {
    if (cap < 2) return -1;
    long fd = open_path(path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) { buf[0] = 0; return fd; }
    size_t used = 0;
    while (used + 1 < cap) {
        long r = sc3(SYS_read, fd, (long)(buf + used), (long)(cap - used - 1));
        if (r == -EINTR_VALUE) continue;
        if (r < 0) { close_fd(fd); buf[used] = 0; return r; }
        if (r == 0) break;
        used += (size_t)r;
    }
    close_fd(fd); buf[used] = 0; return (long)used;
}
static bool read_first_line(const char *path, char *out, size_t cap) {
    char tmp[4096]; long n = read_path(path, tmp, sizeof(tmp));
    if (n < 0) { if (cap) out[0] = 0; return false; }
    size_t len = 0; while (len < (size_t)n && tmp[len] != '\n' && tmp[len] != '\r') ++len;
    if (len >= cap) len = cap ? cap - 1 : 0;
    if (cap) { for (size_t i = 0; i < len; ++i) out[i] = tmp[i]; out[len] = 0; trim(out); }
    return true;
}
static bool read_uint_file(const char *path, uint64_t *out) {
    char tmp[4096]; if (!read_first_line(path, tmp, sizeof(tmp))) return false;
    bool ok = false; uint64_t v = parse_u64(tmp, &ok); if (ok) *out = v; return ok;
}
static long read_link_path(const char *path, char *buf, size_t cap) {
    if (cap < 2) return -1;
    long r = sc4(SYS_readlinkat, AT_FDCWD, (long)path, (long)buf, (long)(cap - 1));
    if (r >= 0) buf[r] = 0;
    else buf[0] = 0;
    return r;
}
static void driver_name(const char *device_dir, char *out, size_t cap) {
    char path[PATH_CAP], target[PATH_CAP];
    fmt_to(path, sizeof(path), "%s/driver", device_dir);
    if (read_link_path(path, target, sizeof(target)) < 0) { copystr(out, cap, "unknown"); return; }
    char *last = target;
    for (size_t i = 0; target[i]; ++i) if (target[i] == '/') last = &target[i + 1];
    copystr(out, cap, last[0] ? last : "unknown");
}

typedef struct {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
} LinuxDirent64;
typedef struct {
    long fd;
    long n;
    long pos;
    unsigned char data[8192];
} DirIter;
static DirIter g_dir;
static bool dir_open(const char *path) {
    g_dir.fd = open_path(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    g_dir.n = 0; g_dir.pos = 0;
    return g_dir.fd >= 0;
}
static int dir_next(char *name, size_t cap) {
    for (;;) {
        if (g_dir.pos >= g_dir.n) {
            long n = sc3(SYS_getdents64, g_dir.fd, (long)g_dir.data, (long)sizeof(g_dir.data));
            if (n == -EINTR_VALUE) continue;
            if (n < 0) return -1;
            if (n == 0) return 0;
            g_dir.n = n; g_dir.pos = 0;
        }
        LinuxDirent64 *d = (LinuxDirent64 *)(g_dir.data + g_dir.pos);
        if (d->d_reclen < offsetof(LinuxDirent64, d_name) + 1) return -1;
        g_dir.pos += d->d_reclen;
        copystr(name, cap, d->d_name);
        if (!seq(name, ".") && !seq(name, "..")) return 1;
    }
}

/* ----------------------- uname/statfs kernel layouts ----------------------- */
struct UtsName { char sysname[65], nodename[65], release[65], version[65], machine[65], domainname[65]; };
struct KStatFs {
    long f_type, f_bsize;
    unsigned long f_blocks, f_bfree, f_bavail, f_files, f_ffree;
    int f_fsid[2];
    long f_namelen, f_frsize, f_flags;
    long f_spare[4];
};
static struct UtsName g_uts;
static char g_filebuf[FILE_CAP];
static char g_root_device[PATH_CAP];

/* ----------------------- Report model ----------------------- */
enum { SCORE_FULL = 0, SCORE_MINOR = 1, SCORE_MAYBE = 2, SCORE_NONE = 3 };
typedef struct {
    char name[NAME_CAP];
    char category[48];
    char detail[DETAIL_CAP];
    char recommendation[RECOMMEND_CAP];
    int score;
    bool critical;
} CompatItem;
typedef struct {
    CompatItem items[MAX_ITEMS];
    unsigned count;
    unsigned score_counts[4];
    uint64_t overall_tenths;
} CompatReport;
static CompatReport g_report;
static CompatItem *new_item(CompatReport *r) {
    if (r->count >= MAX_ITEMS) return (CompatItem *)0;
    return &r->items[r->count++];
}
static void item_base(CompatItem *it, const char *category, const char *name, bool critical) {
    copystr(it->category, sizeof(it->category), category);
    copystr(it->name, sizeof(it->name), name);
    it->critical = critical;
}
static void compute_report(CompatReport *r) {
    uint64_t weighted_points = 0, total_weight = 0;
    for (unsigned i = 0; i < 4; ++i) r->score_counts[i] = 0;
    for (unsigned i = 0; i < r->count; ++i) {
        CompatItem *it = &r->items[i];
        int s = it->score;
        if (s < 0 || s > 3) s = SCORE_MAYBE;
        ++r->score_counts[s];
        uint64_t w = it->critical ? 2 : 1;
        weighted_points += (uint64_t)(3 - s) * w;
        total_weight += w;
    }
    r->overall_tenths = total_weight ? (weighted_points * 1000) / (3 * total_weight) : 0;
}

/* ----------------------- CPU ----------------------- */
static void analyze_cpu(CompatReport *r) {
    char vendor[128] = "", model[NAME_CAP] = "";
    unsigned cores = 0;
    long n = read_path("/proc/cpuinfo", g_filebuf, sizeof(g_filebuf));
    if (n >= 0) {
        char *p = g_filebuf;
        while (*p) {
            char *line = p;
            while (*p && *p != '\n') ++p;
            if (*p == '\n') *p++ = 0;
            if (starts(line, "vendor_id") && !vendor[0]) {
                char *colon = line; while (*colon && *colon != ':') ++colon;
                if (*colon) copystr(vendor, sizeof(vendor), trim(colon + 1));
            } else if (starts(line, "model name") && !model[0]) {
                char *colon = line; while (*colon && *colon != ':') ++colon;
                if (*colon) copystr(model, sizeof(model), trim(colon + 1));
            } else if (starts(line, "processor")) ++cores;
        }
    }
    (void)sc1(SYS_uname, (long)&g_uts);
    CompatItem *it = new_item(r); if (!it) return;
    item_base(it, "CPU", model[0] ? model : (vendor[0] ? vendor : g_uts.machine), true);
    bool x64 = seq(g_uts.machine, "x86_64");
    bool intel = contains(vendor, "GenuineIntel"), amd = contains(vendor, "AuthenticAMD");
    if (x64 && (intel || amd)) {
        it->score = SCORE_FULL;
        fmt_to(it->detail, sizeof(it->detail), "%s | %u logical cores | architecture: %s", intel ? "Intel" : "AMD", cores, g_uts.machine);
        copystr(it->recommendation, sizeof(it->recommendation), "FreeBSD 15.1 has mature, first-class support for x86_64. No CPU-related migration concerns expected.");
    } else if (starts(g_uts.machine, "aarch64") || starts(g_uts.machine, "arm")) {
        it->score = SCORE_MAYBE;
        fmt_to(it->detail, sizeof(it->detail), "ARM architecture detected: %s | %u logical cores", g_uts.machine, cores);
        copystr(it->recommendation, sizeof(it->recommendation), "FreeBSD's ARM64 (aarch64) support exists but is considerably less mature than its x86_64 support. Expect missing packages and rougher edges on ARM hardware.");
    } else {
        it->score = SCORE_MAYBE;
        fmt_to(it->detail, sizeof(it->detail), "Uncommon architecture: %s | vendor: %s", g_uts.machine, vendor);
        copystr(it->recommendation, sizeof(it->recommendation), "This architecture is not among FreeBSD's primary supported targets. Check the FreeBSD Handbook for current platform support before migrating.");
    }
}

/* ----------------------- RAM ----------------------- */
static void analyze_ram(CompatReport *r) {
    uint64_t total_kb = 0;
    long n = read_path("/proc/meminfo", g_filebuf, sizeof(g_filebuf));
    if (n >= 0) {
        char *p = g_filebuf;
        while (*p) {
            char *line = p; while (*p && *p != '\n') ++p; if (*p == '\n') *p++ = 0;
            if (starts(line, "MemTotal:")) { char *q = line; while (*q && *q != ':') ++q; if (*q) { bool ok; total_kb = parse_u64(q + 1, &ok); if (!ok) total_kb = 0; } break; }
        }
    }
    uint64_t mb = total_kb / 1024, gb = mb / 1024;
    CompatItem *it = new_item(r); if (!it) return;
    fmt_to(it->name, sizeof(it->name), "System memory: %llu MB (%llu GB)", (unsigned long long)mb, (unsigned long long)gb);
    item_base(it, "Memory (RAM)", it->name, true);
    if (mb < 2048) {
        it->score = SCORE_NONE;
        fmt_to(it->detail, sizeof(it->detail), "Only %llu MB RAM detected -- FreeBSD desktop use (KDE Plasma, GNOME) generally wants at least 2-4 GB.", (unsigned long long)mb);
        copystr(it->recommendation, sizeof(it->recommendation), "Consider a lightweight window manager instead of a full desktop environment, or add more RAM before migrating.");
    } else if (mb < 4096) {
        it->score = SCORE_MINOR;
        fmt_to(it->detail, sizeof(it->detail), "%llu MB RAM -- sufficient for basic desktop use.", (unsigned long long)mb);
        copystr(it->recommendation, sizeof(it->recommendation), "A lightweight desktop (Xfce, LXQt) will feel more comfortable than KDE Plasma or GNOME at this memory size.");
    } else {
        it->score = SCORE_FULL;
        fmt_to(it->detail, sizeof(it->detail), "%llu MB (%llu GB) RAM -- comfortable for any desktop environment.", (unsigned long long)mb, (unsigned long long)gb);
        copystr(it->recommendation, sizeof(it->recommendation), "No memory-related migration concerns.");
    }
}

/* ----------------------- Storage ----------------------- */
typedef struct { uint64_t start, size; } PartitionRange;
static PartitionRange g_parts[MAX_ITEMS];
static void analyze_storage(CompatReport *r) {
    uint64_t total_gb = 0, free_gb = 0;
    struct KStatFs st;
    long sr = sc2(SYS_statfs, (long)"/", (long)&st);
    if (sr == 0) {
        uint64_t block = st.f_frsize ? (uint64_t)st.f_frsize : (uint64_t)st.f_bsize;
        total_gb = ((uint64_t)st.f_blocks * block) / (1024ULL * 1024 * 1024);
        free_gb = ((uint64_t)st.f_bavail * block) / (1024ULL * 1024 * 1024);
    }
    g_root_device[0] = 0;
    long mn = read_path("/proc/self/mountinfo", g_filebuf, sizeof(g_filebuf));
    if (mn >= 0) {
        char *p = g_filebuf;
        while (*p) {
            char *line = p; while (*p && *p != '\n') ++p; if (*p == '\n') *p++ = 0;
            char *fields[256]; unsigned nf = 0; char *q = line;
            while (*q && nf < 256) { while (is_space(*q)) ++q; if (!*q) break; fields[nf++] = q; while (*q && !is_space(*q)) ++q; if (*q) *q++ = 0; }
            unsigned sep = nf;
            for (unsigned i = 0; i < nf; ++i) if (seq(fields[i], "-")) { sep = i; break; }
            if (nf > 4 && seq(fields[4], "/") && sep + 2 < nf) { copystr(g_root_device, sizeof(g_root_device), fields[sep + 2]); break; }
        }
    }
    bool is_ssd = false, is_nvme = false, direct = false, unallocated_known = false;
    char base[NAME_CAP] = "";
    if (starts(g_root_device, "/dev/")) {
        const char *b = g_root_device; for (size_t i = 0; g_root_device[i]; ++i) if (g_root_device[i] == '/') b = &g_root_device[i + 1];
        copystr(base, sizeof(base), b);
        if (starts(base, "nvme")) {
            for (size_t i = 0; base[i]; ++i) if (base[i] == 'p') { base[i] = 0; break; }
            is_nvme = true;
        } else if (starts(base, "mmcblk")) {
            for (size_t i = 0; base[i]; ++i) if (base[i] == 'p') { base[i] = 0; break; }
        } else {
            size_t z = slen(base); while (z && base[z - 1] >= '0' && base[z - 1] <= '9') base[--z] = 0;
        }
        char path[PATH_CAP]; fmt_to(path, sizeof(path), "/sys/block/%s/queue/rotational", base);
        direct = base[0] && path_exists(path);
        if (direct) { char rot[32]; if (read_first_line(path, rot, sizeof(rot))) is_ssd = seq(rot, "0"); }
    }
    uint64_t disk_sectors = 0, gap_sectors = 0;
    if (direct) {
        char path[PATH_CAP]; fmt_to(path, sizeof(path), "/sys/block/%s/size", base);
        if (read_uint_file(path, &disk_sectors)) {
            unsigned count = 0;
            fmt_to(path, sizeof(path), "/sys/block/%s", base);
            if (dir_open(path)) {
                char entry[NAME_CAP]; int dr;
                while ((dr = dir_next(entry, sizeof(entry))) > 0 && count < MAX_ITEMS) {
                    char partpath[PATH_CAP]; uint64_t start = 0, size = 0;
                    fmt_to(partpath, sizeof(partpath), "/sys/block/%s/%s/partition", base, entry);
                    if (!path_exists(partpath)) continue;
                    fmt_to(partpath, sizeof(partpath), "/sys/block/%s/%s/start", base, entry);
                    if (!read_uint_file(partpath, &start)) continue;
                    fmt_to(partpath, sizeof(partpath), "/sys/block/%s/%s/size", base, entry);
                    if (!read_uint_file(partpath, &size) || start >= disk_sectors) continue;
                    if (size > disk_sectors - start) size = disk_sectors - start;
                    if (size) { g_parts[count].start = start; g_parts[count].size = size; ++count; }
                }
                close_fd(g_dir.fd);
            }
            for (unsigned i = 1; i < count; ++i) {
                PartitionRange v = g_parts[i]; unsigned j = i;
                while (j && g_parts[j - 1].start > v.start) { g_parts[j] = g_parts[j - 1]; --j; }
                g_parts[j] = v;
            }
            uint64_t cursor = 0;
            for (unsigned i = 0; i < count; ++i) {
                if (g_parts[i].start > cursor && g_parts[i].start - cursor > gap_sectors) gap_sectors = g_parts[i].start - cursor;
                uint64_t end = g_parts[i].start + g_parts[i].size; if (end > cursor) cursor = end;
            }
            if (cursor < disk_sectors && disk_sectors - cursor > gap_sectors) gap_sectors = disk_sectors - cursor;
            unallocated_known = true;
        }
    }
    uint64_t gap_gb = gap_sectors / (1024ULL * 1024 * 2);
    const char *drive_type = is_nvme ? "NVMe SSD" : is_ssd ? "SSD" : direct ? "Rotational (HDD)" : "Unknown";
    CompatItem *it = new_item(r); if (!it) return;
    fmt_to(it->name, sizeof(it->name), "Storage device: %s", drive_type);
    item_base(it, "Storage (Disk)", it->name, true);
    if (is_nvme) {
        it->score = SCORE_FULL; copystr(it->detail, sizeof(it->detail), "NVMe storage controller.");
        copystr(it->recommendation, sizeof(it->recommendation), "Natively supported by FreeBSD's nvme(4) driver. ZFS or UFS are both good filesystem choices on NVMe.");
    } else if (direct) {
        it->score = SCORE_FULL; fmt_to(it->detail, sizeof(it->detail), "%s storage device (SATA/AHCI-class).", drive_type);
        copystr(it->recommendation, sizeof(it->recommendation), "Natively supported by FreeBSD's ahci(4)/ada(4) drivers. No storage-hardware migration concerns.");
    } else {
        it->score = SCORE_MAYBE; copystr(it->detail, sizeof(it->detail), "Could not determine the backing storage device type (possibly LVM, dm-crypt, RAID, or a network filesystem).");
        copystr(it->recommendation, sizeof(it->recommendation), "Check the underlying physical storage hardware manually; layered storage (LVM/RAID/encryption) needs separate inspection.");
    }
    it = new_item(r); if (!it) return;
    fmt_to(it->name, sizeof(it->name), "Installation space: root FS %llu GB total / %llu GB free", (unsigned long long)total_gb, (unsigned long long)free_gb);
    item_base(it, "Storage (Disk)", it->name, false);
    if (unallocated_known) {
        fmt_to(it->detail, sizeof(it->detail), "Largest unpartitioned gap on the backing disk: %llu GB. Root filesystem free space is %llu GB and is a separate figure -- it is not installable unallocated space.", (unsigned long long)gap_gb, (unsigned long long)free_gb);
        if (gap_gb >= 50) { it->score = SCORE_FULL; copystr(it->recommendation, sizeof(it->recommendation), "At least 50 GiB of unpartitioned space is already available for a comfortable FreeBSD desktop installation."); }
        else if (gap_gb >= 20) { it->score = SCORE_MINOR; copystr(it->recommendation, sizeof(it->recommendation), "At least 20 GiB of unpartitioned space is visible, enough for a basic install; 50+ GiB is preferable for a full desktop."); }
        else { it->score = SCORE_MINOR; copystr(it->recommendation, sizeof(it->recommendation), "No 20+ GiB unpartitioned gap was detected right now. This does not mean the hardware is incompatible -- you'll need to shrink an existing partition, free up space, or use another disk before installing."); }
    } else {
        it->score = SCORE_MAYBE;
        fmt_to(it->detail, sizeof(it->detail), "Root filesystem reports %llu GB free, but unpartitioned disk space could not be safely determined (backing device: %s).", (unsigned long long)free_gb, g_root_device[0] ? g_root_device : "unknown");
        copystr(it->recommendation, sizeof(it->recommendation), "Check the partition table manually before installing FreeBSD. LVM, dm-crypt, RAID, and other layered storage need separate inspection.");
    }
}

/* ----------------------- GPU ----------------------- */
static void analyze_gpu(CompatReport *r) {
    const char *root = "/sys/bus/pci/devices";
    if (!path_exists(root)) return;
    bool found = false; unsigned gpu_count = 0;
    if (!dir_open(root)) return;
    char entry[NAME_CAP]; int dr;
    while ((dr = dir_next(entry, sizeof(entry))) > 0) {
        char dir[PATH_CAP], path[PATH_CAP], classid[64], vendor[64], device[64], driver[NAME_CAP];
        fmt_to(dir, sizeof(dir), "%s/%s", root, entry);
        fmt_to(path, sizeof(path), "%s/class", dir);
        if (!read_first_line(path, classid, sizeof(classid)) || !starts(classid, "0x03")) continue;
        fmt_to(path, sizeof(path), "%s/vendor", dir); if (!read_first_line(path, vendor, sizeof(vendor))) copystr(vendor, sizeof(vendor), "");
        fmt_to(path, sizeof(path), "%s/device", dir); if (!read_first_line(path, device, sizeof(device))) copystr(device, sizeof(device), "");
        driver_name(dir, driver, sizeof(driver)); found = true; ++gpu_count;
        CompatItem *it = new_item(r); if (!it) break;
        fmt_to(it->name, sizeof(it->name), "PCI display controller [%s:%s] (Linux driver: %s)", vendor, device, driver);
        item_base(it, "Graphics (GPU)", it->name, true);
        bool intel = seq(vendor, "0x8086"), amd = seq(vendor, "0x1002"), nvidia = seq(vendor, "0x10de");
        if (intel) { it->score = SCORE_MINOR; copystr(it->detail, sizeof(it->detail), "Intel graphics device detected."); copystr(it->recommendation, sizeof(it->recommendation), "FreeBSD 15.1 uses drm-kmod/i915kms for supported Intel generations. FreeBSD's current DRM status notes that i915 still has instabilities; verify the exact GPU ID and required firmware."); }
        else if (amd) { it->score = SCORE_MINOR; copystr(it->detail, sizeof(it->detail), "AMD graphics device detected."); copystr(it->recommendation, sizeof(it->recommendation), "FreeBSD provides amdgpu through drm-kmod. Check the exact GPU generation against the current FreeBSD graphics support matrix."); }
        else if (nvidia) { it->score = SCORE_MAYBE; copystr(it->detail, sizeof(it->detail), "NVIDIA graphics device detected."); copystr(it->recommendation, sizeof(it->recommendation), "FreeBSD's NVIDIA stack is proprietary. Driver/compositor behavior may be unstable or lack features; on hybrid laptops, a supported integrated GPU is the lower-risk primary desktop GPU."); }
        else { it->score = SCORE_MAYBE; copystr(it->detail, sizeof(it->detail), "Unrecognized PCI display vendor."); copystr(it->recommendation, sizeof(it->recommendation), "Check the exact PCI device against FreeBSD's current graphics support before migrating."); }
    }
    close_fd(g_dir.fd);
    if (!found) {
        CompatItem *it = new_item(r); if (!it) return;
        item_base(it, "Graphics (GPU)", "No PCI display controller found", true); it->score = SCORE_MAYBE;
        copystr(it->detail, sizeof(it->detail), "Could not enumerate a display controller via /sys/bus/pci/devices.");
        copystr(it->recommendation, sizeof(it->recommendation), "This may be a virtual machine or an unusual setup; verify manually.");
    } else if (gpu_count > 1) {
        CompatItem *it = new_item(r); if (!it) return;
        fmt_to(it->name, sizeof(it->name), "Hybrid/multi-GPU system: %u display controllers", gpu_count);
        item_base(it, "Graphics (GPU)", it->name, false); it->score = SCORE_MINOR;
        copystr(it->detail, sizeof(it->detail), "Multiple display controllers were detected. Linux GPU-driver bindings do not guarantee identical offload, power-management, or suspend behavior on FreeBSD.");
        copystr(it->recommendation, sizeof(it->recommendation), "Validate the primary GPU first, then test graphics offload and suspend/resume separately.");
    }
}

/* ----------------------- Networking ----------------------- */
static void analyze_network(CompatReport *r) {
    const char *root = "/sys/class/net"; if (!path_exists(root) || !dir_open(root)) return;
    bool found = false; char iface[NAME_CAP]; int dr;
    while ((dr = dir_next(iface, sizeof(iface))) > 0) {
        if (seq(iface, "lo")) continue;
        char entry[PATH_CAP], device_dir[PATH_CAP], path[PATH_CAP], driver[NAME_CAP];
        fmt_to(entry, sizeof(entry), "%s/%s", root, iface);
        fmt_to(device_dir, sizeof(device_dir), "%s/device", entry);
        if (!path_exists(device_dir)) continue;
        driver_name(device_dir, driver, sizeof(driver));
        fmt_to(path, sizeof(path), "%s/wireless", entry);
        bool wireless = path_exists(path);
        fmt_to(path, sizeof(path), "%s/phy80211", entry); wireless = wireless || path_exists(path);
        found = true;
        CompatItem *it = new_item(r); if (!it) break;
        fmt_to(it->name, sizeof(it->name), "%s (%s, driver: %s)", iface, wireless ? "Wi-Fi" : "Ethernet", driver);
        item_base(it, "Networking", it->name, false);
        bool intel_eth = contains(driver, "e1000") || contains(driver, "igb") || contains(driver, "igc") || contains(driver, "ice") || contains(driver, "ixgbe");
        bool iwl = contains(driver, "iwlwifi") || contains(driver, "iwl");
        bool realtek = contains(driver, "rtw") || contains(driver, "r8169") || contains(driver, "r8168");
        bool atheros = contains(driver, "ath");
        bool mediatek = contains(driver, "mt7") || contains(driver, "mt76");
        bool broadcom = contains(driver, "brcm") || contains(driver, "bnx") || contains(driver, "tg3");
        if (intel_eth) { it->score = SCORE_FULL; copystr(it->detail, sizeof(it->detail), "Intel wired Ethernet controller."); copystr(it->recommendation, sizeof(it->recommendation), "Well supported via FreeBSD's em(4)/igb(4)/ix(4) drivers."); }
        else if (iwl) { it->score = SCORE_MINOR; copystr(it->detail, sizeof(it->detail), "Intel Wi-Fi adapter (Linux driver: iwlwifi)."); copystr(it->recommendation, sizeof(it->recommendation), "FreeBSD's iwlwifi(4) port supports many Intel Wi-Fi chips, but firmware/chip support can lag behind Linux for the newest cards. Check the supported-chipset list for your exact model."); }
        else if (atheros) { it->score = SCORE_FULL; copystr(it->detail, sizeof(it->detail), "Atheros Wi-Fi adapter."); copystr(it->recommendation, sizeof(it->recommendation), "Atheros chips (ath(4)) have a long history of solid, mature support on FreeBSD."); }
        else if (realtek) { it->score = SCORE_MAYBE; fmt_to(it->detail, sizeof(it->detail), "Realtek %s adapter.", wireless ? "Wi-Fi" : "Ethernet"); copystr(it->recommendation, sizeof(it->recommendation), wireless ? "Realtek Wi-Fi chip support on FreeBSD is inconsistent; many newer chips have no driver at all. Verify your exact chip before migrating." : "Realtek Ethernet (re(4)) generally works but has historically been less robust than Intel's drivers."); }
        else if (mediatek) { it->score = SCORE_MAYBE; copystr(it->detail, sizeof(it->detail), "MediaTek Wi-Fi adapter."); copystr(it->recommendation, sizeof(it->recommendation), "MediaTek Wi-Fi support on FreeBSD is limited compared to Linux's mt76 driver. Verify chip-specific support before migrating."); }
        else if (broadcom) { it->score = SCORE_MAYBE; fmt_to(it->detail, sizeof(it->detail), "Broadcom %s adapter.", wireless ? "Wi-Fi" : "Ethernet"); copystr(it->recommendation, sizeof(it->recommendation), "Broadcom devices are frequently problematic on FreeBSD; a USB Ethernet adapter as backup is a reasonable precaution."); }
        else { it->score = SCORE_MAYBE; fmt_to(it->detail, sizeof(it->detail), "Unrecognized %s driver: %s", wireless ? "Wi-Fi" : "network", driver); copystr(it->recommendation, sizeof(it->recommendation), "Search the FreeBSD Handbook's hardware notes or the forums for this specific chipset."); }
    }
    close_fd(g_dir.fd);
    if (!found) {
        CompatItem *it = new_item(r); if (!it) return;
        item_base(it, "Networking", "No physical network adapters found", false); it->score = SCORE_MAYBE;
        copystr(it->detail, sizeof(it->detail), "Could not enumerate any non-loopback network device with a backing driver.");
        copystr(it->recommendation, sizeof(it->recommendation), "Verify manually; this may be a container or unusual environment.");
    }
}

/* ----------------------- Audio ----------------------- */
static void analyze_audio(CompatReport *r) {
    long n = read_path("/proc/asound/cards", g_filebuf, sizeof(g_filebuf));
    if (n < 0) {
        CompatItem *it = new_item(r); if (!it) return;
        item_base(it, "Audio", "No ALSA sound cards found", false); it->score = SCORE_MAYBE;
        copystr(it->detail, sizeof(it->detail), "Could not read /proc/asound/cards.");
        copystr(it->recommendation, sizeof(it->recommendation), "Verify your sound hardware manually."); return;
    }
    bool found = false; char *p = g_filebuf;
    while (*p) {
        char *line = p; while (*p && *p != '\n') ++p; if (*p == '\n') *p++ = 0;
        char *colon = line; while (*colon && *colon != ':') ++colon; if (!*colon) continue;
        found = true; char desc[NAME_CAP]; copystr(desc, sizeof(desc), trim(colon + 1));
        CompatItem *it = new_item(r); if (!it) return;
        item_base(it, "Audio", desc, false);
        if (contains(desc, "HDA")) {
            it->score = SCORE_MINOR; copystr(it->detail, sizeof(it->detail), "Standard HD Audio (HDA) codec.");
            copystr(it->recommendation, sizeof(it->recommendation), "FreeBSD's native sound(4)/hdac(4) driver generally handles HDA audio, but the audio stack may be rougher than Linux ALSA/PipeWire. PipeWire + WirePlumber is recommended for a modern experience and is specifically needed for Wayland screen capture.");
        } else { it->score = SCORE_MAYBE; copystr(it->detail, sizeof(it->detail), "Non-HDA audio device."); copystr(it->recommendation, sizeof(it->recommendation), "Check FreeBSD's sound(4) man page for explicit support of this device."); }
    }
    if (!found) {
        CompatItem *it = new_item(r); if (!it) return;
        item_base(it, "Audio", "No sound cards enumerated", false); it->score = SCORE_MAYBE;
        copystr(it->detail, sizeof(it->detail), "/proc/asound/cards was empty or unreadable."); copystr(it->recommendation, sizeof(it->recommendation), "Verify your sound hardware manually.");
    }
}

/* ----------------------- Secure Boot ----------------------- */
static void analyze_secure_boot(CompatReport *r) {
    CompatItem *it = new_item(r); if (!it) return;
    item_base(it, "Secure Boot", "", false);
    if (!path_exists("/sys/firmware/efi")) {
        copystr(it->name, sizeof(it->name), "Secure Boot: not applicable (legacy BIOS)"); it->score = SCORE_FULL;
        copystr(it->detail, sizeof(it->detail), "The system was not booted through UEFI.");
        copystr(it->recommendation, sizeof(it->recommendation), "Secure Boot is informational here and is not a migration blocker."); return;
    }
    bool known = false, enabled = false;
    const char *root = "/sys/firmware/efi/efivars";
    if (path_exists(root) && dir_open(root)) {
        char name[NAME_CAP]; int dr;
        while ((dr = dir_next(name, sizeof(name))) > 0) {
            if (!starts(name, "SecureBoot-")) continue;
            char path[PATH_CAP], bytes[32]; fmt_to(path, sizeof(path), "%s/%s", root, name);
            long n = read_path(path, bytes, sizeof(bytes));
            if (n >= 5) { known = true; enabled = bytes[4] != 0; }
            break;
        }
        close_fd(g_dir.fd);
    }
    it->score = SCORE_FULL;
    if (known) fmt_to(it->name, sizeof(it->name), "Secure Boot: %s", enabled ? "enabled" : "disabled");
    else copystr(it->name, sizeof(it->name), "Secure Boot: state unavailable");
    copystr(it->detail, sizeof(it->detail), known ? "UEFI Secure Boot state was read from efivarfs." : "UEFI was detected, but the SecureBoot EFI variable could not be read.");
    copystr(it->recommendation, sizeof(it->recommendation), "Secure Boot is treated as informational by this scanner rather than as a hardware compatibility score.");
}

/* ----------------------- Firmware and TPM ----------------------- */
static void analyze_firmware(CompatReport *r) {
    bool uefi = path_exists("/sys/firmware/efi");
    bool tpm = path_exists("/sys/class/tpm/tpm0") || path_exists("/dev/tpm0");
    CompatItem *it = new_item(r); if (!it) return;
    fmt_to(it->name, sizeof(it->name), "Boot type: %s", uefi ? "UEFI" : "Legacy BIOS");
    item_base(it, "Firmware", it->name, true);
    if (uefi) { it->score = SCORE_FULL; copystr(it->detail, sizeof(it->detail), "UEFI boot environment detected."); copystr(it->recommendation, sizeof(it->recommendation), "FreeBSD 15.1 installs and boots in UEFI mode. Make sure to select the UEFI installer image."); }
    else { it->score = SCORE_MINOR; copystr(it->detail, sizeof(it->detail), "Legacy BIOS boot environment detected."); copystr(it->recommendation, sizeof(it->recommendation), "FreeBSD still supports legacy BIOS boot, but UEFI is the better-tested, more actively maintained path."); }
    it = new_item(r); if (!it) return;
    fmt_to(it->name, sizeof(it->name), "Trusted Platform Module (TPM): %s", tpm ? "Present" : "Not detected");
    item_base(it, "TPM", it->name, false); it->score = SCORE_FULL;
    copystr(it->detail, sizeof(it->detail), tpm ? "TPM device node found." : "No TPM device detected.");
    copystr(it->recommendation, sizeof(it->recommendation), "TPM is not a hard requirement for FreeBSD; it can optionally be used for disk encryption key storage if desired.");
}

/* ----------------------- Power / Battery ----------------------- */
static void analyze_power(CompatReport *r) {
    const char *root = "/sys/class/power_supply"; if (!path_exists(root) || !dir_open(root)) return;
    char name[NAME_CAP]; int dr;
    while ((dr = dir_next(name, sizeof(name))) > 0) {
        if (!starts(name, "BAT")) continue;
        char path[PATH_CAP], cap[64] = "?", status[64] = "Unknown";
        fmt_to(path, sizeof(path), "%s/%s/capacity", root, name); (void)read_first_line(path, cap, sizeof(cap));
        fmt_to(path, sizeof(path), "%s/%s/status", root, name); (void)read_first_line(path, status, sizeof(status));
        CompatItem *it = new_item(r); if (!it) break;
        fmt_to(it->name, sizeof(it->name), "Battery %s: %s%%  |  Status: %s", name, cap, status);
        item_base(it, "Power / Battery", it->name, false); it->score = SCORE_MINOR;
        copystr(it->detail, sizeof(it->detail), "A laptop battery was detected. Power management on FreeBSD differs from Linux's kernel power framework.");
        copystr(it->recommendation, sizeof(it->recommendation), "Install powerd(8) for basic CPU frequency scaling, and check acpi_video(4)/backlight support for your specific laptop model, since brightness-key behavior can vary.");
        break;
    }
    close_fd(g_dir.fd);
}

/* ----------------------- Virtualization ----------------------- */
static void analyze_virtualization(CompatReport *r) {
    long n = read_path("/proc/cpuinfo", g_filebuf, sizeof(g_filebuf)); bool hv = false;
    if (n >= 0) {
        char *p = g_filebuf;
        while (*p) { char *line = p; while (*p && *p != '\n') ++p; if (*p == '\n') *p++ = 0; if (starts(line, "flags") && contains(line, "hypervisor")) { hv = true; break; } }
    }
    if (!hv) return;
    char product[NAME_CAP] = "Unknown"; (void)read_first_line("/sys/class/dmi/id/product_name", product, sizeof(product));
    CompatItem *it = new_item(r); if (!it) return;
    fmt_to(it->name, sizeof(it->name), "Running inside a virtual machine (%s)", product);
    item_base(it, "Virtualization", it->name, false); it->score = SCORE_MINOR;
    copystr(it->detail, sizeof(it->detail), "The CPU's hypervisor flag is set, meaning this scan itself is running inside a VM.");
    copystr(it->recommendation, sizeof(it->recommendation), "Results reflect virtual hardware, not physical hardware. FreeBSD generally runs well as a guest OS, but re-run this tool on physical hardware for an accurate bare-metal assessment.");
}

/* ----------------------- Raw TCP reachability probe ----------------------- */
struct SockAddrIn { uint16_t family; uint16_t port; uint32_t addr; unsigned char zero[8]; };
struct PollFd { int fd; short events; short revents; };
static uint16_t swap16(uint16_t x) { return (uint16_t)((x << 8) | (x >> 8)); }
static bool connect_with_timeout(uint32_t ip, uint16_t port, int timeout_ms) {
    long fd = sc3(SYS_socket, AF_INET_VALUE, SOCK_STREAM_VALUE | SOCK_NONBLOCK_VALUE | SOCK_CLOEXEC_VALUE, 0);
    if (fd < 0) return false;
    struct SockAddrIn addr;
    addr.family = AF_INET_VALUE; addr.port = swap16(port); addr.addr = ip;
    for (unsigned i = 0; i < sizeof(addr.zero); ++i) addr.zero[i] = 0;
    long rc = sc3(SYS_connect, fd, (long)&addr, (long)sizeof(addr));
    if (rc == 0) { close_fd(fd); return true; }
    if (rc != -EINPROGRESS_VALUE) { close_fd(fd); return false; }
    struct PollFd pfd; pfd.fd = (int)fd; pfd.events = POLLOUT_VALUE; pfd.revents = 0;
    long pr = sc3(SYS_poll, (long)&pfd, 1, timeout_ms);
    if (pr <= 0) { close_fd(fd); return false; }
    int soerr = 0; uint32_t optlen = sizeof(soerr);
    long gr = sc5(SYS_getsockopt, fd, SOL_SOCKET_VALUE, SO_ERROR_VALUE, (long)&soerr, (long)&optlen);
    close_fd(fd);
    return gr == 0 && soerr == 0;
}
static bool check_connectivity(void) {
    /* Each address has four identical octets, so its network-order integer is unchanged. */
    if (connect_with_timeout(0x01010101U, 443, 2000)) return true;
    if (connect_with_timeout(0x08080808U, 443, 2000)) return true;
    if (connect_with_timeout(0x09090909U, 443, 2000)) return true;
    return false;
}
static void analyze_online(CompatReport *r, bool online) {
    CompatItem *it = new_item(r); if (!it) return;
    item_base(it, "Online Data", online ? "External network reachability: detected" : "External network reachability: not detected", false);
    if (online) { it->score = SCORE_FULL; copystr(it->detail, sizeof(it->detail), "At least one external IPv4 TCP/443 endpoint accepted a connection."); copystr(it->recommendation, sizeof(it->recommendation), "This only verifies basic outbound reachability. DNS, HTTPS, captive portals, firewalls, and package-repository access still need to be tested after installation."); }
    else { it->score = SCORE_MINOR; copystr(it->detail, sizeof(it->detail), "No tested external IPv4 TCP/443 endpoint could be reached right now."); copystr(it->recommendation, sizeof(it->recommendation), "The network may be filtered, offline, or temporarily unavailable. This result alone is not a FreeBSD hardware-compatibility failure."); }
}

/* ----------------------- Console and report rendering ----------------------- */
static const char *C_RESET = "\033[0m", *C_BOLD = "\033[1m", *C_DIM = "\033[2m";
static const char *C_RED = "\033[91m", *C_GREEN = "\033[92m", *C_YELLOW = "\033[93m";
static const char *C_BLUE = "\033[94m", *C_CYAN = "\033[96m", *C_WHITE = "\033[97m", *C_ORANGE = "\033[38;5;208m";
static const char *score_label(int s) {
    switch (s) {
        case SCORE_FULL: return "\033[92m\033[1m[0] FULLY COMPATIBLE      \033[0m";
        case SCORE_MINOR: return "\033[93m\033[1m[1] COMPATIBLE (minor)    \033[0m";
        case SCORE_MAYBE: return "\033[38;5;208m\033[1m[2] MAYBE INCOMPATIBLE    \033[0m";
        case SCORE_NONE: return "\033[91m\033[1m[3] INCOMPATIBLE          \033[0m";
        default: return "\033[97m[?] UNKNOWN\033[0m";
    }
}
static const char *score_icon(int s) {
    switch (s) { case SCORE_FULL: return "\033[92m*\033[0m"; case SCORE_MINOR: return "\033[93mo\033[0m"; case SCORE_MAYBE: return "\033[38;5;208m.\033[0m"; case SCORE_NONE: return "\033[91mx\033[0m"; default: return "?"; }
}
static void print_header(Builder *b) {
    b_fmt(b, "\n%s%s================================================================\n%s", C_CYAN, C_BOLD, C_RESET);
    b_fmt(b, "%s%s   FreeBSD 15.1 Migration Compatibility Checker\n%s", C_CYAN, C_BOLD, C_RESET);
    b_fmt(b, "%s%s   Scanning this Linux system's hardware for FreeBSD readiness\n%s", C_CYAN, C_BOLD, C_RESET);
    b_fmt(b, "%s%s   Privilege mode: %s\n%s", C_CYAN, C_BOLD, sc0(SYS_geteuid) == 0 ? "root (optional elevated scan)" : "normal user (least privilege)", C_RESET);
    b_fmt(b, "%s%s================================================================\n%s\n", C_CYAN, C_BOLD, C_RESET);
}
static const char *g_categories[] = { "CPU", "Memory (RAM)", "Storage (Disk)", "Graphics (GPU)", "Networking", "Audio", "Firmware", "Secure Boot", "TPM", "Power / Battery", "Virtualization", "Online Data" };
static void print_percent_bar(Builder *b, uint64_t pct, unsigned width) {
    unsigned filled = (unsigned)((pct * width) / 1000); const char *color = pct >= 750 ? C_GREEN : pct >= 500 ? C_YELLOW : C_RED;
    b_fmt(b, "%s%s[", color, C_BOLD);
    for (unsigned i = 0; i < width; ++i) b_char(b, i < filled ? '#' : '-');
    b_str(b, "] "); b_pct_tenths(b, pct); b_str(b, C_RESET);
}
static char g_output[OUTPUT_CAP];
static char g_saved[REPORT_CAP];
static void render_console(CompatReport *r) {
    Builder b = { g_output, sizeof(g_output), 0 }; g_output[0] = 0;
    compute_report(r);
    b_fmt(&b, "\n%s%s================================================================\n%s", C_CYAN, C_BOLD, C_RESET);
    b_fmt(&b, "%s%s  DETAILED HARDWARE COMPATIBILITY REPORT\n%s", C_BOLD, C_WHITE, C_RESET);
    b_fmt(&b, "%s%s================================================================\n\n%s", C_CYAN, C_BOLD, C_RESET);
    for (unsigned c = 0; c < sizeof(g_categories) / sizeof(g_categories[0]); ++c) {
        bool header = false;
        for (unsigned i = 0; i < r->count; ++i) {
            CompatItem *it = &r->items[i]; if (!seq(it->category, g_categories[c])) continue;
            if (!header) { b_fmt(&b, "%s%s  -- %s\n%s", C_BLUE, C_BOLD, g_categories[c], C_RESET); header = true; }
            b_fmt(&b, "  |  %s  %s  %s\n", score_icon(it->score), score_label(it->score), it->name);
            b_fmt(&b, "  |     %s-> %s\n%s", C_DIM, it->detail, C_RESET);
            b_fmt(&b, "  |     %s%s\n%s", C_CYAN, it->recommendation, C_RESET);
            b_str(&b, "  |\n");
        }
    }
    b_fmt(&b, "\n%s%s================================================================\n%s", C_CYAN, C_BOLD, C_RESET);
    b_fmt(&b, "%s%s  SUMMARY\n%s", C_BOLD, C_WHITE, C_RESET);
    b_fmt(&b, "%s%s================================================================\n\n%s", C_CYAN, C_BOLD, C_RESET);
    b_fmt(&b, "  %s*%s  Fully compatible      : %u items\n", C_GREEN, C_RESET, r->score_counts[0]);
    b_fmt(&b, "  %so%s  Compatible (minor)    : %u items\n", C_YELLOW, C_RESET, r->score_counts[1]);
    b_fmt(&b, "  %s.%s  Maybe incompatible    : %u items\n", C_ORANGE, C_RESET, r->score_counts[2]);
    b_fmt(&b, "  %sx%s  Incompatible          : %u items\n", C_RED, C_RESET, r->score_counts[3]);
    b_str(&b, "\n  Overall compatibility score:\n  "); print_percent_bar(&b, r->overall_tenths, 40); b_str(&b, "\n\n");
    b_fmt(&b, "%s%s  OVERALL ASSESSMENT\n\n%s", C_BOLD, C_WHITE, C_RESET);
    if (r->overall_tenths >= 850) b_fmt(&b, "%s%s  READY: This system looks well-suited for FreeBSD 15.1.\n%s", C_GREEN, C_BOLD, C_RESET);
    else if (r->overall_tenths >= 650) b_fmt(&b, "%s%s  MOSTLY READY: Expect some manual driver/configuration work after install.\n%s", C_YELLOW, C_BOLD, C_RESET);
    else if (r->overall_tenths >= 400) b_fmt(&b, "%s%s  MODERATE: Several components may need workarounds. Test from a live/USB install first if possible.\n%s", C_ORANGE, C_BOLD, C_RESET);
    else b_fmt(&b, "%s%s  NOT RECOMMENDED YET: This hardware has significant compatibility gaps for a daily-driver FreeBSD install.\n%s", C_RED, C_BOLD, C_RESET);
    b_fmt(&b, "\n%s================================================================\n%s", C_CYAN, C_RESET);
    b_fmt(&b, "%s  FreeBSD 15.1 Migration Compatibility Checker\n%s", C_DIM, C_RESET);
    b_fmt(&b, "%s================================================================\n\n%s", C_CYAN, C_RESET);
    (void)write_all(1, g_output, b.len);
}
static void render_saved_report(CompatReport *r, const char *host, const char *sys, const char *release) {
    Builder b = { g_saved, sizeof(g_saved), 0 }; g_saved[0] = 0;
    b_str(&b, "FreeBSD 15.1 Migration Compatibility Checker -- Report\n");
    b_fmt(&b, "Hostname: %s\nCurrent kernel: %s %s\nPrivilege mode: %s\n\n", host, sys, release, sc0(SYS_geteuid) == 0 ? "root (optional elevated scan)" : "normal user (least privilege)");
    const char *score_text[] = { "[0] FULLY COMPATIBLE", "[1] COMPATIBLE (minor)", "[2] MAYBE INCOMPATIBLE", "[3] INCOMPATIBLE" };
    for (unsigned i = 0; i < r->count; ++i) {
        CompatItem *it = &r->items[i]; int s = it->score; if (s < 0 || s > 3) s = 2;
        b_fmt(&b, "%s  %s  %s\n  -> %s\n  %s\n\n", it->category, score_text[s], it->name, it->detail, it->recommendation);
    }
    b_str(&b, "Overall compatibility score: "); b_pct_tenths(&b, r->overall_tenths); b_char(&b, '\n');
    b_fmt(&b, "Fully compatible: %u | Compatible (minor): %u | Maybe incompatible: %u | Incompatible: %u\n", r->score_counts[0], r->score_counts[1], r->score_counts[2], r->score_counts[3]);
}

/* ----------------------- Entry point ----------------------- */
int main(int argc, char **argv) {
    char save_path[PATH_CAP] = "";
    for (int i = 1; i < argc; ++i) {
        if (seq(argv[i], "--help") || seq(argv[i], "-h")) {
            say("Usage: ./freebsd_compat_checker [--save REPORT.txt]\n"); return 0;
        }
        if (seq(argv[i], "--save")) {
            if (i + 1 >= argc) { say("error: --save requires a file path\n"); return 2; }
            copystr(save_path, sizeof(save_path), argv[++i]); continue;
        }
        Builder b = { g_output, sizeof(g_output), 0 }; g_output[0] = 0;
        b_fmt(&b, "error: unknown argument: %s\nUse --help for usage.\n", argv[i]); (void)write_all(2, g_output, b.len); return 2;
    }
    (void)sc1(SYS_uname, (long)&g_uts);
    Builder head = { g_output, sizeof(g_output), 0 }; g_output[0] = 0; print_header(&head);
    b_fmt(&head, "%s  Hostname       : %s\n%s", C_DIM, g_uts.nodename, C_RESET);
    b_fmt(&head, "%s  Current kernel : %s %s\n%s", C_DIM, g_uts.sysname, g_uts.release, C_RESET);
    if (sc0(SYS_geteuid) != 0) {
        b_fmt(&head, "%s  Note: running without root privileges. This is the recommended default.\n", C_DIM);
        b_fmt(&head, "%s        Restricted hardware/firmware nodes may be unavailable; such cases are reported as unknown.\n%s", C_DIM, C_RESET);
        b_fmt(&head, "%s        For a second pass only, you can re-run the same command with sudo.\n%s\n", C_CYAN, C_RESET);
    } else b_fmt(&head, "%s  Elevated scan: root privileges detected. Restricted readable nodes can be inspected.\n%s", C_GREEN, C_RESET);
    b_fmt(&head, "%s  Testing internet connectivity...\n%s", C_CYAN, C_RESET);
    (void)write_all(1, g_output, head.len);
    bool online = check_connectivity();
    say(online ? "              \033[92mOnline\033[0m\n\n" : "              \033[93mOffline\033[0m\n\n");

    analyze_cpu(&g_report);
    analyze_ram(&g_report);
    analyze_storage(&g_report);
    analyze_gpu(&g_report);
    analyze_network(&g_report);
    analyze_audio(&g_report);
    analyze_firmware(&g_report);
    analyze_secure_boot(&g_report);
    analyze_power(&g_report);
    analyze_virtualization(&g_report);
    analyze_online(&g_report, online);
    render_console(&g_report);
    compute_report(&g_report);

    if (save_path[0]) {
        render_saved_report(&g_report, g_uts.nodename, g_uts.sysname, g_uts.release);
        long fd = open_path(save_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd >= 0) {
            long wr = write_all((int)fd, g_saved, slen(g_saved)); close_fd(fd);
            if (wr >= 0) { Builder b = { g_output, sizeof(g_output), 0 }; g_output[0] = 0; b_fmt(&b, "\033[92m  Report saved to: %s\033[0m\n", save_path); (void)write_all(1, g_output, b.len); }
            else { say("\033[91m  Failed to save report: write error\033[0m\n"); }
        } else {
            Builder b = { g_output, sizeof(g_output), 0 }; g_output[0] = 0; b_fmt(&b, "\033[91m  Failed to save report to: %s\033[0m\n", save_path); (void)write_all(1, g_output, b.len);
        }
    }
    return 0;
}

/* Minimal ELF entry point; bypasses the C runtime and passes argc/argv. */
__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile(
        "xor %rbp, %rbp\n\t"
        "mov (%rsp), %rdi\n\t"
        "lea 8(%rsp), %rsi\n\t"
        "call main\n\t"
        "mov %eax, %edi\n\t"
        "mov $60, %eax\n\t"
        "syscall\n\t"
    );
}
