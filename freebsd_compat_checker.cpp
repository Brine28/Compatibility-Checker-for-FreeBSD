/*
 * FreeBSD 15.1 Migration Compatibility Checker
 * =============================================
 * Scans the current Linux system's hardware and configuration and produces
 * a scored report estimating how well it would work after migrating to
 * FreeBSD 15.1, based on the current state of FreeBSD's hardware support
 * (drm-kmod/i915kms for Intel graphics, nvidia-driver for NVIDIA, PipeWire
 * for Wayland screen capture, OSS/PipeWire for audio, etc.).
 *
 * This is a from-scratch Linux port of a similar Windows-to-Linux checker,
 * reusing the same scoring architecture but reading Linux's own sysfs/procfs
 * instead of the Win32 API, and scoring against FreeBSD 15.1 specifically
 * instead of Linux.
 *
 * Scores: 0=Fully Compatible | 1=Compatible (minor caveats)
 *         2=Possibly Incompatible | 3=Incompatible
 *
 * Usage:
 *   ./freebsd_compat_checker [--save report.txt]
 *
 * Privileges:
 *   Runs safely as a normal user. Root is optional and only used to improve
 *   access to restricted firmware/sysfs information; it is never required.
 *
 * Build:
 *   g++ -O2 -Wall -Wextra -std=c++20 freebsd_compat_checker.cpp \
 *       -o freebsd_compat_checker
 */

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <memory>
#include <poll.h>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;

/* ---- ANSI color codes ---- */
inline constexpr const char* RESET  = "\033[0m";
inline constexpr const char* BOLD   = "\033[1m";
inline constexpr const char* DIM    = "\033[2m";
inline constexpr const char* RED    = "\033[91m";
inline constexpr const char* GREEN  = "\033[92m";
inline constexpr const char* YELLOW = "\033[93m";
inline constexpr const char* BLUE   = "\033[94m";
inline constexpr const char* CYAN   = "\033[96m";
inline constexpr const char* WHITE  = "\033[97m";
inline constexpr const char* ORANGE = "\033[38;5;208m";

/* ---- Category name constants ---- */
inline constexpr std::string_view CAT_CPU    = "CPU";
inline constexpr std::string_view CAT_RAM    = "Memory (RAM)";
inline constexpr std::string_view CAT_DISK   = "Storage (Disk)";
inline constexpr std::string_view CAT_GPU    = "Graphics (GPU)";
inline constexpr std::string_view CAT_NET    = "Networking";
inline constexpr std::string_view CAT_AUDIO  = "Audio";
inline constexpr std::string_view CAT_FW     = "Firmware";
inline constexpr std::string_view CAT_SB     = "Secure Boot";
inline constexpr std::string_view CAT_TPM    = "TPM";
inline constexpr std::string_view CAT_POWER  = "Power / Battery";
inline constexpr std::string_view CAT_VIRT   = "Virtualization";
inline constexpr std::string_view CAT_ONLINE = "Online Data";

enum class CompatScore : int {
    FULL  = 0,
    MINOR = 1,
    MAYBE = 2,
    NONE  = 3
};

inline constexpr int MAX_DEVICES = 256;

struct CompatItem {
    std::string  name;
    std::string  category;
    std::string  detail;
    std::string  recommendation;
    CompatScore  score    = CompatScore::FULL;
    bool         critical = false;
};

class CompatReport {
public:
    std::vector<CompatItem>  items;
    std::array<int, 4>       score_counts{};
    double                   overall_percent = 0.0;

    [[nodiscard]] CompatItem* add_item() {
        if (static_cast<int>(items.size()) >= MAX_DEVICES)
            return nullptr;
        items.emplace_back();
        return &items.back();
    }

    void compute() {
        score_counts.fill(0);
        double weighted     = 0.0;
        double total_weight = 0.0;

        for (const auto& item : items) {
            int s = static_cast<int>(item.score);
            ++score_counts[s];
            double w       = item.critical ? 2.0 : 1.0;
            double contrib = (3.0 - static_cast<double>(s)) / 3.0;
            weighted      += contrib * w;
            total_weight  += w;
        }

        overall_percent = (total_weight > 0.0)
            ? (weighted / total_weight) * 100.0
            : 0.0;
    }
};

/* ---------------------------------------------------------------------
 * Small filesystem/text helpers -- everything here reads from sysfs/procfs,
 * no external hardware-enumeration commands (lspci/lsusb/etc.) are shelled out to.
 * ------------------------------------------------------------------- */
namespace SysFs {

    [[nodiscard]] inline std::string trim(std::string value) {
        auto not_space = [](unsigned char c) { return !std::isspace(c); };
        value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
        value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
        return value;
    }

    [[nodiscard]] inline std::optional<std::string> read_first_line(const fs::path& path) {
        std::ifstream in(path);
        if (!in) return std::nullopt;
        std::string line;
        if (!std::getline(in, line)) return std::nullopt;
        return trim(std::move(line));
    }

    [[nodiscard]] inline bool read_uint64(const fs::path& path, unsigned long long& value) {
        const auto line = read_first_line(path);
        if (!line) return false;
        try {
            size_t used = 0;
            const auto parsed = std::stoull(*line, &used, 10);
            if (used != line->size()) return false;
            value = parsed;
            return true;
        } catch (...) {
            return false;
        }
    }

    [[nodiscard]] inline std::string read_whole_file(const fs::path& path) {
        std::ifstream in(path);
        if (!in) return {};
        std::ostringstream ss;
        ss << in.rdbuf();
        return ss.str();
    }

    /* Reads a value like "MemTotal:  16384000 kB" style lines from /proc/meminfo. */
    [[nodiscard]] inline std::optional<unsigned long long> read_meminfo_kb(std::string_view key) {
        std::ifstream in("/proc/meminfo");
        if (!in) return std::nullopt;
        std::string line;
        while (std::getline(in, line)) {
            if (line.rfind(key, 0) == 0) {
                unsigned long long value = 0;
                std::istringstream iss(line.substr(key.size()));
                if (iss >> value) return value;
            }
        }
        return std::nullopt;
    }

    /* Resolves the driver name bound to a /sys/class/... device via its
     * 'driver' symlink, e.g. "iwlwifi", "r8169", "e1000e". */
    [[nodiscard]] inline std::optional<std::string> driver_name_for(const fs::path& device_dir) {
        std::error_code ec;
        fs::path link = device_dir / "driver";
        fs::path target = fs::read_symlink(link, ec);
        if (ec) return std::nullopt;
        return target.filename().string();
    }

} // namespace SysFs

/* =================================================================
 * Privilege helpers
 * ================================================================= */
namespace Privilege {
    [[nodiscard]] inline bool is_root() noexcept {
        return geteuid() == 0;
    }
}

/* =================================================================
 * Analyzer base class
 * ================================================================= */
class Analyzer {
public:
    virtual ~Analyzer() = default;
    virtual void analyze(CompatReport& report) = 0;

protected:
    [[nodiscard]] static CompatItem* new_item(CompatReport& r) { return r.add_item(); }
};

/* =================================================================
 * CPU
 * ================================================================= */
class CpuAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        std::string vendor;
        std::string model_name;
        unsigned int core_count = 0;

        std::ifstream in("/proc/cpuinfo");
        std::string line;
        while (std::getline(in, line)) {
            if (vendor.empty() && line.rfind("vendor_id", 0) == 0) {
                auto pos = line.find(':');
                if (pos != std::string::npos) vendor = SysFs::trim(line.substr(pos + 1));
            } else if (model_name.empty() && line.rfind("model name", 0) == 0) {
                auto pos = line.find(':');
                if (pos != std::string::npos) model_name = SysFs::trim(line.substr(pos + 1));
            } else if (line.rfind("processor", 0) == 0) {
                ++core_count;
            }
        }

        struct utsname uts{};
        uname(&uts);
        const std::string arch = uts.machine;

        CompatItem* itp = new_item(report);
        if (!itp) return;
        CompatItem& it = *itp;
        it.category = std::string(CAT_CPU);
        it.name     = !model_name.empty() ? model_name : (vendor.empty() ? arch : vendor);
        it.critical = true;

        const bool is_x86_64 = (arch == "x86_64");
        const bool is_intel  = vendor.find("GenuineIntel") != std::string::npos;
        const bool is_amd    = vendor.find("AuthenticAMD") != std::string::npos;

        if (is_x86_64 && (is_intel || is_amd)) {
            it.score = CompatScore::FULL;
            it.detail = std::format("{} | {} logical cores | architecture: {}",
                                    is_intel ? "Intel" : "AMD", core_count, arch);
            it.recommendation = "FreeBSD 15.1 has mature, first-class support for x86_64. "
                                 "No CPU-related migration concerns expected.";
        } else if (arch.rfind("aarch64", 0) == 0 || arch.rfind("arm", 0) == 0) {
            it.score = CompatScore::MAYBE;
            it.detail = std::format("ARM architecture detected: {} | {} logical cores", arch, core_count);
            it.recommendation = "FreeBSD's ARM64 (aarch64) support exists but is considerably "
                                 "less mature than its x86_64 support. Expect missing packages "
                                 "and rougher edges on ARM hardware.";
        } else {
            it.score = CompatScore::MAYBE;
            it.detail = std::format("Uncommon architecture: {} | vendor: {}", arch, vendor);
            it.recommendation = "This architecture is not among FreeBSD's primary supported "
                                 "targets. Check the FreeBSD Handbook for current platform support "
                                 "before migrating.";
        }
    }
};

/* =================================================================
 * RAM
 * ================================================================= */
class RamAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        const auto total_kb = SysFs::read_meminfo_kb("MemTotal:").value_or(0);
        const unsigned long long total_mb = total_kb / 1024;
        const unsigned long long total_gb = total_mb / 1024;

        CompatItem* itp = new_item(report);
        if (!itp) return;
        CompatItem& it = *itp;
        it.category = std::string(CAT_RAM);
        it.name     = std::format("System memory: {} MB ({} GB)", total_mb, total_gb);
        it.critical = true;

        if (total_mb < 2048) {
            it.score  = CompatScore::NONE;
            it.detail = std::format("Only {} MB RAM detected -- FreeBSD desktop use (KDE Plasma, "
                                    "GNOME) generally wants at least 2-4 GB.", total_mb);
            it.recommendation = "Consider a lightweight window manager instead of a full desktop "
                                 "environment, or add more RAM before migrating.";
        } else if (total_mb < 4096) {
            it.score  = CompatScore::MINOR;
            it.detail = std::format("{} MB RAM -- sufficient for basic desktop use.", total_mb);
            it.recommendation = "A lightweight desktop (Xfce, LXQt) will feel more comfortable "
                                 "than KDE Plasma or GNOME at this memory size.";
        } else {
            it.score  = CompatScore::FULL;
            it.detail = std::format("{} MB ({} GB) RAM -- comfortable for any desktop environment.",
                                    total_mb, total_gb);
            it.recommendation = "No memory-related migration concerns.";
        }
    }
};

/* =================================================================
 * Storage
 * ================================================================= */
class StorageAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        struct statvfs vfs{};
        unsigned long long total_gb = 0, free_gb = 0;
        if (statvfs("/", &vfs) == 0) {
            const unsigned long long block = vfs.f_frsize ? vfs.f_frsize : vfs.f_bsize;
            total_gb = (static_cast<unsigned long long>(vfs.f_blocks) * block)
                     / (1024ULL * 1024 * 1024);
            free_gb  = (static_cast<unsigned long long>(vfs.f_bavail) * block)
                     / (1024ULL * 1024 * 1024);
        }

        std::string root_device;
        {
            std::ifstream mounts("/proc/self/mountinfo");
            std::string line;
            while (std::getline(mounts, line)) {
                std::istringstream iss(line);
                std::vector<std::string> fields;
                std::string field;
                while (iss >> field)
                    fields.push_back(field);

                const auto sep = std::find(fields.begin(), fields.end(), "-");
                if (sep == fields.end() || sep + 2 >= fields.end())
                    continue;

                // Mount point is field 5 (1-based) in /proc/self/mountinfo.
                if (fields.size() > 4 && fields[4] == "/") {
                    root_device = *(sep + 2); // fs type, source, super options
                    break;
                }
            }
        }

        bool is_ssd = false;
        bool is_nvme = false;
        bool direct_block_device = false;
        std::string base;

        if (!root_device.empty() && root_device.rfind("/dev/", 0) == 0) {
            base = fs::path(root_device).filename().string();

            if (base.rfind("nvme", 0) == 0) {
                const auto p_pos = base.find('p');
                if (p_pos != std::string::npos && p_pos > 0)
                    base = base.substr(0, p_pos);
                is_nvme = true;
            } else if (base.rfind("mmcblk", 0) == 0) {
                const auto p_pos = base.find('p');
                if (p_pos != std::string::npos && p_pos > 0)
                    base = base.substr(0, p_pos);
            } else {
                while (!base.empty() && std::isdigit(static_cast<unsigned char>(base.back())))
                    base.pop_back();
            }

            direct_block_device = fs::exists("/sys/block/" + base + "/queue/rotational");
        }

        if (direct_block_device) {
            const auto rot = SysFs::read_first_line("/sys/block/" + base + "/queue/rotational");
            is_ssd = rot && *rot == "0";
        }

        unsigned long long disk_sectors = 0;
        unsigned long long largest_gap_sectors = 0;
        bool unallocated_known = false;

        if (direct_block_device &&
            SysFs::read_uint64("/sys/block/" + base + "/size", disk_sectors)) {
            struct PartitionRange {
                unsigned long long start{};
                unsigned long long size{};
            };
            std::vector<PartitionRange> parts;

            std::error_code ec;
            const fs::path block_dir = "/sys/block/" + base;
            for (const auto& entry : fs::directory_iterator(block_dir, ec)) {
                if (ec) break;
                if (!fs::exists(entry.path() / "partition", ec))
                    continue;

                unsigned long long start_sector = 0;
                unsigned long long size_sector = 0;
                if (SysFs::read_uint64(entry.path() / "start", start_sector) &&
                    SysFs::read_uint64(entry.path() / "size", size_sector) &&
                    start_sector < disk_sectors) {
                    const auto clipped = std::min(size_sector, disk_sectors - start_sector);
                    if (clipped)
                        parts.push_back({start_sector, clipped});
                }
            }

            std::sort(parts.begin(), parts.end(),
                      [](const PartitionRange& a, const PartitionRange& b) {
                          return a.start < b.start;
                      });

            unsigned long long cursor = 0;
            for (const auto& part : parts) {
                if (part.start > cursor)
                    largest_gap_sectors = std::max(largest_gap_sectors, part.start - cursor);
                cursor = std::max(cursor, part.start + part.size);
            }
            if (cursor < disk_sectors)
                largest_gap_sectors = std::max(largest_gap_sectors, disk_sectors - cursor);

            unallocated_known = true;
        }

        const unsigned long long largest_gap_gb =
            largest_gap_sectors / (1024ULL * 1024 * 2); // 512-byte sectors -> GiB

        const char* drive_type =
            is_nvme ? "NVMe SSD" : is_ssd ? "SSD" : direct_block_device ? "Rotational (HDD)" : "Unknown";

        CompatItem* itp = new_item(report);
        if (!itp) return;
        CompatItem& it = *itp;
        it.category = std::string(CAT_DISK);
        it.critical = true;
        it.name = std::format("Storage: root FS {} GB total / {} GB free [{}]",
                              total_gb, free_gb, drive_type);

        if (unallocated_known) {
            it.detail = std::format(
                "Largest unpartitioned gap on the backing disk: {} GB. "
                "Root filesystem free space is {} GB and is NOT counted as installable unallocated space.",
                largest_gap_gb, free_gb);

            if (largest_gap_gb >= 50) {
                it.score = CompatScore::FULL;
                it.recommendation =
                    "At least 50 GiB of unpartitioned space is visible for a comfortable FreeBSD "
                    "desktop installation. The storage device itself is suitable.";
            } else if (largest_gap_gb >= 20) {
                it.score = CompatScore::MINOR;
                it.recommendation =
                    "At least 20 GiB of unpartitioned space is visible, so a basic FreeBSD "
                    "installation is plausible; 50+ GiB is preferable for a full desktop.";
            } else {
                it.score = CompatScore::NONE;
                it.recommendation =
                    "No 20+ GiB unpartitioned gap was detected. Shrink/create a partition or use "
                    "another disk before treating this machine as installation-ready. "
                    "Filesystem free space is not the same as partition-free space.";
            }
        } else {
            it.score = CompatScore::MAYBE;
            it.detail = std::format(
                "Root filesystem reports {} GB free, but unpartitioned disk space could not be "
                "safely determined (backing device: {}).",
                free_gb, root_device.empty() ? "unknown" : root_device);
            it.recommendation =
                "Check the partition table manually before installing FreeBSD. LVM, dm-crypt, "
                "RAID, and other layered storage need separate inspection.";
        }
    }
};

/* =================================================================
 * GPU
 * ================================================================= */
class GpuAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        bool found = false;
        int gpu_count = 0;

        if (!fs::exists("/sys/bus/pci/devices"))
            return;

        for (const auto& entry : fs::directory_iterator("/sys/bus/pci/devices")) {
            const auto class_str = SysFs::read_first_line(entry.path() / "class");
            if (!class_str || class_str->rfind("0x03", 0) != 0)
                continue;

            const auto vendor_str = SysFs::read_first_line(entry.path() / "vendor").value_or("");
            const auto device_str = SysFs::read_first_line(entry.path() / "device").value_or("");
            const auto driver = SysFs::driver_name_for(entry.path()).value_or("unbound");

            found = true;
            ++gpu_count;

            CompatItem* itp = new_item(report);
            if (!itp) return;
            CompatItem& it = *itp;
            it.category = std::string(CAT_GPU);
            it.critical = true;

            const bool is_intel  = vendor_str == "0x8086";
            const bool is_amd    = vendor_str == "0x1002";
            const bool is_nvidia = vendor_str == "0x10de";

            it.name = std::format("PCI display controller [{}:{}] (Linux driver: {})",
                                  vendor_str, device_str, driver);

            if (is_intel) {
                it.score = CompatScore::MINOR;
                it.detail = "Intel graphics device detected.";
                it.recommendation =
                    "FreeBSD 15.1 uses drm-kmod/i915kms for supported Intel generations. "
                    "FreeBSD's current DRM status notes that i915 still has instabilities, so "
                    "this should be treated as supported but not risk-free. Verify the exact GPU "
                    "ID and required firmware before migrating.";
            } else if (is_amd) {
                it.score = CompatScore::MINOR;
                it.detail = "AMD graphics device detected.";
                it.recommendation =
                    "FreeBSD provides amdgpu through drm-kmod. Exact GPU generation should be "
                    "checked against the current FreeBSD graphics support matrix.";
            } else if (is_nvidia) {
                it.score = CompatScore::MAYBE;
                it.detail = "NVIDIA graphics device detected.";
                it.recommendation =
                    "FreeBSD's NVIDIA stack is proprietary. The current Handbook says the NVIDIA "
                    "driver can work with many wlroots compositors but may be unstable and may "
                    "lack some features. On hybrid laptops, using the supported integrated GPU "
                    "as the primary desktop GPU is the lower-risk approach.";
            } else {
                it.score = CompatScore::MAYBE;
                it.detail = "Unrecognized PCI display vendor.";
                it.recommendation =
                    "Check the exact PCI device against FreeBSD's current graphics support before migrating.";
            }
        }

        if (!found) {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            itp->category = std::string(CAT_GPU);
            itp->name = "No PCI display controller found";
            itp->critical = true;
            itp->score = CompatScore::MAYBE;
            itp->detail = "Could not enumerate a display controller via /sys/bus/pci/devices.";
            itp->recommendation =
                "This may be a virtual machine or an unusual setup; verify manually.";
        } else if (gpu_count > 1) {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            itp->category = std::string(CAT_GPU);
            itp->name = std::format("Hybrid/multi-GPU system: {} display controllers", gpu_count);
            itp->critical = false;
            itp->score = CompatScore::MINOR;
            itp->detail =
                "Multiple display controllers were detected. Linux GPU-driver bindings do not "
                "guarantee identical offload, power-management, or suspend behavior on FreeBSD.";
            itp->recommendation =
                "Validate the primary GPU first, then test graphics offload and suspend/resume separately.";
        }
    }
};

/* =================================================================
 * Networking
 * ================================================================= */
class NetworkAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        bool found = false;

        if (!fs::exists("/sys/class/net")) return;

        for (const auto& entry : fs::directory_iterator("/sys/class/net")) {
            const std::string iface = entry.path().filename().string();
            if (iface == "lo") continue;

            const fs::path device_dir = entry.path() / "device";
            if (!fs::exists(device_dir)) continue;

            const auto driver = SysFs::driver_name_for(device_dir).value_or("unknown");
            const bool is_wireless = fs::exists(entry.path() / "wireless")
                                   || fs::exists(entry.path() / "phy80211");

            found = true;
            CompatItem* itp = new_item(report);
            if (!itp) return;
            CompatItem& it = *itp;
            it.category = std::string(CAT_NET);
            it.name     = std::format("{} ({}, driver: {})", iface, is_wireless ? "Wi-Fi" : "Ethernet", driver);

            const bool is_iwlwifi   = driver.find("iwlwifi") != std::string::npos || driver.find("iwl") != std::string::npos;
            const bool is_intel_eth = driver.find("e1000") != std::string::npos || driver.find("igb") != std::string::npos || driver.find("igc") != std::string::npos || driver.find("ice") != std::string::npos || driver.find("ixgbe") != std::string::npos;
            const bool is_realtek   = driver.find("rtw") != std::string::npos || driver.find("r8169") != std::string::npos || driver.find("r8168") != std::string::npos;
            const bool is_atheros   = driver.find("ath") != std::string::npos;
            const bool is_mediatek  = driver.find("mt7") != std::string::npos || driver.find("mt76") != std::string::npos;
            const bool is_broadcom  = driver.find("brcm") != std::string::npos || driver.find("bnx") != std::string::npos || driver.find("tg3") != std::string::npos;

            if (is_intel_eth) {
                it.score  = CompatScore::FULL;
                it.detail = "Intel wired Ethernet controller.";
                it.recommendation = "Well supported via FreeBSD's em(4)/igb(4)/ix(4) drivers.";
            } else if (is_iwlwifi) {
                it.score  = CompatScore::MINOR;
                it.detail = "Intel Wi-Fi adapter (Linux driver: iwlwifi).";
                it.recommendation = "FreeBSD's iwlwifi(4) port supports many Intel Wi-Fi chips, but "
                                     "firmware/chip support can lag behind Linux for the newest cards. "
                                     "Check the FreeBSD wiki's supported-chipset list for your exact model.";
            } else if (is_atheros) {
                it.score  = CompatScore::FULL;
                it.detail = "Atheros Wi-Fi adapter.";
                it.recommendation = "Atheros chips (ath(4)) have a long history of solid, mature support on FreeBSD.";
            } else if (is_realtek) {
                it.score  = CompatScore::MAYBE;
                it.detail = std::format("Realtek {} adapter.", is_wireless ? "Wi-Fi" : "Ethernet");
                it.recommendation = is_wireless
                    ? "Realtek Wi-Fi chip support on FreeBSD is inconsistent; many newer chips have no driver at all. Verify your exact chip before migrating."
                    : "Realtek Ethernet (re(4)) generally works but has historically been less robust than Intel's drivers.";
            } else if (is_mediatek) {
                it.score  = CompatScore::MAYBE;
                it.detail = "MediaTek Wi-Fi adapter.";
                it.recommendation = "MediaTek Wi-Fi support on FreeBSD is limited compared to Linux's mt76 driver. Verify chip-specific support before migrating.";
            } else if (is_broadcom) {
                it.score  = CompatScore::MAYBE;
                it.detail = std::format("Broadcom {} adapter.", is_wireless ? "Wi-Fi" : "Ethernet");
                it.recommendation = "Broadcom devices are frequently problematic on FreeBSD; a USB Ethernet adapter as backup is a reasonable precaution.";
            } else {
                it.score  = CompatScore::MAYBE;
                it.detail = std::format("Unrecognized {} driver: {}", is_wireless ? "Wi-Fi" : "network", driver);
                it.recommendation = "Search the FreeBSD Handbook's hardware notes or the forums for this specific chipset.";
            }
        }

        if (!found) {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            itp->category       = std::string(CAT_NET);
            itp->name           = "No physical network adapters found";
            itp->critical       = false;
            itp->score          = CompatScore::MAYBE;
            itp->detail         = "Could not enumerate any non-loopback network device with a backing driver.";
            itp->recommendation = "Verify manually; this may be a container or unusual environment.";
        }
    }
};

/* =================================================================
 * Audio
 * ================================================================= */
class AudioAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        std::ifstream cards("/proc/asound/cards");
        if (!cards) {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            itp->category       = std::string(CAT_AUDIO);
            itp->name           = "No ALSA sound cards found";
            itp->critical       = false;
            itp->score          = CompatScore::MAYBE;
            itp->detail         = "Could not read /proc/asound/cards.";
            itp->recommendation = "Verify your sound hardware manually.";
            return;
        }

        std::string line;
        bool found = false;
        while (std::getline(cards, line)) {
            if (line.find(':') == std::string::npos) continue;
            auto namePos = line.find(':');
            if (namePos == std::string::npos) continue;

            std::string desc = line.substr(namePos + 1);
            while (!desc.empty() && desc.front() == ' ') desc.erase(desc.begin());

            found = true;
            CompatItem* itp = new_item(report);
            if (!itp) return;
            CompatItem& it = *itp;
            it.category = std::string(CAT_AUDIO);
            it.name     = desc;
            it.critical = false;

            const bool is_hda = desc.find("HDA") != std::string::npos;

            if (is_hda) {
                it.score  = CompatScore::MINOR;
                it.detail = "Standard HD Audio (HDA) codec.";
                it.recommendation = "FreeBSD's native sound(4)/hdac(4) driver generally handles HDA "
                                     "audio, but community reports describe FreeBSD's audio stack as "
                                     "still rough around the edges compared to Linux's ALSA/PipeWire "
                                     "maturity. Installing pipewire + wireplumber on FreeBSD is "
                                     "recommended for a more modern experience, and is required "
                                     "specifically for Wayland screen capture (Spectacle, screen "
                                     "sharing), not just audio.";
            } else {
                it.score  = CompatScore::MAYBE;
                it.detail = "Non-HDA audio device.";
                it.recommendation = "Check FreeBSD's sound(4) man page for explicit support of this device.";
            }
        }

        if (!found) {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            itp->category       = std::string(CAT_AUDIO);
            itp->name           = "No sound cards enumerated";
            itp->critical       = false;
            itp->score          = CompatScore::MAYBE;
            itp->detail         = "/proc/asound/cards was empty or unreadable.";
            itp->recommendation = "Verify your sound hardware manually.";
        }
    }
};

/* =================================================================
 * Firmware (UEFI/BIOS, TPM)
 * ================================================================= */
class SecureBootAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        CompatItem* itp = new_item(report);
        if (!itp) return;

        CompatItem& it = *itp;
        it.category = std::string(CAT_SB);
        it.critical = false;

        if (!fs::exists("/sys/firmware/efi")) {
            it.name = "Secure Boot: not applicable (legacy BIOS)";
            it.score = CompatScore::FULL;
            it.detail = "The system was not booted through UEFI.";
            it.recommendation = "Secure Boot is informational here and is not a migration blocker.";
            return;
        }

        std::optional<bool> enabled;
        const fs::path efivars = "/sys/firmware/efi/efivars";
        std::error_code ec;
        if (fs::exists(efivars, ec)) {
            for (const auto& entry : fs::directory_iterator(efivars, ec)) {
                if (ec) break;

                const auto filename = entry.path().filename().string();
                if (filename.rfind("SecureBoot-", 0) != 0)
                    continue;

                std::ifstream in(entry.path(), std::ios::binary);
                if (!in) break;

                std::array<unsigned char, 5> header_and_value{};
                in.read(reinterpret_cast<char*>(header_and_value.data()),
                        static_cast<std::streamsize>(header_and_value.size()));
                if (in.gcount() >= 5)
                    enabled = header_and_value[4] != 0;
                break;
            }
        }

        it.score = CompatScore::FULL;
        if (enabled) {
            it.name = std::format("Secure Boot: {}", *enabled ? "enabled" : "disabled");
            it.detail = "UEFI Secure Boot state was read from efivarfs.";
        } else {
            it.name = "Secure Boot: state unavailable";
            it.detail = "UEFI was detected, but the SecureBoot EFI variable could not be read.";
        }
        it.recommendation =
            "Secure Boot is treated as informational by this scanner rather than as a hardware "
            "compatibility score.";
    }
};

class FirmwareAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        const bool is_uefi = fs::exists("/sys/firmware/efi");
        const bool has_tpm = fs::exists("/sys/class/tpm/tpm0") || fs::exists("/dev/tpm0");

        {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            CompatItem& it = *itp;
            it.category = std::string(CAT_FW);
            it.name     = std::format("Boot type: {}", is_uefi ? "UEFI" : "Legacy BIOS");
            it.critical = true;

            if (is_uefi) {
                it.score  = CompatScore::FULL;
                it.detail = "UEFI boot environment detected.";
                it.recommendation = "FreeBSD 15.1 installs and boots cleanly in UEFI mode. "
                                     "Make sure to select the UEFI installer image.";
            } else {
                it.score  = CompatScore::MINOR;
                it.detail = "Legacy BIOS boot environment detected.";
                it.recommendation = "FreeBSD still supports legacy BIOS boot, but UEFI is the "
                                     "better-tested, more actively maintained path.";
            }
        }

        {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            CompatItem& it = *itp;
            it.category = std::string(CAT_TPM);
            it.name     = std::format("Trusted Platform Module (TPM): {}", has_tpm ? "Present" : "Not detected");
            it.critical = false;
            it.score    = CompatScore::FULL;
            it.detail   = has_tpm ? "TPM device node found." : "No TPM device detected.";
            it.recommendation = "TPM is not a hard requirement for FreeBSD; it can optionally be "
                                 "used for disk encryption key storage if desired.";
        }
    }
};

/* =================================================================
 * Power / Battery
 * ================================================================= */
class PowerAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        if (!fs::exists("/sys/class/power_supply")) return;

        for (const auto& entry : fs::directory_iterator("/sys/class/power_supply")) {
            const std::string name = entry.path().filename().string();
            if (name.rfind("BAT", 0) != 0) continue;

            const auto capacity = SysFs::read_first_line(entry.path() / "capacity").value_or("?");
            const auto status   = SysFs::read_first_line(entry.path() / "status").value_or("Unknown");

            CompatItem* itp = new_item(report);
            if (!itp) return;
            CompatItem& it = *itp;
            it.category = std::string(CAT_POWER);
            it.name     = std::format("Battery {}: {}%  |  Status: {}", name, capacity, status);
            it.critical = false;
            it.score    = CompatScore::MINOR;
            it.detail   = "A laptop battery was detected. Power management on FreeBSD differs "
                          "from Linux's kernel power framework.";
            it.recommendation = "Install powerd(8) (built into base) for basic CPU frequency "
                                 "scaling, and check acpi_video(4)/backlight support for your "
                                 "specific laptop model, since brightness-key behavior can vary.";
            return;
        }
    }
};

/* =================================================================
 * Virtualization (are we already inside a VM?)
 * ================================================================= */
class VirtualizationAnalyzer : public Analyzer {
public:
    void analyze(CompatReport& report) override {
        std::ifstream cpuinfo("/proc/cpuinfo");
        std::string line;
        bool hypervisor_flag = false;
        while (std::getline(cpuinfo, line)) {
            if (line.rfind("flags", 0) == 0 && line.find("hypervisor") != std::string::npos) {
                hypervisor_flag = true;
                break;
            }
        }
        if (!hypervisor_flag) return;

        const auto product = SysFs::read_first_line("/sys/class/dmi/id/product_name").value_or("Unknown");

        CompatItem* itp = new_item(report);
        if (!itp) return;
        CompatItem& it    = *itp;
        it.category       = std::string(CAT_VIRT);
        it.name           = std::format("Running inside a virtual machine ({})", product);
        it.critical       = false;
        it.score          = CompatScore::MINOR;
        it.detail         = "The CPU's hypervisor flag is set, meaning this scan itself is running inside a VM.";
        it.recommendation = "Results here reflect the virtual hardware, not physical hardware. "
                             "FreeBSD generally runs very well as a guest OS (bhyve, VirtualBox, "
                             "VMware, QEMU/KVM all have good support), but re-run this tool on "
                             "physical hardware for an accurate assessment of a bare-metal install.";
    }
};

/* =================================================================
 * Online connectivity check (plain TCP, no TLS dependency)
 * ================================================================= */
class OnlineAnalyzer : public Analyzer {
public:
    explicit OnlineAnalyzer(bool online) : m_online(online) {}

    void analyze(CompatReport& report) override {
        CompatItem* itp = new_item(report);
        if (!itp) return;
        CompatItem& it = *itp;
        it.category = std::string(CAT_ONLINE);
        it.name     = m_online ? "External network reachability: detected" : "External network reachability: not detected";
        it.critical = false;

        if (m_online) {
            it.score  = CompatScore::FULL;
            it.detail = "At least one external IPv4 TCP/443 endpoint accepted a connection.";
            it.recommendation = "This only verifies basic outbound reachability. DNS, HTTPS, captive portals, "
                                 "firewalls, and package-repository access still need to be tested after installation.";
        } else {
            it.score  = CompatScore::MINOR;
            it.detail = "No tested external IPv4 TCP/443 endpoint could be reached right now.";
            it.recommendation = "The network may be filtered, offline, or temporarily unavailable. "
                                 "This result alone is not a FreeBSD hardware-compatibility failure.";
        }
    }

private:
    bool m_online;
};

/* ---------------------------------------------------------------------
 * A minimal, dependency-free connectivity probe: plain TCP connect to a
 * well-known DNS resolver on port 53. No HTTP/TLS parsing involved, so
 * this needs no external libraries.
 * ------------------------------------------------------------------- */
static bool ConnectWithTimeout(const char* ip, uint16_t port, int timeout_ms) {
    const int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    const int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(sock);
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(sock);
        return false;
    }

    const int rc = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (rc == 0) {
        close(sock);
        return true;
    }
    if (errno != EINPROGRESS) {
        close(sock);
        return false;
    }

    pollfd pfd{};
    pfd.fd = sock;
    pfd.events = POLLOUT;
    if (poll(&pfd, 1, timeout_ms) <= 0) {
        close(sock);
        return false;
    }

    int so_error = 0;
    socklen_t so_error_len = sizeof(so_error);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) < 0) {
        close(sock);
        return false;
    }

    close(sock);
    return so_error == 0;
}

static bool CheckInternetConnectivity() {
    // Best-effort external reachability test. TCP/443 is more representative than TCP/53
    // because DNS port 53 is frequently filtered independently of general connectivity.
    constexpr std::array targets{
        std::pair{"1.1.1.1", uint16_t{443}},
        std::pair{"8.8.8.8", uint16_t{443}},
        std::pair{"9.9.9.9", uint16_t{443}}
    };

    for (const auto& [ip, port] : targets) {
        if (ConnectWithTimeout(ip, port, 2000))
            return true;
    }
    return false;
}

/* =================================================================
 * Console helpers
 * ================================================================= */
namespace Console {

    inline void print_header() {
        printf("\n");
        printf("%s%s================================================================\n%s", CYAN, BOLD, RESET);
        printf("%s%s   FreeBSD 15.1 Migration Compatibility Checker\n%s", CYAN, BOLD, RESET);
        printf("%s%s   Privilege mode: %s\n%s", CYAN, BOLD,
               Privilege::is_root() ? "root (optional elevated scan)" : "normal user (least privilege)", RESET);
        printf("%s%s   Scanning this Linux system's hardware for FreeBSD readiness\n%s", CYAN, BOLD, RESET);
        printf("%s%s================================================================\n%s", CYAN, BOLD, RESET);
        printf("\n");
    }

    [[nodiscard]] inline const char* score_label(CompatScore s) noexcept {
        switch (s) {
            case CompatScore::FULL:  return "\033[92m\033[1m[0] FULLY COMPATIBLE      \033[0m";
            case CompatScore::MINOR: return "\033[93m\033[1m[1] COMPATIBLE (minor)    \033[0m";
            case CompatScore::MAYBE: return "\033[38;5;208m\033[1m[2] MAYBE INCOMPATIBLE    \033[0m";
            case CompatScore::NONE:  return "\033[91m\033[1m[3] INCOMPATIBLE          \033[0m";
        }
        return "\033[97m[?] UNKNOWN\033[0m";
    }

    [[nodiscard]] inline const char* score_icon(CompatScore s) noexcept {
        switch (s) {
            case CompatScore::FULL:  return "\033[92m*\033[0m";
            case CompatScore::MINOR: return "\033[93mo\033[0m";
            case CompatScore::MAYBE: return "\033[38;5;208m.\033[0m";
            case CompatScore::NONE:  return "\033[91mx\033[0m";
        }
        return "\033[97m?\033[0m";
    }

    inline void print_percent_bar(double pct, int width) {
        int         filled = static_cast<int>(pct / 100.0 * static_cast<double>(width));
        const char* color  = (pct >= 75.0) ? GREEN : (pct >= 50.0) ? YELLOW : RED;
        printf("%s%s[", color, BOLD);
        for (int i = 0; i < width; i++)
            printf(i < filled ? "#" : "-");
        printf("] %.1f%%%s", pct, RESET);
    }

} // namespace Console

/* =================================================================
 * Report printer
 * ================================================================= */
class ReportPrinter {
public:
    void print(CompatReport& report) {
        report.compute();

        printf("\n%s%s================================================================\n%s", CYAN, BOLD, RESET);
        printf("%s%s  DETAILED HARDWARE COMPATIBILITY REPORT\n%s", BOLD, WHITE, RESET);
        printf("%s%s================================================================\n\n%s", CYAN, BOLD, RESET);

        constexpr std::array categories{
            CAT_CPU, CAT_RAM, CAT_DISK, CAT_GPU, CAT_NET,
            CAT_AUDIO, CAT_FW, CAT_SB, CAT_TPM, CAT_POWER, CAT_VIRT,
            CAT_ONLINE
        };

        for (const auto& cat : categories) {
            bool header_printed = false;
            for (const auto& it : report.items) {
                if (it.category != cat) continue;
                if (!header_printed) {
                    printf("%s%s  -- %.*s\n%s", BLUE, BOLD, static_cast<int>(cat.size()), cat.data(), RESET);
                    header_printed = true;
                }
                printf("  |  %s  %s  %s\n", Console::score_icon(it.score), Console::score_label(it.score), it.name.c_str());
                printf("  |     %s-> %s\n%s", DIM, it.detail.c_str(), RESET);
                printf("  |     %s%s\n%s", CYAN, it.recommendation.c_str(), RESET);
                printf("  |\n");
            }
        }

        printf("\n%s%s================================================================\n%s", CYAN, BOLD, RESET);
        printf("%s%s  SUMMARY\n%s", BOLD, WHITE, RESET);
        printf("%s%s================================================================\n\n%s", CYAN, BOLD, RESET);

        printf("  %s*%s  Fully compatible      : %d items\n", GREEN,  RESET, report.score_counts[0]);
        printf("  %so%s  Compatible (minor)    : %d items\n", YELLOW, RESET, report.score_counts[1]);
        printf("  %s.%s  Maybe incompatible    : %d items\n", ORANGE, RESET, report.score_counts[2]);
        printf("  %sx%s  Incompatible          : %d items\n", RED,    RESET, report.score_counts[3]);
        printf("\n  Overall compatibility score:\n  ");
        Console::print_percent_bar(report.overall_percent, 40);
        printf("\n\n");

        printf("%s%s  OVERALL ASSESSMENT\n\n%s", BOLD, WHITE, RESET);
        if (report.overall_percent >= 85.0) {
            printf("%s%s  READY: This system looks well-suited for FreeBSD 15.1.\n%s", GREEN, BOLD, RESET);
        } else if (report.overall_percent >= 65.0) {
            printf("%s%s  MOSTLY READY: Expect some manual driver/configuration work after install.\n%s", YELLOW, BOLD, RESET);
        } else if (report.overall_percent >= 40.0) {
            printf("%s%s  MODERATE: Several components may need workarounds. Test from a live/USB install first if possible.\n%s", ORANGE, BOLD, RESET);
        } else {
            printf("%s%s  NOT RECOMMENDED YET: This hardware has significant compatibility gaps for a daily-driver FreeBSD install.\n%s", RED, BOLD, RESET);
        }

        printf("\n%s================================================================\n%s", CYAN, RESET);
        printf("%s  FreeBSD 15.1 Migration Compatibility Checker\n%s", DIM, RESET);
        printf("%s================================================================\n\n%s", CYAN, RESET);
    }
};

/* =================================================================
 * Entry point
 * ================================================================= */
int main(int argc, char* argv[]) {
    std::string save_path;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);

        if (arg == "--help" || arg == "-h") {
            printf("Usage: %s [--save REPORT.txt]\n", argv[0]);
            return 0;
        }

        if (arg == "--save") {
            if (i + 1 >= argc) {
                fprintf(stderr, "error: --save requires a file path\n");
                return 2;
            }
            save_path = argv[++i];
            continue;
        }

        fprintf(stderr, "error: unknown argument: %s\n", argv[i]);
        fprintf(stderr, "Use --help for usage.\n");
        return 2;
    }

    Console::print_header();

    struct utsname uts{};
    uname(&uts);
    printf("%s  Hostname       : %s\n%s", DIM, uts.nodename, RESET);
    printf("%s  Current kernel : %s %s\n%s", DIM, uts.sysname, uts.release, RESET);

    if (!Privilege::is_root()) {
        printf("%s  Note: running without root privileges. This is the recommended default.\n", DIM);
        printf("%s        Restricted hardware/firmware nodes may be unavailable; such cases are reported as unknown.\n%s", DIM, RESET);
        printf("%s        For a second pass only, you can re-run the same command with sudo.\n%s\n", CYAN, RESET);
    } else {
        printf("%s  Elevated scan: root privileges detected. Restricted readable nodes can be inspected.\n%s", GREEN, RESET);
    }

    printf("%s  Testing internet connectivity...\n%s", CYAN, RESET);
    const bool g_online = CheckInternetConnectivity();
    printf("              %s%s%s\n\n", g_online ? GREEN : YELLOW, g_online ? "Online" : "Offline", RESET);

    std::vector<std::unique_ptr<Analyzer>> analyzers;
    analyzers.push_back(std::make_unique<CpuAnalyzer>());
    analyzers.push_back(std::make_unique<RamAnalyzer>());
    analyzers.push_back(std::make_unique<StorageAnalyzer>());
    analyzers.push_back(std::make_unique<GpuAnalyzer>());
    analyzers.push_back(std::make_unique<NetworkAnalyzer>());
    analyzers.push_back(std::make_unique<AudioAnalyzer>());
    analyzers.push_back(std::make_unique<FirmwareAnalyzer>());
    analyzers.push_back(std::make_unique<SecureBootAnalyzer>());
    analyzers.push_back(std::make_unique<PowerAnalyzer>());
    analyzers.push_back(std::make_unique<VirtualizationAnalyzer>());
    analyzers.push_back(std::make_unique<OnlineAnalyzer>(g_online));

    CompatReport report;
    for (auto& analyzer : analyzers) {
        analyzer->analyze(report);
    }

    printf("\n");
    ReportPrinter printer;
    printer.print(report);

    report.compute();

    if (!save_path.empty()) {
        FILE* f = fopen(save_path.c_str(), "w");
        if (f) {
            fprintf(f, "FreeBSD 15.1 Migration Compatibility Checker -- Report\n");
            fprintf(f, "Hostname: %s\n", uts.nodename);
            fprintf(f, "Current kernel: %s %s\n", uts.sysname, uts.release);
            fprintf(f, "Privilege mode: %s\n\n",
                    Privilege::is_root() ? "root (optional elevated scan)" : "normal user (least privilege)");

            constexpr const char* score_text[] = {
                "[0] FULLY COMPATIBLE",
                "[1] COMPATIBLE (minor)",
                "[2] MAYBE INCOMPATIBLE",
                "[3] INCOMPATIBLE"
            };
            for (const auto& item : report.items) {
                const int s = static_cast<int>(item.score);
                fprintf(f, "%-26s  %-30s  %s\n", item.category.c_str(), score_text[s], item.name.c_str());
                fprintf(f, "  -> %s\n", item.detail.c_str());
                fprintf(f, "  %s\n\n", item.recommendation.c_str());
            }
            fprintf(f, "Overall compatibility score: %.1f%%\n", report.overall_percent);
            fprintf(f, "Fully compatible: %d | Compatible (minor): %d | Maybe incompatible: %d | Incompatible: %d\n",
                    report.score_counts[0], report.score_counts[1], report.score_counts[2], report.score_counts[3]);
            fclose(f);
            printf("%s  Report saved to: %s\n%s", GREEN, save_path.c_str(), RESET);
        } else {
            printf("%s  Failed to save report to: %s\n%s", RED, save_path.c_str(), RESET);
        }
    }

    return 0;
}
