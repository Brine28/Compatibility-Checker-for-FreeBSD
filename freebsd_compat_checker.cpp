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
 * Build:
 *   g++ -O2 -Wall -Wextra -std=c++20 freebsd_compat_checker.cpp \
 *       -o freebsd_compat_checker
 */

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
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
 * no external commands (lspci/lsusb/etc.) are shelled out to.
 * ------------------------------------------------------------------- */
namespace SysFs {

    [[nodiscard]] inline std::optional<std::string> read_first_line(const fs::path& path) {
        std::ifstream in(path);
        if (!in) return std::nullopt;
        std::string line;
        if (!std::getline(in, line)) return std::nullopt;
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' '))
            line.pop_back();
        return line;
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
                if (pos != std::string::npos) vendor = line.substr(pos + 2);
            } else if (model_name.empty() && line.rfind("model name", 0) == 0) {
                auto pos = line.find(':');
                if (pos != std::string::npos) model_name = line.substr(pos + 2);
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
            total_gb = (static_cast<unsigned long long>(vfs.f_blocks) * block) / (1024ULL * 1024 * 1024);
            free_gb  = (static_cast<unsigned long long>(vfs.f_bavail) * block) / (1024ULL * 1024 * 1024);
        }

        /* Find the block device backing "/" and check its 'rotational' flag
         * to distinguish SSD/NVMe from spinning disks -- and its name to
         * spot NVMe specifically. This is a best-effort, sysfs-only lookup. */
        std::string root_device;
        {
            std::ifstream mounts("/proc/self/mountinfo");
            std::string line;
            while (std::getline(mounts, line)) {
                std::istringstream iss(line);
                std::vector<std::string> fields;
                std::string field;
                while (iss >> field) fields.push_back(field);
                for (size_t i = 0; i + 1 < fields.size(); ++i) {
                    if (fields[i] == "-" && i + 2 < fields.size()) {
                        if (std::find(fields.begin(), fields.end(), std::string("/")) != fields.end()) {
                            root_device = fields[i + 2];
                        }
                    }
                }
                if (!root_device.empty()) break;
            }
        }

        bool is_ssd = false;
        bool is_nvme = false;
        if (!root_device.empty()) {
            is_nvme = root_device.find("nvme") != std::string::npos;
            std::string base;
            if (is_nvme) {
                base = root_device.substr(root_device.find_last_of('/') + 1);
                auto p_pos = base.find('p');
                if (p_pos != std::string::npos && p_pos > 0) base = base.substr(0, p_pos);
            } else {
                base = fs::path(root_device).filename().string();
                while (!base.empty() && std::isdigit(static_cast<unsigned char>(base.back())))
                    base.pop_back();
            }
            auto rot = SysFs::read_first_line("/sys/block/" + base + "/queue/rotational");
            if (rot) is_ssd = (*rot == "0");
        }

        const char* drive_type = is_nvme ? "NVMe SSD" : is_ssd ? "SSD" : "Rotational (HDD)";

        CompatItem* itp = new_item(report);
        if (!itp) return;
        CompatItem& it = *itp;
        it.category = std::string(CAT_DISK);
        it.name     = std::format("Storage: {} GB total / {} GB free  [{}]", total_gb, free_gb, drive_type);
        it.critical = true;

        if (free_gb < 20) {
            it.score  = CompatScore::NONE;
            it.detail = std::format("Only {} GB free -- a comfortable FreeBSD install with ports/"
                                    "packages usually wants at least 20 GB.", free_gb);
            it.recommendation = "Free up space or use a separate disk/partition for the FreeBSD install.";
        } else if (free_gb < 50) {
            it.score  = CompatScore::MINOR;
            it.detail = std::format("{} GB free -- installable, but tight once packages accumulate.", free_gb);
            it.recommendation = "50+ GB is recommended if you plan to install a full desktop plus applications.";
        } else {
            it.score  = CompatScore::FULL;
            it.detail = std::format("{} GB free -- plenty of room for FreeBSD and your data.", free_gb);
            it.recommendation = is_nvme
                ? "NVMe works natively with FreeBSD's nvme(4) driver; ZFS or UFS are both good filesystem choices."
                : "No storage-related migration concerns.";
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

        if (!fs::exists("/sys/bus/pci/devices")) return;

        for (const auto& entry : fs::directory_iterator("/sys/bus/pci/devices")) {
            const auto class_str = SysFs::read_first_line(entry.path() / "class");
            if (!class_str || class_str->rfind("0x03", 0) != 0) continue;

            const auto vendor_str = SysFs::read_first_line(entry.path() / "vendor").value_or("");
            const auto device_str = SysFs::read_first_line(entry.path() / "device").value_or("");

            found = true;
            CompatItem* itp = new_item(report);
            if (!itp) return;
            CompatItem& it = *itp;
            it.category = std::string(CAT_GPU);
            it.critical = true;

            const bool is_intel  = vendor_str == "0x8086";
            const bool is_amd    = vendor_str == "0x1002";
            const bool is_nvidia = vendor_str == "0x10de";

            it.name = std::format("PCI display controller [{}:{}]", vendor_str, device_str);

            if (is_intel) {
                it.score  = CompatScore::FULL;
                it.detail = "Intel graphics device.";
                it.recommendation = "Install drm-kmod (i915kms) and libva-intel-media-driver (iHD) "
                                     "for VA-API. This is currently the most reliable, best-supported "
                                     "graphics path on FreeBSD, including under Wayland.";
            } else if (is_amd) {
                it.score  = CompatScore::MINOR;
                it.detail = "AMD graphics device.";
                it.recommendation = "Install drm-kmod (amdgpu). Generally works, though driver "
                                     "maturity on FreeBSD tends to lag a bit behind Intel's i915kms path.";
            } else if (is_nvidia) {
                it.score  = CompatScore::MAYBE;
                it.detail = "NVIDIA graphics device.";
                it.recommendation = "Requires the proprietary nvidia-driver port. As of FreeBSD "
                                     "15.1, Wayland support for NVIDIA (screen capture, PRIME-style "
                                     "hybrid offload) is still limited. If this is a hybrid Intel+"
                                     "NVIDIA laptop, letting the Intel GPU drive the desktop is the "
                                     "more reliable path today.";
            } else {
                it.score  = CompatScore::MAYBE;
                it.detail = "Unrecognized GPU vendor.";
                it.recommendation = "Check the FreeBSD Handbook's graphics section for driver availability.";
            }
        }

        if (!found) {
            CompatItem* itp = new_item(report);
            if (!itp) return;
            itp->category       = std::string(CAT_GPU);
            itp->name           = "No PCI display controller found";
            itp->critical       = true;
            itp->score          = CompatScore::MAYBE;
            itp->detail         = "Could not enumerate a display controller via /sys/bus/pci/devices.";
            itp->recommendation = "This may be a virtual machine or an unusual setup; verify manually.";
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
            const bool is_intel_eth = driver.find("e1000") != std::string::npos || driver.find("igb") != std::string::npos || driver.find("ixgbe") != std::string::npos;
            const bool is_realtek   = driver.find("rtw") != std::string::npos || driver.find("r8169") != std::string::npos || driver.find("r8168") != std::string::npos;
            const bool is_atheros   = driver.find("ath") != std::string::npos;
            const bool is_mediatek  = driver.find("mt7") != std::string::npos;
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
        it.name     = m_online ? "Internet connectivity: reachable" : "Internet connectivity: unreachable";
        it.critical = false;

        if (m_online) {
            it.score  = CompatScore::FULL;
            it.detail = "A route to the internet was confirmed.";
            it.recommendation = "You'll be able to fetch packages from FreeBSD's package "
                                 "repositories (pkg) and ports tree immediately after installing.";
        } else {
            it.score  = CompatScore::MINOR;
            it.detail = "No internet route could be confirmed from this machine right now.";
            it.recommendation = "FreeBSD's installer can still complete an offline base install, "
                                 "but installing packages (pkg install) requires network access "
                                 "afterwards.";
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
static bool CheckInternetConnectivity() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);

    timeval tv{};
    tv.tv_sec  = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    const bool ok = (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    close(sock);
    return ok;
}

/* =================================================================
 * Console helpers
 * ================================================================= */
namespace Console {

    inline void print_header() {
        printf("\n");
        printf("%s%s================================================================\n%s", CYAN, BOLD, RESET);
        printf("%s%s   FreeBSD 15.1 Migration Compatibility Checker\n%s", CYAN, BOLD, RESET);
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
        if (std::string_view(argv[i]) == "--save" && i + 1 < argc) {
            save_path = argv[++i];
        }
    }

    Console::print_header();

    struct utsname uts{};
    uname(&uts);
    printf("%s  Hostname       : %s\n%s", DIM, uts.nodename, RESET);
    printf("%s  Current kernel : %s %s\n%s", DIM, uts.sysname, uts.release, RESET);

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

    if (!save_path.empty()) {
        FILE* f = fopen(save_path.c_str(), "w");
        if (f) {
            fprintf(f, "FreeBSD 15.1 Migration Compatibility Checker -- Report\n");
            fprintf(f, "Hostname: %s\n", uts.nodename);
            fprintf(f, "Current kernel: %s %s\n\n", uts.sysname, uts.release);

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
