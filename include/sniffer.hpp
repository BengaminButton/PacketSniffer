#pragma once

#include <pcap/pcap.h>
#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace sniffer {

struct Config {
    std::string interface;
    std::optional<std::string> bpf;
    int snaplen = 65535;
    bool promisc = true;
    int timeout_ms = 1000;
    bool monitor = false;
    std::optional<std::string> pcap_input;
    std::optional<std::string> pcap_output;
};

struct PacketInfo {
    std::uint64_t number = 0;
    std::uint64_t ts_usec = 0;
    std::uint32_t caplen = 0;
    std::uint32_t len = 0;
    std::optional<std::string> l2;
    std::optional<std::string> l3;
    std::optional<std::string> l4;
    std::optional<std::string> src_ip;
    std::optional<std::string> dst_ip;
    std::optional<std::uint16_t> src_port;
    std::optional<std::uint16_t> dst_port;
    std::optional<std::string> src_geo;
    std::optional<std::string> dst_geo;
};

struct StatsSnapshot {
    std::uint64_t started_ts_usec = 0;
    std::uint64_t pkts_total = 0;
    std::uint64_t bytes_total = 0;
    std::uint64_t pkts_tcp = 0;
    std::uint64_t pkts_udp = 0;
    std::uint64_t pkts_icmp = 0;
};

class GeoIPResolver {
public:
    virtual ~GeoIPResolver() = default;
    virtual std::string lookup(const std::string& ip) = 0;
};

#ifdef USE_GEOIP
std::unique_ptr<GeoIPResolver> make_geoip_resolver(const std::string& mmdb_path);
#else
inline std::unique_ptr<GeoIPResolver> make_geoip_resolver(const std::string&) { return nullptr; }
#endif

class Analyzer {
public:
    virtual ~Analyzer() = default;
    virtual void on_packet(const PacketInfo& info, const u_char* data, std::size_t length) = 0;
    virtual void on_stats(const StatsSnapshot& stats) = 0;
};

class CaptureSession {
public:
    explicit CaptureSession(Config cfg);
    ~CaptureSession();
    CaptureSession(const CaptureSession&) = delete;
    CaptureSession& operator=(const CaptureSession&) = delete;
    void start(std::shared_ptr<Analyzer> analyzer);
    void stop();
    void run(std::shared_ptr<Analyzer> analyzer);
    StatsSnapshot stats() const;
private:
    void capture_loop();
    void stats_loop();
    void apply_bpf();
    void open_handles();
    void close_handles();
    PacketInfo parse_packet(std::uint64_t number, const pcap_pkthdr* hdr, const u_char* bytes);
    Config cfg_;
    pcap_t* cap_ = nullptr;
    pcap_dumper_t* dumper_ = nullptr;
    std::shared_ptr<Analyzer> analyzer_;
    std::thread capture_thr_;
    std::thread stats_thr_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    mutable std::mutex mtx_;
    StatsSnapshot stats_{};
};

class ConsoleAnalyzer : public Analyzer {
public:
    explicit ConsoleAnalyzer(std::unique_ptr<GeoIPResolver> resolver = nullptr);
    void on_packet(const PacketInfo& info, const u_char* data, std::size_t length) override;
    void on_stats(const StatsSnapshot& stats) override;
private:
    std::unique_ptr<GeoIPResolver> resolver_;
    std::mutex io_mtx_;
};

std::string ts_to_string(std::uint64_t usec);

}