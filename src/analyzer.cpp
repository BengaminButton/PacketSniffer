#include "sniffer.hpp"
#include <chrono>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

#ifdef USE_GEOIP
#include <maxminddb.h>
#endif

namespace sniffer {

std::string ts_to_string(std::uint64_t usec) {
    using namespace std::chrono;
    system_clock::time_point tp = system_clock::time_point(microseconds(usec));
    std::time_t t = system_clock::to_time_t(tp);
    auto micros = duration_cast<microseconds>(tp.time_since_epoch()).count() % 1000000ULL;
    std::tm tmv{};
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tmv, "%F %T") << "." << std::setw(6) << std::setfill('0') << micros;
    return oss.str();
}

#ifdef USE_GEOIP
class MaxMindResolver : public GeoIPResolver {
public:
    explicit MaxMindResolver(const std::string& path) {
        int rc = MMDB_open(path.c_str(), MMDB_MODE_MMAP, &db_);
        if (rc != MMDB_SUCCESS) throw std::runtime_error("MMDB_open failed");
    }
    ~MaxMindResolver() override { MMDB_close(&db_); }
    std::string lookup(const std::string& ip) override {
        int gai_error = 0;
        int mmdb_error = 0;
        MMDB_lookup_result_s res = MMDB_lookup_string(&db_, ip.c_str(), &gai_error, &mmdb_error);
        if (gai_error != 0 || mmdb_error != MMDB_SUCCESS || !res.found_entry) return std::string();
        MMDB_entry_data_s data;
        int status = MMDB_get_value(&res.entry, &data, "country", "iso_code", NULL);
        if (status == MMDB_SUCCESS && data.has_data && data.type == MMDB_DATA_TYPE_UTF8_STRING) {
            return std::string(data.utf8_string, data.data_size);
        }
        return std::string();
    }
private:
    MMDB_s db_{};
};

std::unique_ptr<GeoIPResolver> make_geoip_resolver(const std::string& mmdb_path) {
    return std::unique_ptr<GeoIPResolver>(new MaxMindResolver(mmdb_path));
}
#endif

ConsoleAnalyzer::ConsoleAnalyzer(std::unique_ptr<GeoIPResolver> resolver) : resolver_(std::move(resolver)) {}

void ConsoleAnalyzer::on_packet(const PacketInfo& info, const u_char*, std::size_t) {
    std::ostringstream line;
    line << ts_to_string(info.ts_usec) << " ";
    if (info.l3) line << *info.l3 << " ";
    if (info.l4) line << *info.l4 << " ";
    if (info.src_ip) {
        line << *info.src_ip;
        if (info.src_port) line << ":" << *info.src_port;
        if (resolver_) {
            std::string g = resolver_->lookup(*info.src_ip);
            if (!g.empty()) line << "[" << g << "]";
        }
    }
    line << " -> ";
    if (info.dst_ip) {
        line << *info.dst_ip;
        if (info.dst_port) line << ":" << *info.dst_port;
        if (resolver_) {
            std::string g = resolver_->lookup(*info.dst_ip);
            if (!g.empty()) line << "[" << g << "]";
        }
    }
    line << " len=" << info.caplen;
    std::lock_guard<std::mutex> lk(io_mtx_);
    std::cout << line.str() << std::endl;
}

void ConsoleAnalyzer::on_stats(const StatsSnapshot& s) {
    if (s.started_ts_usec == 0) return;
    std::uint64_t now = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    double secs = (now - s.started_ts_usec) / 1e6;
    if (secs <= 0) secs = 1;
    double pps = s.pkts_total / secs;
    double bps = (s.bytes_total * 8.0) / secs;
    std::lock_guard<std::mutex> lk(io_mtx_);
    std::cout << "stats pkts=" << s.pkts_total << " tcp=" << s.pkts_tcp << " udp=" << s.pkts_udp << " icmp=" << s.pkts_icmp << " pps=" << std::fixed << std::setprecision(2) << pps << " bps=" << bps << std::endl;
}

}