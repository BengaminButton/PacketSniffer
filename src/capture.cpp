#include "sniffer.hpp"

#include <pcap/pcap.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>

#include <chrono>
#include <cstring>
#include <cstdio>
#include <stdexcept>

namespace sniffer {

namespace {
std::string choose_default_device() {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errbuf) != 0) {
        throw std::runtime_error(std::string("pcap_findalldevs failed: ") + errbuf);
    }
    std::string dev;
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        if (d->name && !(d->flags & PCAP_IF_LOOPBACK)) {
            dev = d->name;
            break;
        }
    }
    if (dev.empty() && alldevs && alldevs->name) dev = alldevs->name;
    pcap_freealldevs(alldevs);
    if (dev.empty()) throw std::runtime_error("No capture devices found");
    return dev;
}

std::uint64_t now_usec() {
    using namespace std::chrono;
    return duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
}
}

CaptureSession::CaptureSession(Config cfg) : cfg_(std::move(cfg)) {}

CaptureSession::~CaptureSession() {
    stop();
    close_handles();
}

void CaptureSession::open_handles() {
    if (cap_) return;

    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    if (cfg_.pcap_input.has_value()) {
        cap_ = pcap_open_offline(cfg_.pcap_input->c_str(), errbuf);
        if (!cap_) {
            throw std::runtime_error(std::string("pcap_open_offline failed: ") + errbuf);
        }
    } else {
        std::string dev = cfg_.interface.empty() ? choose_default_device() : cfg_.interface;

        if (cfg_.monitor) {
            pcap_t* h = pcap_create(dev.c_str(), errbuf);
            if (!h) throw std::runtime_error(std::string("pcap_create failed: ") + errbuf);
            if (pcap_set_rfmon(h, 1) != 0) {
                pcap_close(h);
                throw std::runtime_error("Interface does not support monitor mode or cannot enable it");
            }
            if (pcap_set_promisc(h, cfg_.promisc ? 1 : 0) != 0) {
                pcap_close(h);
                throw std::runtime_error("pcap_set_promisc failed");
            }
            if (pcap_set_snaplen(h, cfg_.snaplen) != 0) {
                pcap_close(h);
                throw std::runtime_error("pcap_set_snaplen failed");
            }
            if (pcap_set_timeout(h, cfg_.timeout_ms) != 0) {
                pcap_close(h);
                throw std::runtime_error("pcap_set_timeout failed");
            }
            int rc = pcap_activate(h);
            if (rc < 0) {
                std::string msg = pcap_geterr(h);
                pcap_close(h);
                throw std::runtime_error(std::string("pcap_activate failed: ") + msg);
            }
            cap_ = h;
        } else {
            cap_ = pcap_open_live(dev.c_str(), cfg_.snaplen, cfg_.promisc ? 1 : 0, cfg_.timeout_ms, errbuf);
            if (!cap_) {
                throw std::runtime_error(std::string("pcap_open_live failed: ") + errbuf);
            }
        }
    }

    if (cfg_.bpf.has_value() && !cfg_.bpf->empty()) {
        apply_bpf();
    }

    if (cfg_.pcap_output.has_value()) {
        dumper_ = pcap_dump_open(cap_, cfg_.pcap_output->c_str());
        if (!dumper_) {
            throw std::runtime_error(std::string("pcap_dump_open failed: ") + pcap_geterr(cap_));
        }
    }
}

void CaptureSession::close_handles() {
    if (dumper_) {
        pcap_dump_flush(dumper_);
        pcap_dump_close(dumper_);
        dumper_ = nullptr;
    }
    if (cap_) {
        pcap_close(cap_);
        cap_ = nullptr;
    }
}

void CaptureSession::apply_bpf() {
    if (!cap_) return;
    bpf_program prog{};
    int optimize = 1;
    bpf_u_int32 netmask = 0xFFFFFF;
    const char* filter = cfg_.bpf ? cfg_.bpf->c_str() : "";
    if (pcap_compile(cap_, &prog, filter, optimize, netmask) < 0) {
        throw std::runtime_error(std::string("pcap_compile failed: ") + pcap_geterr(cap_));
    }
    if (pcap_setfilter(cap_, &prog) < 0) {
        pcap_freecode(&prog);
        throw std::runtime_error(std::string("pcap_setfilter failed: ") + pcap_geterr(cap_));
    }
    pcap_freecode(&prog);
}

PacketInfo CaptureSession::parse_packet(std::uint64_t number, const pcap_pkthdr* hdr, const u_char* bytes) {
    PacketInfo info{};
    info.number = number;
    info.ts_usec = static_cast<std::uint64_t>(hdr->ts.tv_sec) * 1000000ULL + static_cast<std::uint64_t>(hdr->ts.tv_usec);
    info.caplen = hdr->caplen;
    info.len = hdr->len;
    info.l2 = "Ethernet";

    const u_char* ptr = bytes;
    std::size_t remain = hdr->caplen;
    if (remain < sizeof(ether_header)) return info;
    auto* eth = reinterpret_cast<const ether_header*>(ptr);
    uint16_t ethertype = ntohs(eth->ether_type);
    ptr += sizeof(ether_header);
    remain -= sizeof(ether_header);

    if (ethertype == ETHERTYPE_IP) {
        info.l3 = "IPv4";
        if (remain < sizeof(iphdr)) return info;
        const ip* ip4 = reinterpret_cast<const ip*>(ptr);
        std::size_t iphdr_len = ip4->ip_hl * 4u;
        if (remain < iphdr_len) return info;
        char srcbuf[INET_ADDRSTRLEN] = {0};
        char dstbuf[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &ip4->ip_src, srcbuf, sizeof(srcbuf));
        inet_ntop(AF_INET, &ip4->ip_dst, dstbuf, sizeof(dstbuf));
        info.src_ip = std::string(srcbuf);
        info.dst_ip = std::string(dstbuf);
        uint8_t proto = ip4->ip_p;
        ptr += iphdr_len;
        remain -= iphdr_len;
        if (proto == IPPROTO_TCP) {
            info.l4 = "TCP";
            if (remain >= sizeof(tcphdr)) {
                const tcphdr* th = reinterpret_cast<const tcphdr*>(ptr);
                info.src_port = ntohs(th->th_sport);
                info.dst_port = ntohs(th->th_dport);
            }
        } else if (proto == IPPROTO_UDP) {
            info.l4 = "UDP";
            if (remain >= sizeof(udphdr)) {
                const udphdr* uh = reinterpret_cast<const udphdr*>(ptr);
                info.src_port = ntohs(uh->uh_sport);
                info.dst_port = ntohs(uh->uh_dport);
            }
        } else if (proto == IPPROTO_ICMP) {
            info.l4 = "ICMP";
        } else {
            info.l4 = std::string("Proto(") + std::to_string(proto) + ")";
        }
    } else if (ethertype == ETHERTYPE_IPV6) {
        info.l3 = "IPv6";
        if (remain < sizeof(ip6_hdr)) return info;
        const ip6_hdr* ip6 = reinterpret_cast<const ip6_hdr*>(ptr);
        char srcbuf[INET6_ADDRSTRLEN] = {0};
        char dstbuf[INET6_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET6, &ip6->ip6_src, srcbuf, sizeof(srcbuf));
        inet_ntop(AF_INET6, &ip6->ip6_dst, dstbuf, sizeof(dstbuf));
        info.src_ip = std::string(srcbuf);
        info.dst_ip = std::string(dstbuf);
        uint8_t nh = ip6->ip6_nxt;
        ptr += sizeof(ip6_hdr);
        remain -= sizeof(ip6_hdr);
        if (nh == IPPROTO_TCP) {
            info.l4 = "TCP";
            if (remain >= sizeof(tcphdr)) {
                const tcphdr* th = reinterpret_cast<const tcphdr*>(ptr);
                info.src_port = ntohs(th->th_sport);
                info.dst_port = ntohs(th->th_dport);
            }
        } else if (nh == IPPROTO_UDP) {
            info.l4 = "UDP";
            if (remain >= sizeof(udphdr)) {
                const udphdr* uh = reinterpret_cast<const udphdr*>(ptr);
                info.src_port = ntohs(uh->uh_sport);
                info.dst_port = ntohs(uh->uh_dport);
            }
        } else if (nh == IPPROTO_ICMPV6) {
            info.l4 = "ICMP";
        } else {
            info.l4 = std::string("NH(") + std::to_string(nh) + ")";
        }
    } else {
        info.l3 = std::string("Ethertype(0x") + [] (uint16_t t){ char b[8]; std::snprintf(b, sizeof(b), "%04x", t); return std::string(b);} (ethertype) + ")";
    }

    return info;
}

void CaptureSession::capture_loop() {
    running_ = true;
    std::uint64_t pktno = 0;
    while (!stop_requested_) {
        pcap_pkthdr* hdr = nullptr;
        const u_char* data = nullptr;
        int rc = pcap_next_ex(cap_, &hdr, &data);
        if (rc == 1) {
            ++pktno;
            PacketInfo info = parse_packet(pktno, hdr, data);
            {
                std::lock_guard<std::mutex> lk(mtx_);
                if (stats_.pkts_total == 0) stats_.started_ts_usec = now_usec();
                stats_.pkts_total++;
                stats_.bytes_total += hdr->caplen;
                if (info.l4 && *info.l4 == "TCP") stats_.pkts_tcp++;
                else if (info.l4 && *info.l4 == "UDP") stats_.pkts_udp++;
                else if (info.l4 && *info.l4 == "ICMP") stats_.pkts_icmp++;
            }
            if (dumper_) {
                pcap_dump(reinterpret_cast<u_char*>(dumper_), hdr, data);
            }
            if (analyzer_) analyzer_->on_packet(info, data, hdr->caplen);
        } else if (rc == 0) {
            continue;
        } else if (rc == -2) {
            break;
        } else {
            break;
        }
    }
    running_ = false;
}

void CaptureSession::stats_loop() {
    using namespace std::chrono_literals;
    while (!stop_requested_) {
        std::this_thread::sleep_for(1s);
        if (stop_requested_) break;
        if (!analyzer_) continue;
        analyzer_->on_stats(stats());
    }
}

void CaptureSession::start(std::shared_ptr<Analyzer> analyzer) {
    if (running_) return;
    analyzer_ = std::move(analyzer);
    stop_requested_ = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        stats_ = StatsSnapshot{};
        stats_.started_ts_usec = now_usec();
    }
    open_handles();
    capture_thr_ = std::thread([this]{ capture_loop(); });
    stats_thr_ = std::thread([this]{ stats_loop(); });
}

void CaptureSession::run(std::shared_ptr<Analyzer> analyzer) {
    if (running_) return;
    analyzer_ = std::move(analyzer);
    stop_requested_ = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        stats_ = StatsSnapshot{};
        stats_.started_ts_usec = now_usec();
    }
    open_handles();
    std::thread stats_thread([this]{ stats_loop(); });
    capture_loop();
    stop_requested_ = true;
    if (stats_thread.joinable()) stats_thread.join();
    close_handles();
}

void CaptureSession::stop() {
    stop_requested_ = true;
    if (capture_thr_.joinable()) capture_thr_.join();
    if (stats_thr_.joinable()) stats_thr_.join();
    close_handles();
}

StatsSnapshot CaptureSession::stats() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return stats_;
}

}
