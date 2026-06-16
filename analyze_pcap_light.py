from collections import Counter
import ipaddress
import statistics
import struct
import sys
import time


def fmt_ts(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else None


def mac_addr(buf):
    return ":".join(f"{b:02x}" for b in buf)


def ipv4_addr(buf):
    return str(ipaddress.IPv4Address(buf))


def main(path):
    cnt = 0
    captured_bytes = 0
    first = None
    last = None
    bad = 0
    truncated = 0

    sizes = []
    ethertypes = Counter()
    ip_protocols = Counter()
    top_talkers = Counter()
    ip_pairs = Counter()
    tcp_ports = Counter()
    udp_ports = Counter()
    port_bytes = Counter()

    broadcasts = 0
    multicasts = 0
    arp = 0
    icmp = 0
    payload_bytes = 0
    tcp_ack_no_payload = 0
    tcp_payload_pkts = 0
    udp_payload_pkts = 0
    dns_pkts = 0
    mdns_pkts = 0
    ssdp_pkts = 0
    ntp_pkts = 0

    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) != 24:
            raise SystemExit("Not a valid pcap: global header is too short")
        magic = gh[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
            ns_resolution = False
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
            ns_resolution = False
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian = "<"
            ns_resolution = True
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian = ">"
            ns_resolution = True
        else:
            raise SystemExit(f"Unsupported pcap magic: {magic.hex()}")

        _magic, ver_major, ver_minor, _tz, _sig, snaplen, network = struct.unpack(
            endian + "IHHIIII", gh
        )
        print("pcap_header", {"version": f"{ver_major}.{ver_minor}", "snaplen": snaplen, "network": network})

        while True:
            ph = f.read(16)
            if not ph:
                break
            if len(ph) != 16:
                truncated += 1
                break
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", ph)
            raw = f.read(incl_len)
            if len(raw) != incl_len:
                truncated += 1
                break

            cnt += 1
            captured_bytes += incl_len
            sizes.append(incl_len)
            frac_div = 1_000_000_000 if ns_resolution else 1_000_000
            ts = ts_sec + ts_frac / frac_div
            if first is None:
                first = ts
            last = ts

            try:
                if network != 1 or len(raw) < 14:
                    bad += 1
                    continue
                dst_mac = mac_addr(raw[0:6])
                if dst_mac == "ff:ff:ff:ff:ff:ff":
                    broadcasts += 1
                if raw[0] & 1 and dst_mac != "ff:ff:ff:ff:ff:ff":
                    multicasts += 1

                eth_type = struct.unpack("!H", raw[12:14])[0]
                offset = 14
                if eth_type == 0x8100 and len(raw) >= 18:
                    eth_type = struct.unpack("!H", raw[16:18])[0]
                    offset = 18
                ethertypes[eth_type] += 1
                if eth_type == 0x0806:
                    arp += 1
                    continue
                if eth_type != 0x0800 or len(raw) < offset + 20:
                    continue

                ip0 = raw[offset]
                ihl = (ip0 & 0x0F) * 4
                if ihl < 20 or len(raw) < offset + ihl:
                    bad += 1
                    continue
                total_len = struct.unpack("!H", raw[offset + 2 : offset + 4])[0]
                proto = raw[offset + 9]
                src = ipv4_addr(raw[offset + 12 : offset + 16])
                dst = ipv4_addr(raw[offset + 16 : offset + 20])
                ip_protocols[proto] += 1
                top_talkers[src] += incl_len
                top_talkers[dst] += 0
                ip_pairs[(src, dst)] += incl_len

                l4 = offset + ihl
                ip_payload_len = max(0, min(total_len, len(raw) - offset) - ihl)
                if proto == 1:
                    icmp += 1
                elif proto == 6 and len(raw) >= l4 + 20:
                    sport, dport = struct.unpack("!HH", raw[l4 : l4 + 4])
                    data_offset = (raw[l4 + 12] >> 4) * 4
                    flags = raw[l4 + 13]
                    payload_len = max(0, ip_payload_len - data_offset)
                    tcp_ports[(sport, dport)] += 1
                    port_bytes[("tcp", sport, dport)] += incl_len
                    payload_bytes += payload_len
                    if payload_len == 0 and (flags & 0x10):
                        tcp_ack_no_payload += 1
                    if payload_len > 0:
                        tcp_payload_pkts += 1
                elif proto == 17 and len(raw) >= l4 + 8:
                    sport, dport, udp_len = struct.unpack("!HHH", raw[l4 : l4 + 6])
                    payload_len = max(0, min(udp_len, ip_payload_len) - 8)
                    udp_ports[(sport, dport)] += 1
                    port_bytes[("udp", sport, dport)] += incl_len
                    payload_bytes += payload_len
                    if payload_len > 0:
                        udp_payload_pkts += 1
                    ports = {sport, dport}
                    if ports & {53}:
                        dns_pkts += 1
                    if ports & {5353}:
                        mdns_pkts += 1
                    if ports & {1900}:
                        ssdp_pkts += 1
                    if ports & {123}:
                        ntp_pkts += 1
            except Exception:
                bad += 1

    sorted_sizes = sorted(sizes)
    print("packets", cnt)
    print("captured_bytes", captured_bytes)
    print("time_start", fmt_ts(first))
    print("time_end", fmt_ts(last))
    print("duration_sec", round((last - first), 3) if first and last else None)
    print("ethertype_top", ethertypes.most_common(10))
    print("ip_protocol_top", ip_protocols.most_common(10))
    print("broadcast_pkts", broadcasts)
    print("multicast_pkts", multicasts)
    print("arp_pkts", arp)
    print("icmp_pkts", icmp)
    print("parse_errors", bad)
    print("truncated_records", truncated)
    print("payload_bytes", payload_bytes)
    print("tcp_ack_no_payload", tcp_ack_no_payload)
    print("tcp_payload_pkts", tcp_payload_pkts)
    print("udp_payload_pkts", udp_payload_pkts)
    print("dns_pkts", dns_pkts)
    print("mdns_pkts", mdns_pkts)
    print("ssdp_pkts", ssdp_pkts)
    print("ntp_pkts", ntp_pkts)
    if sorted_sizes:
        print(
            "size_min_avg_p50_p90_p99_max",
            sorted_sizes[0],
            round(statistics.mean(sorted_sizes), 1),
            statistics.median(sorted_sizes),
            sorted_sizes[int(len(sorted_sizes) * 0.90)],
            sorted_sizes[int(len(sorted_sizes) * 0.99)],
            sorted_sizes[-1],
        )
    print("top_talkers_bytes", top_talkers.most_common(10))
    print("top_ip_pairs_bytes", ip_pairs.most_common(10))
    print("top_tcp_port_pairs", tcp_ports.most_common(20))
    print("top_udp_port_pairs", udp_ports.most_common(20))
    print("top_port_bytes", port_bytes.most_common(20))


if __name__ == "__main__":
    main(sys.argv[1])
