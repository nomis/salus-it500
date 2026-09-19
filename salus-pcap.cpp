#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <pcap/pcap.h>
#include <pcap/sll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

/* Destination MAC, Source MAC, Ethertype */
static constexpr size_t PREFIX_LEN = (6 + 6 + 2);
static constexpr unsigned short SRC_PORT = 21313;
static constexpr unsigned short DST_PORT = 19541;
static const char *GROUP = "ff02::114";

static struct sockaddr_in dev_addr{};
static struct sockaddr_in6 dst_addr{};

static int out = -1;

static void log_packet_ts(const struct pcap_pkthdr *h) {
	std::cout << "# " << std::to_string(h->ts.tv_sec)
		<< "." << std::setfill('0') << std::setw(6)
		<< std::to_string(h->ts.tv_usec) << std::setw(0) << " ";
}

static void recv_packet(u_char *, const struct pcap_pkthdr *h, const u_char *bytes) {
	auto caplen = h->caplen;
	std::stringstream message;

	if (caplen < 14)
		return;

	if (bytes[12] == 0x08 && bytes[13] == 0x00) { /* IPv4 */
		bool in = true;

		if (caplen < 20) /* ip header */
			return;

		bytes += 14;
		caplen -= 14;

		if (!(bytes[0] == 0x45)) /* ip version/hlen */
			return;

		if (!((unsigned int)((bytes[2] << 8) | bytes[3]) <= caplen)) /* ip length */
			return;

		if ((unsigned int)((bytes[2] << 8) | bytes[3]) < 20 + 8 + 1) /* minimum 1 byte of UDP data */
			return;

		if (!((bytes[6] & 0x3F) == 0 && bytes[7] == 0x00)) /* ip flags/fragment offset - ignore fragmented packets */
			return;

		if (!(bytes[9] == 0x11)) /* ip proto */
			return;

		if (memcmp(&bytes[12], &dev_addr.sin_addr, 4) /* ip src */
				&& !(in = false)
				&& memcmp(&bytes[16], &dev_addr.sin_addr, 4)) /* ip dst */
			return;

		bytes += 20 + 8;
		caplen -= 20 + 8;

		log_packet_ts(h);

		message << (in ? "-> " : "<- ");
		message << std::setbase(16) << std::setfill('0');
		for (int i = 0; i < caplen; i++)
			message << std::setw(2) << (unsigned int)bytes[i];

		syslog(LOG_INFO, "%s", message.str().c_str());

		std::cout << message.str() << std::endl;

		uint64_t ts_sec = h->ts.tv_sec;
		uint32_t ts_usec = h->ts.tv_usec;
		std::vector<char> packet(sizeof(ts_sec) + sizeof(ts_usec) + 1 + caplen);

		std::memcpy(packet.data(), &ts_sec, sizeof(ts_sec));
		std::memcpy(&packet.data()[sizeof(ts_sec)], &ts_usec, sizeof(ts_usec));
		packet[sizeof(ts_sec) + sizeof(ts_usec)] = in ? 1 : 0;
		std::memcpy(&packet.data()[sizeof(ts_sec) + sizeof(ts_usec) + 1], bytes, caplen);

		sendto(out, packet.data(), packet.size(), MSG_DONTWAIT|MSG_NOSIGNAL, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
	}
}

int main(int argc, char *argv[]) {
	std::array<char,256> capture_filter{};

	if (argc != 4) {
		std::cerr << "Usage: " << argv[0] << " <listen intf> <ip> <output intf>" << std::endl;
		return 1;
	}

	std::snprintf(&capture_filter[0], capture_filter.size(),
		"host %s and udp and port 443", argv[2]);

	if (inet_pton(AF_INET, argv[2], &dev_addr.sin_addr) != 1) {
		std::cerr << "Invalid IP address" << std::endl;
		return 1;
	}

	openlog("salus-pcap", LOG_PID, LOG_USER);

	int s = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (s == -1) {
		std::perror("socket");
		return 1;
	}

	std::vector<char> errbuf(PCAP_ERRBUF_SIZE);

	if (pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf.data())) {
		std::cerr << "pcap_init: " << std::string{errbuf.data(), errbuf.size()} << std::endl;
		return 1;
	}

	s = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (s == -1) {
		std::perror("socket");
		return 1;
	}

	out = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (out == -1) {
		std::perror("socket");
		return 1;
	}

	int one = 1;

	if (setsockopt(out, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) {
		std::perror("setsockopt(SO_REUSEADDR)");
		return 1;
	}

	sockaddr_in6 src_addr{};
	int ifidx;

	src_addr.sin6_family = AF_INET6;
	src_addr.sin6_addr = in6addr_any;
	src_addr.sin6_port = htons(SRC_PORT);
	src_addr.sin6_scope_id = 0;

	dst_addr.sin6_family = AF_INET6;
	if (inet_pton(AF_INET6, GROUP, &dst_addr.sin6_addr) != 1) {
		std::cerr << "inet_pton: Failed" << std::endl;
		return 1;
	}
	dst_addr.sin6_port = htons(DST_PORT);
	dst_addr.sin6_scope_id = ifidx;

	if (bind(out, (struct sockaddr*)&src_addr, sizeof(src_addr))) {
		std::perror("bind");
		return 1;
	}

	if (setsockopt(out, SOL_IPV6, IPV6_MULTICAST_HOPS, &one, sizeof(one))) {
		std::perror("setsockopt(IPV6_MULTICAST_HOPS)");
		return 1;
	}

	if (setsockopt(out, SOL_IPV6, IPV6_MULTICAST_IF, &ifidx, sizeof(ifidx))) {
		std::perror("setsockopt(IPV6_MULTICAST_IF)");
		return 1;
	}

	ifidx = if_nametoindex(argv[3]);
	if (!ifidx) {
		std::cerr << argv[3] << ": Interface not found" << std::endl;
		return 1;
	}

	pcap_t *pcap;
	if (argv[1][0] == '/') {
		pcap = pcap_open_offline(argv[1], errbuf.data());

		if (!pcap) {
			std::cerr << "pcap_open_offline: " << std::string{errbuf.data(), errbuf.size()} << std::endl;
			return 1;
		}
	} else {
		pcap =pcap_create(argv[1], errbuf.data());

		if (!pcap) {
			std::cerr << "pcap_create: " << std::string{errbuf.data(), errbuf.size()} << std::endl;
			return 1;
		}

		if (pcap_set_snaplen(pcap, 1514)) {
			pcap_perror(pcap, "pcap_set_snaplen");
			return 1;
		}

		if (pcap_set_immediate_mode(pcap, 1)) {
			pcap_perror(pcap, "pcap_set_immediate_mode");
			return 1;
		}

		if (pcap_activate(pcap)) {
			pcap_perror(pcap, "pcap_activate");
			return 1;
		}
	}

	if (pcap_set_datalink(pcap, DLT_EN10MB)) {
		pcap_perror(pcap, "pcap_set_datalink");
		return 1;
	}

	struct bpf_program fp;
	if (pcap_compile(pcap, &fp, &capture_filter[0], 1, PCAP_NETMASK_UNKNOWN)) {
		pcap_perror(pcap, "pcap_compile");
		return 1;
	}

	if (pcap_setfilter(pcap, &fp)) {
		pcap_perror(pcap, "pcap_setfilter");
		return 1;
	}

	if (pcap_loop(pcap, -1, recv_packet, nullptr)) {
		pcap_perror(pcap, "pcap_loop");
		return 1;
	}

	closelog();

	return 0;
}
