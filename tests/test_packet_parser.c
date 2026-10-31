#include "packet.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define PARSED       1   // packet parsed successfully
#define NOT_PARSED   0   // packet ignored (unsupported, truncated or malformed)
#define INVALID     -1   // invalid arguments

// Byte offsets inside an Ethernet frame that holds an IPv4 packet with a 20 byte IP header
#define ETH_LEN               14
#define APP_OFFSET             (ETH_LEN + 20)   // start of the TCP / ICMP header
#define OFF_ETHERTYPE_LOW     13
#define OFF_IP_VERSION_IHL    14
#define OFF_IP_TOTAL_LEN_LOW  17
#define OFF_IP_FLAGS          20
#define OFF_IP_FRAG_OFFSET    21
#define OFF_IP_PROTOCOL       23
#define OFF_ICMP_TYPE         APP_OFFSET
#define OFF_QUOTED_IP         (APP_OFFSET + 8)
#define OFF_TCP_DATA_OFFSET   (APP_OFFSET + 12)
#define OFF_TCP_MSS_LENGTH    (APP_OFFSET + 21)  // length byte of the first TCP option (MSS)
#define OFF_TCP_LAST_OPTION   (APP_OFFSET + 39)  // last of the 20 option bytes

// Quoted IP header start (version 4, IHL 5) with a checksum of 0xABCD, used as ICMP payload
static uint8_t icmp_payload[28] = {0x45, [10] = 0xAB, [11] = 0xCD};

static struct tcp_probe make_tcp_spec(void) {
    return (struct tcp_probe){
        .dest_ip = "10.0.0.2",
        .source_port = 1000,
        .dest_port = 80,
        .seq_num = 0x01020304,
        .ack_num = 0x0A0B0C0D,
        .tcp_flags = TH_SYN | TH_ACK,
        .window_size = 512,
        .urgent_pointer = 7,
        .reseved_bit = true,
        .tcp_options = {
            TCPOPT_MAXSEG, TCPOLEN_MAXSEG, 0x05, 0xB4,
            TCPOPT_SACK_PERMITTED, TCPOLEN_SACK_PERMITTED,
            TCPOPT_WINDOW, TCPOLEN_WINDOW, 7,
            TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP, 0, 0, 0, 1, 0, 0, 0, 2,  // TSval = 1, TSecr = 2
            TCPOPT_NOP,
        },
        .tcp_options_len = 20,
    };
}

static struct icmp_probe make_icmp_spec(void) {
    return (struct icmp_probe){
        .dest_ip = "10.0.0.2",
        .icmp_type = ICMP_DEST_UNREACH,
        .icmp_code = ICMP_PORT_UNREACH,
        .icmp_identifier = 7,
        .icmp_sequence = 295,
        .ip_DF = true,
        .ip_id = 0x1234,
        .payload = icmp_payload,
        .payload_len = sizeof(icmp_payload),
    };
}

// Puts an IP packet inside an Ethernet frame, frees the packet and returns the frame length.
static size_t wrap_in_ethernet(uint8_t *frame, uint8_t *ip_packet, size_t ip_len) {
    assert(ip_packet != NULL);
    memset(frame, 0, ETH_LEN);
    frame[12] = 0x08;  // EtherType 0x0800 (IPv4)
    memcpy(frame + ETH_LEN, ip_packet, ip_len);
    free(ip_packet);
    return ETH_LEN + ip_len;
}

static size_t tcp_frame(uint8_t *frame, struct tcp_probe spec) {
    size_t ip_len;
    uint8_t *packet = construct_TCP_packet(spec, "10.0.0.1", &ip_len);
    return wrap_in_ethernet(frame, packet, ip_len);
}

static size_t icmp_frame(uint8_t *frame, struct icmp_probe spec) {
    size_t ip_len;
    uint8_t *packet = construct_ICMP_packet(spec, "10.0.0.1", &ip_len);
    return wrap_in_ethernet(frame, packet, ip_len);
}

static int parse_frame(const uint8_t *frame, size_t len, struct parsed_info *parsed) {
    struct pcap_pkthdr header = {.caplen = (bpf_u_int32)len, .len = (bpf_u_int32)len};
    return parse_packet(frame, &header, DLT_EN10MB, parsed);
}

// Changes one byte of a copy of the frame, parses it and returns the parse_packet result.
static int parse_modified(const uint8_t *frame, size_t len, size_t offset, uint8_t value) {
    uint8_t copy[128];
    struct parsed_info parsed;

    memcpy(copy, frame, len);
    copy[offset] = value;

    int status = parse_frame(copy, len, &parsed);
    free_parsed_info(&parsed);
    return status;
}

// Packets built by construct_TCP_packet must be parsed back to the same values.
static void test_parse_tcp(void) {
    uint8_t frame[128];
    struct parsed_info parsed;
    struct tcp_probe spec = make_tcp_spec();
    size_t len = tcp_frame(frame, spec);

    assert(parse_frame(frame, len, &parsed) == PARSED);
    assert(parsed.ip_protocol == IPPROTO_TCP);
    assert(parsed.src_ip.s_addr == inet_addr("10.0.0.1"));
    assert(parsed.dst_ip.s_addr == inet_addr("10.0.0.2"));
    assert(parsed.ip_id == 54321);
    assert(parsed.ip_ttl == 64);
    assert(parsed.ip_tot_length == 60);
    assert(parsed.ip_hdr_length == 20);
    assert(parsed.ip_fragoff == 0);
    assert(parsed.app_protocol.tcp_ap.src_port == 1000);
    assert(parsed.app_protocol.tcp_ap.dst_port == 80);
    assert(parsed.app_protocol.tcp_ap.seq == 0x01020304);
    assert(parsed.app_protocol.tcp_ap.ack == 0x0A0B0C0D);
    assert(parsed.app_protocol.tcp_ap.flags == (TH_SYN | TH_ACK));
    assert(parsed.app_protocol.tcp_ap.win_size == 512);
    assert(parsed.app_protocol.tcp_ap.urg_pointer == 7);
    assert(parsed.app_protocol.tcp_ap.offset == 10);
    assert(parsed.app_protocol.tcp_ap.reserved == 8);
    assert(parsed.app_protocol.tcp_ap.options_len == 20);
    assert(memcmp(parsed.app_protocol.tcp_ap.options, spec.tcp_options, 20) == 0);
    assert(parsed.app_protocol.tcp_ap.timestamp_present);
    assert(parsed.app_protocol.tcp_ap.tsval == 1);
    assert(parsed.app_protocol.tcp_ap.tsecr == 2);
    assert(parsed.app_protocol.tcp_ap.payload_len == 0);
    assert(parsed.app_protocol.tcp_ap.payload == NULL);
    free_parsed_info(&parsed);

    // No options
    spec.tcp_options_len = 0;
    len = tcp_frame(frame, spec);
    assert(parse_frame(frame, len, &parsed) == PARSED);
    assert(parsed.app_protocol.tcp_ap.options_len == 0);
    assert(parsed.app_protocol.tcp_ap.options == NULL);
    assert(!parsed.app_protocol.tcp_ap.timestamp_present);
    free_parsed_info(&parsed);

    // End of options (EOL) stops the option validation, so the bytes after it are not checked
    memcpy(spec.tcp_options, (uint8_t[]){TCPOPT_EOL, 0xFF, 0xFF, 0xFF}, 4);
    spec.tcp_options_len = 4;
    len = tcp_frame(frame, spec);
    assert(parse_frame(frame, len, &parsed) == PARSED);
    assert(parsed.app_protocol.tcp_ap.options_len == 4);
    free_parsed_info(&parsed);

    // Payload after the TCP header
    len = tcp_frame(frame, make_tcp_spec());
    memcpy(frame + len, "abc", 3);
    len += 3;
    frame[OFF_IP_TOTAL_LEN_LOW] = 63;  // IP total length 60 + 3
    assert(parse_frame(frame, len, &parsed) == PARSED);
    assert(parsed.app_protocol.tcp_ap.payload_len == 3);
    assert(memcmp(parsed.app_protocol.tcp_ap.payload, "abc", 3) == 0);
    free_parsed_info(&parsed);
}

// Round trip for ICMP: echo request/reply and destination unreachable.
static void test_parse_icmp(void) {
    uint8_t frame[128];
    struct parsed_info parsed;
    struct icmp_probe spec = make_icmp_spec();
    uint8_t echo_types[] = {ICMP_ECHO, ICMP_ECHOREPLY};

    for (size_t i = 0; i < sizeof(echo_types); i++) {
        spec.icmp_type = echo_types[i];
        spec.icmp_code = 0;
        size_t len = icmp_frame(frame, spec);

        assert(parse_frame(frame, len, &parsed) == PARSED);
        assert(parsed.ip_protocol == IPPROTO_ICMP);
        assert(parsed.src_ip.s_addr == inet_addr("10.0.0.1"));
        assert(parsed.dst_ip.s_addr == inet_addr("10.0.0.2"));
        assert(parsed.ip_id == 0x1234);
        assert(parsed.ip_ttl == 64);
        assert(parsed.ip_fragoff == IP_DF);  // the DF flag is not treated as a fragment
        assert(parsed.app_protocol.icmp_ap.type == echo_types[i]);
        assert(parsed.app_protocol.icmp_ap.code == 0);
        assert(parsed.app_protocol.icmp_ap.header.echo.id == 7);
        assert(parsed.app_protocol.icmp_ap.header.echo.seq == 295);
        assert(parsed.app_protocol.icmp_ap.payload_len == sizeof(icmp_payload));
        assert(memcmp(parsed.app_protocol.icmp_ap.payload, icmp_payload, sizeof(icmp_payload)) == 0);
        free_parsed_info(&parsed);
    }

    // Destination unreachable: the first 4 bytes after the checksum are "unused"
    // (here the echo identifier and sequence), followed by the quoted IP header
    size_t len = icmp_frame(frame, make_icmp_spec());
    assert(parse_frame(frame, len, &parsed) == PARSED);
    assert(parsed.app_protocol.icmp_ap.type == ICMP_DEST_UNREACH);
    assert(parsed.app_protocol.icmp_ap.code == ICMP_PORT_UNREACH);
    assert(parsed.app_protocol.icmp_ap.header.unreachable.unused == 0x00070127);
    assert(parsed.app_protocol.icmp_ap.header.unreachable.ip_checksum == 0xABCD);
    assert(parsed.app_protocol.icmp_ap.payload_len == sizeof(icmp_payload));
    free_parsed_info(&parsed);
}

// Every way a packet can be rejected, by changing one byte (or the length) of a valid frame.
static void test_rejected_packets(void) {
    uint8_t tcp[128];
    uint8_t icmp[128];
    struct parsed_info parsed;
    size_t tcp_len = tcp_frame(tcp, make_tcp_spec());
    size_t icmp_len = icmp_frame(icmp, make_icmp_spec());
    struct pcap_pkthdr header = {.caplen = (bpf_u_int32)tcp_len, .len = (bpf_u_int32)tcp_len};

    // Invalid arguments
    assert(parse_packet(tcp, &header, DLT_EN10MB, NULL) == INVALID);
    assert(parse_packet(NULL, &header, DLT_EN10MB, &parsed) == INVALID);
    assert(parse_packet(tcp, NULL, DLT_EN10MB, &parsed) == INVALID);
    free_parsed_info(NULL);  // must not crash

    // Not Ethernet, too short, or truncated
    assert(parse_packet(tcp, &header, DLT_NULL, &parsed) == NOT_PARSED);
    assert(parse_frame(tcp, ETH_LEN - 1, &parsed) == NOT_PARSED);   // shorter than the Ethernet header
    assert(parse_frame(tcp, ETH_LEN + 10, &parsed) == NOT_PARSED);  // shorter than the IP header
    assert(parse_frame(tcp, tcp_len - 1, &parsed) == NOT_PARSED);   // IP total length is larger than the capture

    // Ethernet and IP header
    assert(parse_modified(tcp, tcp_len, OFF_ETHERTYPE_LOW, 0x06) == NOT_PARSED);       // ARP
    assert(parse_modified(tcp, tcp_len, OFF_IP_VERSION_IHL, 0x65) == NOT_PARSED);      // IPv6
    assert(parse_modified(tcp, tcp_len, OFF_IP_VERSION_IHL, 0x44) == NOT_PARSED);      // IHL below 20 bytes
    assert(parse_modified(tcp, tcp_len, OFF_IP_TOTAL_LEN_LOW, 10) == NOT_PARSED);      // total length below IHL
    assert(parse_modified(tcp, tcp_len, OFF_IP_FLAGS, 0x20) == NOT_PARSED);            // More Fragments flag
    assert(parse_modified(tcp, tcp_len, OFF_IP_FRAG_OFFSET, 1) == NOT_PARSED);         // fragment offset
    assert(parse_modified(tcp, tcp_len, OFF_IP_PROTOCOL, IPPROTO_UDP) == NOT_PARSED);  // unsupported protocol
    assert(parse_modified(tcp, tcp_len, OFF_IP_FLAGS, 0x40) == PARSED);                // DF flag is allowed

    // TCP header and options
    assert(parse_modified(tcp, tcp_len, OFF_IP_TOTAL_LEN_LOW, 30) == NOT_PARSED);   // segment shorter than 20 bytes
    assert(parse_modified(tcp, tcp_len, OFF_TCP_DATA_OFFSET, 0x40) == NOT_PARSED);  // header length below 20
    assert(parse_modified(tcp, tcp_len, OFF_TCP_DATA_OFFSET, 0xF0) == NOT_PARSED);  // header longer than segment
    assert(parse_modified(tcp, tcp_len, OFF_TCP_MSS_LENGTH, 1) == NOT_PARSED);      // option length below 2
    assert(parse_modified(tcp, tcp_len, OFF_TCP_MSS_LENGTH, 5) == NOT_PARSED);      // MSS must be 4 bytes long
    assert(parse_modified(tcp, tcp_len, OFF_TCP_MSS_LENGTH, 0xFF) == NOT_PARSED);   // option runs past the header
    assert(parse_modified(tcp, tcp_len, OFF_TCP_LAST_OPTION, TCPOPT_TIMESTAMP) == NOT_PARSED);  // kind without a length byte

    // ICMP
    assert(parse_modified(icmp, icmp_len, OFF_ICMP_TYPE, 11) == NOT_PARSED);          // unsupported ICMP type
    assert(parse_modified(icmp, icmp_len, OFF_IP_TOTAL_LEN_LOW, 24) == NOT_PARSED);   // ICMP header cut short
    assert(parse_modified(icmp, icmp_len, OFF_IP_TOTAL_LEN_LOW, 38) == NOT_PARSED);   // quoted data below 20 bytes
    assert(parse_modified(icmp, icmp_len, OFF_QUOTED_IP, 0x65) == NOT_PARSED);        // quoted packet is not IPv4
    assert(parse_modified(icmp, icmp_len, OFF_QUOTED_IP, 0x4F) == NOT_PARSED);        // quoted IHL longer than the data
}

int main(void) {
    test_parse_tcp();
    test_parse_icmp();
    test_rejected_packets();

    printf("All packet parser tests passed successfully.\n\n");
    return 0;
}