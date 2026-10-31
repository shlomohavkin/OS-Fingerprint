#include "packet.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

// Big-endian readers, to check the bytes of the constructed packets (network byte order)
static uint16_t read_int16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t read_int32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

// check common fields of the IP header
static void check_ip_header(const uint8_t *packet, size_t len, uint8_t protocol) {
    assert(packet[0] == 0x45);
    assert(read_int16(packet + 2) == len);
    assert(packet[9] == protocol);
    assert(memcmp(packet + 12, (uint8_t[]){10, 0, 0, 1}, 4) == 0);  // source 10.0.0.1
    assert(memcmp(packet + 16, (uint8_t[]){10, 0, 0, 2}, 4) == 0);  // destination 10.0.0.2
}

// calculate the checksum of the transport layer segment.
// The checksum is 0 when the checksum in the segment is correct.
static uint16_t transport_checksum(const uint8_t *packet, size_t len, uint8_t protocol) {
    uint8_t buffer[400] = {0};
    size_t segment_len = len - 20;

    memcpy(buffer, packet + 12, 8);  // source and destination addresses
    buffer[9] = protocol;
    buffer[10] = (uint8_t)(segment_len >> 8);
    buffer[11] = (uint8_t)segment_len;
    memcpy(buffer + 12, packet + 20, segment_len);
    return calculate_checksum(buffer, 12 + segment_len);
}

static void test_construct_tcp(void) {
    struct tcp_probe spec = {
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
            TCPOPT_WINDOW, TCPOLEN_WINDOW, 10, TCPOPT_NOP,
            TCPOPT_MAXSEG, TCPOLEN_MAXSEG, 0x05, 0xB4,
            TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0,
            TCPOPT_SACK_PERMITTED, TCPOLEN_SACK_PERMITTED,
        },
        .tcp_options_len = 20,
    };
    size_t len = 0;

    // Every field of a packet with options
    uint8_t *packet = construct_TCP_packet(spec, "10.0.0.1", &len);
    assert(packet != NULL);
    assert(len == 60);
    check_ip_header(packet, len, IPPROTO_TCP);
    assert(read_int16(packet + 4) == 54321); // IP ID
    assert(read_int16(packet + 6) == 0); // no flags, no fragment offset
    assert(packet[8] == 64); // TTL
    assert(read_int16(packet + 20) == 1000); // source port
    assert(read_int16(packet + 22) == 80); // destination port
    assert(read_int32(packet + 24) == 0x01020304); // sequence number
    assert(read_int32(packet + 28) == 0x0A0B0C0D); // acknowledgment number
    assert((packet[32] >> 4) == 10); // data offset: 40 bytes / 4
    assert((packet[32] & 0x0F) == 8); // reserved bit is set
    assert(packet[33] == (TH_SYN | TH_ACK));
    assert(read_int16(packet + 34) == 512); // window
    assert(read_int16(packet + 38) == 7); // urgent pointer
    assert(memcmp(packet + 40, spec.tcp_options, 20) == 0);
    assert(transport_checksum(packet, len, IPPROTO_TCP) == 0);
    free(packet);

    // No options and the maximum of 40 bytes, without the reserved bit
    size_t option_lengths[] = {0, 40};
    spec.reseved_bit = false;
    for (size_t i = 0; i < 2; i++) {
        spec.tcp_options_len = option_lengths[i];
        packet = construct_TCP_packet(spec, "10.0.0.1", &len);
        assert(packet != NULL);
        assert(len == 40 + option_lengths[i]);
        assert((packet[32] >> 4) == (20 + option_lengths[i]) / 4);
        assert((packet[32] & 0x0F) == 0);
        assert(transport_checksum(packet, len, IPPROTO_TCP) == 0);
        free(packet);
    }

    // Invalid: options too long, options not a multiple of 4, missing arguments
    len = 99;
    spec.tcp_options_len = 44;
    assert(construct_TCP_packet(spec, "10.0.0.1", &len) == NULL);
    assert(len == 0);

    spec.tcp_options_len = 6;
    assert(construct_TCP_packet(spec, "10.0.0.1", &len) == NULL);

    spec.tcp_options_len = 0;
    assert(construct_TCP_packet(spec, NULL, &len) == NULL);
    assert(construct_TCP_packet(spec, "10.0.0.1", NULL) == NULL);
}

static void test_construct_icmp(void) {
    uint8_t payload[5] = {1, 2, 3, 4, 5};
    struct icmp_probe spec = {
        .dest_ip = "10.0.0.2",
        .icmp_type = 8,
        .icmp_code = 9,
        .icmp_identifier = 0x1234,
        .icmp_sequence = 295,
        .ip_DF = true,
        .ip_TOS = 0x04,
        .ip_id = 0xBEEF,
        .payload = payload,
        .payload_len = sizeof(payload),
    };
    size_t len = 0;

    // Every field of a packet with a payload and the DF flag
    uint8_t *packet = construct_ICMP_packet(spec, "10.0.0.1", &len);
    assert(packet != NULL);
    assert(len == 33);
    check_ip_header(packet, len, IPPROTO_ICMP);
    assert(packet[1] == 0x04); // TOS
    assert(read_int16(packet + 4) == 0xBEEF); // IP ID
    assert(read_int16(packet + 6) == IP_DF);
    assert(packet[8] == 64); // TTL
    assert(packet[20] == 8); // ICMP type
    assert(packet[21] == 9); // ICMP code
    assert(read_int16(packet + 24) == 0x1234); // identifier
    assert(read_int16(packet + 26) == 295); // sequence number
    assert(memcmp(packet + 28, payload, sizeof(payload)) == 0);
    assert(calculate_checksum(packet + 20, len - 20) == 0);
    free(packet);

    // No DF flag and an empty payload
    spec.ip_DF = false;
    spec.payload_len = 0;
    packet = construct_ICMP_packet(spec, "10.0.0.1", &len);
    assert(packet != NULL);
    assert(len == 28);
    assert(read_int16(packet + 6) == 0);
    assert(calculate_checksum(packet + 20, len - 20) == 0);
    free(packet);

    // Invalid: missing arguments, payload that does not fit in an IP packet
    assert(construct_ICMP_packet(spec, NULL, &len) == NULL);
    assert(construct_ICMP_packet(spec, "10.0.0.1", NULL) == NULL);
    len = 99;
    spec.payload_len = UINT16_MAX - 28 + 1;
    assert(construct_ICMP_packet(spec, "10.0.0.1", &len) == NULL);
    assert(len == 0);
}

static void test_construct_udp(void) {
    struct udp_probe spec = {
        .dest_ip = "10.0.0.2",
        .source_port = 200,
        .dest_port = 81,
        .ip_id = 0x1042,
        .ip_ttl = 64,
    };
    memset(spec.payload, 'C', sizeof(spec.payload));

    // Empty, odd and maximum payload
    size_t payload_lengths[] = {0, 5, 300};
    for (size_t i = 0; i < 3; i++) {
        size_t len = 99;
        uint16_t checksum = 99;

        spec.payload_len = payload_lengths[i];
        uint8_t *packet = construct_UDP_packet(spec, "10.0.0.1", &len, &checksum);
        assert(packet != NULL);
        assert(len == 28 + payload_lengths[i]);
        check_ip_header(packet, len, IPPROTO_UDP);
        assert(read_int16(packet + 4) == 0x1042);            // IP ID
        assert(packet[8] == 64);                       // TTL from the probe
        assert(read_int16(packet + 20) == 200);              // source port
        assert(read_int16(packet + 22) == 81);               // destination port
        assert(read_int16(packet + 24) == 8 + payload_lengths[i]);
        assert(read_int16(packet + 26) == checksum);         // the returned checksum is the one in the packet
        assert(memcmp(packet + 28, spec.payload, payload_lengths[i]) == 0);
        assert(transport_checksum(packet, len, IPPROTO_UDP) == 0);
        free(packet);
    }

    // Invalid: payload too long (outputs are reset), bad or missing addresses and outputs
    size_t len = 99;
    uint16_t checksum = 99;
    spec.payload_len = 301;
    assert(construct_UDP_packet(spec, "10.0.0.1", &len, &checksum) == NULL);
    assert(len == 0 && checksum == 0);

    spec.payload_len = 0;
    struct udp_probe bad_destination = spec;
    bad_destination.dest_ip = "not an ip";
    struct udp_probe no_destination = spec;
    no_destination.dest_ip = NULL;

    assert(construct_UDP_packet(spec, "not an ip", &len, &checksum) == NULL);
    assert(construct_UDP_packet(bad_destination, "10.0.0.1", &len, &checksum) == NULL);
    assert(construct_UDP_packet(no_destination, "10.0.0.1", &len, &checksum) == NULL);
    assert(construct_UDP_packet(spec, NULL, &len, &checksum) == NULL);
    assert(construct_UDP_packet(spec, "10.0.0.1", NULL, &checksum) == NULL);
    assert(construct_UDP_packet(spec, "10.0.0.1", &len, NULL) == NULL);
}

int main(void) {
    test_construct_tcp();
    test_construct_icmp();
    test_construct_udp();

    printf("All packet construction tests passed successfully.\n");
    return 0;
}