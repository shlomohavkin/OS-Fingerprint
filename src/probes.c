#include <probes.h>


struct tcp_probe *sequence_generation_TCP_spec(uint16_t source_port, uint16_t dest_port, char *dest_ip) {
    struct tcp_probe *tcp_probes = malloc(6 * sizeof(struct tcp_probe));
    if (tcp_probes == NULL) {
        perror("Failed to allocate memory for TCP probes");
        exit(EXIT_FAILURE);
    }

    uint32_t base_seq_num = rand(); 
    uint32_t base_ack_num = rand();

    tcp_probes[0] = (struct tcp_probe){
        .dest_ip = dest_ip,
        .source_port = source_port,
        .dest_port = dest_port,
        .seq_num = base_seq_num,
        .ack_num = base_ack_num,
        .tcp_flags = TH_SYN, // SYN
        .window_size = 1,
        .urgent_pointer = 0,
        .reseved_bit = false,
        .tcp_options = {
            TCPOPT_WINDOW, TCPOLEN_WINDOW, 0x0A, // winow scale = 10
            TCPOPT_NOP, // NOP
            TCPOPT_MAXSEG, TCPOLEN_MAXSEG, 0x05, 0xB4, // MSS = 1460
            TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP, // Timestamp
            0xFF, 0xFF, 0xFF, 0xFF, // Timestamp TSval
            0x00, 0x00, 0x00, 0x00, // Timestamp TSecr
            TCPOPT_SACK_PERMITTED, TCPOLEN_SACK_PERMITTED, // SACK permitted
        },
        .tcp_options_len = 20
    };
    tcp_probes[1] = (struct tcp_probe){
        .dest_ip = dest_ip,
        .source_port = source_port + 1,
        .dest_port = dest_port,
        .seq_num = base_seq_num + 1,
        .ack_num = base_ack_num,
        .tcp_flags = TH_SYN, // SYN
        .window_size = 63,
        .urgent_pointer = 0,
        .reseved_bit = false,
        .tcp_options = {
            TCPOPT_MAXSEG, TCPOLEN_MAXSEG, 0x05, 0x78, // MSS = 1400
            TCPOPT_WINDOW, TCPOLEN_WINDOW, 0x00, // winow scale = 0
            TCPOPT_SACK_PERMITTED, TCPOLEN_SACK_PERMITTED, // SACK permitted
            TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP, // Timestamp
            0xFF, 0xFF, 0xFF, 0xFF, // Timestamp TSval
            0x00, 0x00, 0x00, 0x00, // Timestamp TSecr
            TCPOPT_EOL, // EOL
        },
        .tcp_options_len = 20
    };
    tcp_probes[2] = (struct tcp_probe){
        .dest_ip = dest_ip,
        .source_port = source_port + 2,
        .dest_port = dest_port,
        .seq_num = base_seq_num + 2,
        .ack_num = base_ack_num,
        .tcp_flags = TH_SYN, // SYN
        .window_size = 4,
        .urgent_pointer = 0,
        .reseved_bit = false,
        .tcp_options = {
            TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP, // Timestamp
            0xFF, 0xFF, 0xFF, 0xFF, // Timestamp TSval
            0x00, 0x00, 0x00, 0x00, // Timestamp TSecr
            TCPOPT_NOP, // NOP
            TCPOPT_NOP, // NOP
            TCPOPT_WINDOW, TCPOLEN_WINDOW, 0x05, // winow scale = 5
            TCPOPT_NOP, // NOP
            TCPOPT_MAXSEG, TCPOLEN_MAXSEG, 0x02, 0x80, // MSS = 640
        },
        .tcp_options_len = 20
    };
    tcp_probes[3] = (struct tcp_probe){
        .dest_ip = dest_ip,
        .source_port = source_port + 3,
        .dest_port = dest_port,
        .seq_num = base_seq_num + 3,
        .ack_num = base_ack_num,
        .tcp_flags = TH_SYN, // SYN
        .window_size = 4,
        .urgent_pointer = 0,
        .reseved_bit = false,
        .tcp_options = {
            TCPOPT_SACK_PERMITTED, TCPOLEN_SACK_PERMITTED, // SACK permitted
            TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP, // Timestamp
            0xFF, 0xFF, 0xFF, 0xFF, // Timestamp TSval
            0x00, 0x00, 0x00, 0x00, // Timestamp TSecr
            TCPOPT_WINDOW, TCPOLEN_WINDOW, 0x0A, // winow scale = 10
            TCPOPT_EOL, // EOL
        },
        .tcp_options_len = 16
    };
    tcp_probes[4] = (struct tcp_probe){
        .dest_ip = dest_ip,
        .source_port = source_port + 4,
        .dest_port = dest_port,
        .seq_num = base_seq_num + 4,
        .ack_num = base_ack_num,
        .tcp_flags = TH_SYN, // SYN
        .window_size = 16,
        .urgent_pointer = 0,
        .reseved_bit = false,
        .tcp_options = {
            TCPOPT_MAXSEG, TCPOLEN_MAXSEG, 0x02, 0x18, // MSS = 536
            TCPOPT_SACK_PERMITTED, TCPOLEN_SACK_PERMITTED, // SACK permitted
            TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP, // Timestamp
            0xFF, 0xFF, 0xFF, 0xFF, // Timestamp TSval
            0x00, 0x00, 0x00, 0x00, // Timestamp TSecr
            TCPOPT_WINDOW, TCPOLEN_WINDOW, 0x0A, // winow scale = 10
            TCPOPT_EOL, // EOL
        },
        .tcp_options_len = 20
    };
    tcp_probes[5] = (struct tcp_probe){
        .dest_ip = dest_ip,
        .source_port = source_port + 5,
        .dest_port = dest_port,
        .seq_num = base_seq_num + 5,
        .ack_num = base_ack_num,
        .tcp_flags = TH_SYN, // SYN
        .window_size = 512,
        .urgent_pointer = 0,
        .reseved_bit = false,
        .tcp_options = {
            TCPOPT_MAXSEG, TCPOLEN_MAXSEG, 0x01, 0x09, // MSS = 265
            TCPOPT_SACK_PERMITTED, TCPOLEN_SACK_PERMITTED, // SACK permitted
            TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP, // Timestamp
            0xFF, 0xFF, 0xFF, 0xFF, // Timestamp TSval
            0x00, 0x00, 0x00, 0x00, // Timestamp TSecr
        },
        .tcp_options_len = 16
    };
    

    return tcp_probes;
}

struct icmp_probe *ICMP_echo_probe_spec(uint16_t source_port, uint16_t dest_port, char *dest_ip) {
    struct icmp_probe *icmp_probes = malloc(2 * sizeof(struct icmp_probe));
    srand((unsigned)time(NULL));

    icmp_probes[0] = (struct icmp_probe){
        .dest_ip = dest_ip,
        .source_port = source_port,
        .dest_port = dest_port,
        .icmp_type = 8, // Echo Request
        .icmp_code = 9,
        .icmp_identifier = rand(),
        .icmp_sequence = 295,
        .ip_DF = true,
        .ip_TOS = 0x00,
        .ip_id = rand(),
        .payload_len = 120,
        .payload = calloc(120, sizeof(uint8_t)),
    };

    icmp_probes[1] = (struct icmp_probe){
        .dest_ip = dest_ip,
        .source_port = source_port + 1,
        .dest_port = dest_port,
        .icmp_type = 8, // Echo Request
        .icmp_code = 0,
        .icmp_identifier = icmp_probes[0].icmp_identifier + 1,
        .icmp_sequence = 296,
        .ip_DF = false,
        .ip_TOS = 0x04,
        .ip_id = rand(),
        .payload_len = 150,
        .payload = calloc(150, sizeof(uint8_t)),
    };

    if (icmp_probes[0].payload == NULL || icmp_probes[1].payload == NULL) {
        free(icmp_probes);
        perror("Failed to allocate memory for ICMP payload");
        exit(EXIT_FAILURE);
    }
    return icmp_probes;
}

struct tcp_probe *tcp_ecn_probe_spec(uint16_t source_port, uint16_t dest_port, char *dest_ip) {
    struct tcp_probe *tcp_probe = malloc(sizeof(struct tcp_probe));
    if (tcp_probe == NULL) {
        perror("Failed to allocate memory for TCP probes");
        exit(EXIT_FAILURE);
    }

    uint32_t base_seq_num = rand(); 

    *tcp_probe = (struct tcp_probe){
        .dest_ip = dest_ip,
        .source_port = source_port,
        .dest_port = dest_port,
        .seq_num = base_seq_num,
        .ack_num = 0,
        .tcp_flags = TH_SYN | 0x40 | 0x80, // set SYN, ECN-Echo, and CWR flags
        .window_size = 3,
        .urgent_pointer = 0xF7F5,
        .reseved_bit = true,
        .tcp_options = {
            TCPOPT_WINDOW, TCPOLEN_WINDOW, 0x0A, // winow scale = 10
            TCPOPT_NOP, // NOP
            TCPOPT_MAXSEG, TCPOLEN_MAXSEG, 0x05, 0xB4, // MSS = 1460
            TCPOPT_SACK_PERMITTED, TCPOLEN_SACK_PERMITTED, // SACK permitted
            TCPOPT_NOP, // NOP
            TCPOPT_NOP, // NOP
        },
        .tcp_options_len = 20
    };

    return tcp_probe;
}
