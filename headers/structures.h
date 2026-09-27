#ifndef STRUCTURES_H
#define STRUCTURES_H



#define SEQ1 0
#define SEQ2 1
#define SEQ3 2
#define SEQ4 3
#define SEQ5 4
#define SEQ6 5
#define ECN 6
#define IE1 7
#define IE2 8
#define T2 9
#define T3 10
#define T4 11
#define T5 12
#define T6 13
#define T7 14
#define U1 15

#define SEQ_PROBE_COUNT 6
#define NUM_ICMP_PROBES 2
#define ECN_INDEX SEQ_PROBE_COUNT + 2 // Sequence probes (6) + 2 ICMP probes = 8
#define TX_COUNT 6
#define NUM_PROBES_SENT (SEQ_PROBE_COUNT + 1 + 2 + TX_COUNT + 1) // 6 sequence probes + 1 ECN probe + 2 ICMP probes + 6 T2-T7 probes + 1 U1 probe = 16 

#define SRC_PORT_INIT 1000

enum probe_status {
    PROBE_NOT_SENT,
    PROBE_WAITING,
    PROBE_RECEIVED,
    PROBE_NO_RESPONSE,
    PROBE_SEND_FAILED
};

struct probe_result {
    unsigned probe_id;         /* Identifies SEQ1, SEQ2, ECN, T2, etc. */
    enum probe_status status;

    struct in_addr src_ip;      /* Source IP address of the received packet */
    struct in_addr dst_ip;      /* Destination IP address of the received packet */

    enum probe_type {
        TCP_PROBE,
        ICMP_PROBE,
        UDP_PROBE
    } probe_type;

    union {
        struct tcp_probe tcp; // The probe specification used to generate the packet 
        struct icmp_probe icmp; 
        struct udp_probe udp; 
    } probe_sent;


    struct timespec sent_at;   /* Actual send time: CLOCK_MONOTONIC */

    struct parsed_info parsed_response;

    // bool syn_ack_received;
    // bool ack_matched;
};

#endif