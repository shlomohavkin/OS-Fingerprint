#ifndef STRUCTURES_H
#define STRUCTURES_H

enum probe_status {
    PROBE_NOT_SENT,
    PROBE_WAITING,
    PROBE_RECEIVED,
    PROBE_NO_RESPONSE,
    PROBE_SEND_FAILED
};

struct tcp_probe_res {
    unsigned probe_id;         /* Identifies SEQ1, SEQ2, ECN, T2, etc. */
    enum probe_status status;

    struct in_addr src_ip;      /* Source IP address of the received packet */
    struct in_addr dst_ip;      /* Destination IP address of the received packet */

    struct tcp_probe probe_sent; /* The probe specification used to generate the packet */


    struct timespec sent_at;   /* Actual send time: CLOCK_MONOTONIC */

    struct parsed_info parsed_response;

    // bool syn_ack_received;
    // bool ack_matched;
};

#endif /* STRUCTURES_H */