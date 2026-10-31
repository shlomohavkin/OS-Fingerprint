#include "packet.h"
#include <assert.h>
#include <stdio.h>
#include <stdint.h>


int main(void) {
    uint8_t all_zeros[] = {0x0, 0x0, 0x0, 0x0};
    uint8_t all_ones[] = {0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t odd_len_data[] = {0x01, 0x02, 0x03};
    uint8_t real_data[] = {0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00,
                           0x40, 0x06, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x02,
                           0xC0, 0xA8, 0x01, 0x01};

    uint16_t checksum_zeros = calculate_checksum(all_zeros, sizeof(all_zeros));
    assert(checksum_zeros == 0xFFFF);

    uint16_t checksum_ones = calculate_checksum(all_ones, sizeof(all_ones));
    assert(checksum_ones == 0x0000);

    uint16_t checksum_odd_len = calculate_checksum(odd_len_data, sizeof(odd_len_data));
    assert(checksum_odd_len == 0xFBFD);

    uint16_t checksum_real_data = calculate_checksum(real_data, sizeof(real_data));
    assert(checksum_real_data == 0x9B22);

    printf("All checksum tests passed successfully.\n\n");
    return 0;
}