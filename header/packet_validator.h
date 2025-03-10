#ifndef PACKET_VALIDATOR__H
#define PACKET_VALIDATOR__H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>


#define DATA_CHUNK_MAX_LENGTH (34)
#define SOF_HEADER_OFFSET    (2)
typedef enum
{
    VALID_PACKET,
    INCOMPLETE_PACKET,
    INVALID_TYPE,
    INVALID_SUBTYPE,
    INCORRECT_WRAPPER_CHECKSUM,
    INCORRECT_DATA_PORTION_CHECKSUM,
    INCORRECT_LAST_DATA_PORTION_CHECKSUM,
    ZERO_DATA,
    PACKET_LARGER_THAN_16_CHUNKS
} packet_validor_ErrorType_e;

packet_validor_ErrorType_e packet_validator_validateAsciiEncodedPacket(uint8_t packet[], uint16_t size);

#endif // PACKET_VALIDATOR__H