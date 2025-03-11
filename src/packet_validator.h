#ifndef PACKET_VALIDATOR__H
#define PACKET_VALIDATOR__H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DATA_CHUNK_MAX_LENGTH  (34)
#define SOF_HEADER_OFFSET      (2)
#define DATA_PORTION_MAX_BYTES (340)
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
} packet_validator_ErrorType_e;

typedef struct
{
    uint8_t type;
    uint8_t subType;
    uint8_t data[DATA_PORTION_MAX_BYTES];
    uint8_t wrapperCheckSum[2];

}packet_validator_AsciiPacket_t;

/**
 * @brief This function validates ASCII encoded protocol packets as per Interview Task D_004574    
 * 
 * @param packet 
 * @param size 
 * @return packet_validator_ErrorType_e 
 */
packet_validator_ErrorType_e packet_validator_validateAsciiEncodedPacket(uint8_t packet[], uint16_t size);

#endif // PACKET_VALIDATOR__H