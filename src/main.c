#include "packet_validator.h"
#include "packets.h"


int main()
{
    uint16_t sizeOfPackets = sizeof(packets) / sizeof(packets[0]);
    uint16_t sizeOfPacket  = 0;
    packet_validor_ErrorType_e errorType = VALID_PACKET;

    //!< iterate through the packets array
    for (int i = 0; i < sizeOfPackets; i++)
    {
        sizeOfPacket = strlen(packets[i]);
        
        printf("size: %d \t", sizeOfPacket );
        errorType = packet_validator_validateAsciiEncodedPacket(packets[i], sizeOfPacket);

        switch (errorType)
        {
        case VALID_PACKET:
            printf("packet[%d] is valid.\n", i);
            break;

        case INCOMPLETE_PACKET:
            printf("packet[%d] is incomplete.\n", i);
            break;

        case INVALID_TYPE:
            printf("packet[%d] has an invalid type in the header.\n", i);
            break;

        case INVALID_SUBTYPE:
            printf("packet[%d] has an invalid sub-type in the header.\n", i);
            break;

        case INCORRECT_WRAPPER_CHECKSUM:
            printf("packet[%d] has an invalid wrapper checksum.\n", i);
            break;

        case INCORRECT_DATA_PORTION_CHECKSUM:
            printf("packet[%d] has an invalid checksum for one of the chunks of the data portion.\n", i);
            break;

        case INCORRECT_LAST_DATA_PORTION_CHECKSUM:
            printf("packet[%d] has an invalid checksum for the last data portion.\n", i);
            break;

        case ZERO_DATA:
            printf("packet[%d] has an ZERO data in data portion.\n", i);
            break;

        case PACKET_LARGER_THAN_16_CHUNKS:
            printf("packet[%d] has more than 16 data chunks and can not processed at this moment. See next release. \n", i);
            break;

        default:
            printf("No packet to test. \n");
            break;
        }
   }

    return 0;
}