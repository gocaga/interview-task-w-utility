#include "packet_validator.h"

/**
 * @brief This function validates ASCII encoded protocol packets as per Interview Task D_004574    
 * 
 * @param packet 
 * @param size 
 * @return packet_validor_ErrorType_e 
 */
packet_validor_ErrorType_e packet_validator_validateAsciiEncodedPacket(uint8_t packet[], uint16_t size)
{
    uint16_t calculated_wrapper_checksum = 0;
    packet_validator_AsciiPacket_t asciiPacket;

    asciiPacket.type    = packet[0];
    asciiPacket.subType = packet[1];

    asciiPacket.wrapperCheckSum[0] = packet[size - 2];
    asciiPacket.wrapperCheckSum[1] = packet[size - 1];
    
    uint16_t data_index = 0;
    for(int n = 2; n <= (size); n++)
    {        
        asciiPacket.data[data_index] = packet[n];
        data_index++;
    }
   
    //!< Check for an incomplete packer
    if ((size) < 4) //!< Factoring the null terminator of the array
    {
        return INCOMPLETE_PACKET;
    }

    //!< Check for invalid type in the packet header
    if ((!(packet[0] >= 'A' && packet[0] <= 'Z')))
    {
        return INVALID_TYPE;
    }

    //!< Check for invalid sub-typen in the packet header
    if (!((packet[1] >= 'A' && packet[1] <= 'Z') || (packet[1] >= '0' && packet[1] <= '9')))
    {
        return INVALID_SUBTYPE;
    }

    calculated_wrapper_checksum = (packet[0] + packet[1]) % 256;

    uint8_t wrapper_checksum_hex[3];
    wrapper_checksum_hex[0] = packet[size - 2];
    wrapper_checksum_hex[1] = packet[size - 1];
    wrapper_checksum_hex[2] = '\0';

    uint16_t wrapper_checksum_deci = strtol(wrapper_checksum_hex, NULL, 16);

    //!< Check for invalid wrapper checksum
    if (!(wrapper_checksum_deci == calculated_wrapper_checksum))
    {
        return INCORRECT_WRAPPER_CHECKSUM;
    }

    uint64_t chunk_checksum        = 0;
    uint16_t data_portion_length   = 0;
    uint16_t multiple_chunk_data_portion_length = 0;
    uint64_t sum_of_chunk_checksum = 0;
    uint16_t calculated_last_multi_checksum     = 0;

    uint8_t data_portion[(size - 4)];
    uint8_t multiple_chunk_data_portion[size - 4];
    uint8_t multiple_chunk_array[10][DATA_CHUNK_MAX_LENGTH];
    uint64_t calculated_multi_chunk_checksum[10][1];

    uint8_t last_data_chunk_chksum[3];
    uint8_t n_data_chunks = 0;
    if (size == 4) //!< @note using strlen() so no need to worry about the null terminator
    {
        return ZERO_DATA;
    }
    else if (size < 39)  //!< packet with one chunk of 3 to 34 bytes
    {
        //!< Process packet with a single chunk
        uint8_t packet_index = 0;
        uint8_t data_index   = 0;
        for (packet_index = 2; packet_index < (size - 4); packet_index++)
        {
            data_portion[data_index] = packet[packet_index];
            data_index++;
        }

        data_portion_length = sizeof(data_portion) / sizeof(data_portion[0]);

        //!< Calculate the chuck checksum and validate the data
        for (int i = 0; i < (data_portion_length - 2); i++)
        {
            sum_of_chunk_checksum += (uint16_t)data_portion[i];
        }

        chunk_checksum = sum_of_chunk_checksum % 256;

        // Convert the last 2 bytes of the data portion to decimal for comparison with calculated checksum
        //!< @todo [GO] Intellectual Debt: repeated code that needs extracting into a function
        uint8_t chunk_one_chcksum[3];
        chunk_one_chcksum[0] = packet[size - 4];
        chunk_one_chcksum[1] = packet[size - 3];
        chunk_one_chcksum[2] = '\0';

        long int chunk_one_checksum_deci = strtol(chunk_one_chcksum, NULL, 16);

        if (!(chunk_one_checksum_deci == chunk_checksum))
        {            
            return INCORRECT_DATA_PORTION_CHECKSUM;
        }
    }
    else
    {
        //!< Validate a packet with multiple chunks
        uint16_t dataLength      = strlen(asciiPacket.data);
        uint16_t n_data_chunks   = dataLength / DATA_CHUNK_MAX_LENGTH;
        uint8_t bytesInLastChunk = dataLength % DATA_CHUNK_MAX_LENGTH;
        size_t checksum_summation[10][1];
        uint16_t calcualtedChecksum_nDataChunk[10][1];

        uint8_t chunk_checksums[n_data_chunks][3];
        uint16_t multi_chunk_checksum_deci[n_data_chunks];

        for (int j = 0; j < n_data_chunks; j++)
        {
            for (int k = 0; k < (DATA_CHUNK_MAX_LENGTH - 2); k++)
            {
                checksum_summation[j][0] += asciiPacket.data[k];
            }

            calcualtedChecksum_nDataChunk[j][0] = checksum_summation[j][0] % 256;

            chunk_checksums[j][0] = asciiPacket.data[DATA_CHUNK_MAX_LENGTH - 2];
            chunk_checksums[j][1] = asciiPacket.data[DATA_CHUNK_MAX_LENGTH - 1];
            chunk_checksums[j][2] = '\0';
            multi_chunk_checksum_deci[j] = strtol(chunk_checksums[j], NULL, 16);

            if (multi_chunk_checksum_deci[j] != calcualtedChecksum_nDataChunk[j][0])
            {
                return INCORRECT_DATA_PORTION_CHECKSUM;
            }
        }

        ///!< Check for data in the last data chunk
    }

    return VALID_PACKET;
}