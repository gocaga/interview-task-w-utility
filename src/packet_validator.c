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
    uint64_t calculated_multi_chunk_checksum[16][1];

    uint8_t last_data_chunk_chksum[3];
    uint8_t n_data_chunks = 0;
    if (size == 4) //!< 4 bytes plus the null terminator
    {
        return ZERO_DATA;
    }
    else if (size <= 38)
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
        multiple_chunk_data_portion_length = sizeof(multiple_chunk_data_portion) / sizeof(multiple_chunk_data_portion[0]);
        n_data_chunks = multiple_chunk_data_portion_length / 34;
        uint8_t packet_index = SOF_HEADER_OFFSET;

        if(n_data_chunks >= 16) return PACKET_LARGER_THAN_16_CHUNKS;
        
        for (int i = 0; i < n_data_chunks; i++)
        {
            for (int j = 0; j <= DATA_CHUNK_MAX_LENGTH; j++)
            {
                multiple_chunk_array[i][j] = packet[packet_index];
                packet_index++;
            }
        }

        //!< Check for data portion checksum in each of the 34 byte data chunks
        uint8_t chunk_checksums[n_data_chunks][3];
        uint32_t multi_chunk_checksum_deci[n_data_chunks];
        
        for (int i = 0; i < n_data_chunks; i++)
        {
            chunk_checksums[i][0] = multiple_chunk_array[i][DATA_CHUNK_MAX_LENGTH - 2];
            chunk_checksums[i][1] = multiple_chunk_array[i][DATA_CHUNK_MAX_LENGTH - 1];
            chunk_checksums[i][2] = '\0';
            multi_chunk_checksum_deci[i] = strtol(chunk_checksums[i], NULL, 16);
        }

        //!< Get the calculated checksum for all chunks to the nth one
        for (int i = 0; i < n_data_chunks; i++)
        {
            for (int j = 0; j < (DATA_CHUNK_MAX_LENGTH - 2); j++)
            {
                calculated_multi_chunk_checksum[i][0] += multiple_chunk_array[i][j]; //!< sum the 32 bytes e.g. from 0 to 31st index
            }

            calculated_multi_chunk_checksum[i][0] %= 256;

            if (calculated_multi_chunk_checksum[i][0] != multi_chunk_checksum_deci[i])
            {
                return INCORRECT_DATA_PORTION_CHECKSUM;
            }
        }

        packet_index--; //!< cheating to cater for the increased packet_index when exiting the for-loop

        //!< Capture the last chunk
        for (int k = 0; k < (multiple_chunk_data_portion_length % 34); k++)
        {
            multiple_chunk_array[n_data_chunks + 1][k] = packet[packet_index];

            //!< Get the calculated checksum for the last chunk
            if (k < ((multiple_chunk_data_portion_length % 34) - 2))
            {
                calculated_last_multi_checksum += multiple_chunk_array[n_data_chunks + 1][k];
            }
            packet_index++;
        }

        //!< Check for data in the last data chunk
        last_data_chunk_chksum[0] = multiple_chunk_array[n_data_chunks + 1][(multiple_chunk_data_portion_length % 34) - 2];
        last_data_chunk_chksum[1] = multiple_chunk_array[n_data_chunks + 1][(multiple_chunk_data_portion_length % 34) - 1];
        last_data_chunk_chksum[2] = '\0' ;
        long int last_chunk_checksum_deci = strtol(last_data_chunk_chksum, NULL, 16);

        //!< get the calculated checksum for the last chunk
        calculated_last_multi_checksum %= 256;
        if (calculated_last_multi_checksum != last_chunk_checksum_deci)
        {
            return INCORRECT_LAST_DATA_PORTION_CHECKSUM;
        }
    }

    return VALID_PACKET;
}