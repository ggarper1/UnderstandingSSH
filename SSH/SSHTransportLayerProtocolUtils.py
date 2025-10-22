import re
import secrets

class SSH_Transport_Layer_Protocol_Utils():

    #
    # ID STRING RELATED VARIABLES
    #
    
    MAX_CHAR_LEN_ID_STRING = 255

    #
    # KEY EXCHANGE RELATED VARIBLES
    #

    LENGTH_COOKIE = 16

    #
    # MESSAGE CODES
    #

    MSG_CODE = {
        "SSH_MSG_DISCONNECT"        :   1,
        "SSH_MSG_IGNORE"            :   2,
        "SSH_MSG_UNIMPLEMENTED"     :   3,
        "SSH_MSG_DEBUG"             :   4,
        "SSH_MSG_SERVICE_REQUEST"   :   5,
        "SSH_MSG_SERVICE_ACCEPT"    :   6,
        "SSH_MSG_KEXINIT"           :   20,
        "SSH_MSG_NEWKEYS"           :   21
    }    
    DISCONNECT_MSG_CODES = {
        "SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT"    :   1,
        "SSH_DISCONNECT_PROTOCOL_ERROR"                 :   2,
        "SSH_DISCONNECT_KEY_EXCHANGE_FAILED"            :   3,
        "SSH_DISCONNECT_RESERVED"                       :   4,
        "SSH_DISCONNECT_MAC_ERROR"                      :   5,
        "SSH_DISCONNECT_COMPRESSION_ERROR"              :   6,
        "SSH_DISCONNECT_SERVICE_NOT_AVAILABLE"          :   7,
        "SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED" :   8,
        "SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE"        :   9,
        "SSH_DISCONNECT_CONNECTION_LOST"                :   10,
        "SSH_DISCONNECT_BY_APPLICATION"                 :   11,
        "SSH_DISCONNECT_TOO_MANY_CONNECTIONS"           :   12,
        "SSH_DISCONNECT_AUTH_CANCELLED_BY_USER"         :   13,
        "SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE" :   14,
        "SSH_DISCONNECT_ILLEGAL_USER_NAME"              :   15
    }

    #
    # Supported Algorithms
    #

    SUPPORTED_MAC_ALGORITHMS = [
        "hmac-sha256",      # OPTIONAL      I have added this
        "hmac-sha1",        # REQUIRED      HMAC-SHA1
        "hmac-sha1-96",     # RECOMMENDED   first 96 bits of HMAC-SHA1
        "hmac-md5",         # OPTIONAL      HMAC-MD5
        "hmac-md5-96",      # OPTIONAL      first 96 bits of HMAC-MD5
        "none"              # OPTIONAL      no MAC; NOT RECOMMENDED
    ]
    SUPPORTED_KEY_EXCHANGE_METHODS = [
        "diffie-hellman-group1-sha1",       # REQUIRED
        "diffie-hellman-group14-sha1"       # REQUIRED
    ]
    SUPPORTED_COMPRESSION_ALGORITHMS = [
        "zlib",             # OPTIONAL      ZLIB (LZ77) compression
        "none"              # REQUIRED      no compression
    ]
    SUPPORTED_PUBLIC_KEY_ALGORITHMS = [
        "ssh-dss"           # REQUIRED     sign   Raw DSS Key
        "ssh-rsa"           # RECOMMENDED  sign   Raw RSA Key
        "pgp-sign-rsa"      # OPTIONAL     sign   OpenPGP certificates (RSA key)
        "pgp-sign-dss"      # OPTIONAL     sign   OpenPGP certificates (DSS key)
    ]

    def create_id_str(protoversion:str, sw_version:str, comments:str=None):
        """
        Description:
            Generates a identification string with the SSH format. More about this format's requirements in `check_identification_string`.

        Parameters:
            `sw_version`: softwareversion part of the SSH format.
            `comments`: comments part of the SSH format.

        Returns:
            A SSH identification string or an empty string if any of the parameters don't follow the SSH requirements. 
        """
        id_str = f"SSH-{protoversion}-{sw_version}"
        if comments is not None: id_str += f" {comments}"
        return id_str + "\r\n"

    def check_identification_str(id_str:str):
        """
        Description:
            This function checks if the identification string provided as a parameter follows the SSH convention. The requirements are the following:
                - The string must have the following format:

                    SSH-{protoversion}-{softwareversion} SP {comments} CR LF
                
                where:
                    - SP, CR and LF are space, cariage return and line feed   character respectively.
                    - {protoversion} is the version of the SSH protocol.
                    - {softwareversion} is #TODO (add to docs what is this for) and it only contains US ASCII printable characters except whitspace and '-'.
                    - {comments} is #TODO (add to docs what is this for) and can contain any US ASCII printable characters.

                - The whole string cannot be more than 255 characters long.

                - {protoversion} should be "2.0" or "1.x".

                - {softwareversion} must only contain US-ASCII printable characters except for whitspaces and the minus sign '-'.

                - {comments} there are no clear restrictions so I will assume all printable characters are allowed.

                - The string cannot contain the null character.
        
        Parameters:
            `id_str`: identification string to check.

        Returns:
            True if `id_str` follows the format, false otherwise.

        Notes:
            I will not implement compatibility with SSH versions previous to 2.0. An identification string with version other than 2.0 will be rejected.
        """
        pattern = fr'^SSH-2.0-[\x21-\x7E]+( [\x20-\x7E]+)?\r\n'
        return len(id_str) > 255 or re.match(pattern, id_str) is not None
    
    def create_kex_packet(first_kex_packet_follows:bool, config:dict):
        """
        Description:
            Creates a key exchange packet. This packet contains the following fields:
                byte         SSH_MSG_KEXINIT
                byte[16]     cookie (random bytes)
                name-list    kex_algorithms
                name-list    server_host_key_algorithms
                name-list    encryption_algorithms_client_to_server
                name-list    encryption_algorithms_server_to_client
                name-list    mac_algorithms_client_to_server
                name-list    mac_algorithms_server_to_client
                name-list    compression_algorithms_client_to_server
                name-list    compression_algorithms_server_to_client
                name-list    languages_client_to_server
                name-list    languages_server_to_client
                boolean      first_kex_packet_follows
                uint32       0 (reserved for future extension)

        """
        content = SSH_Transport_Layer_Protocol_Utils.MSG_CODE["SSH_MSG_KEXINIT"].to_bytes(1)
        content += secrets.token_bytes(16)
        for arg in args:
            content += SSH_Transport_Layer_Protocol_Utils.name_list_to_bytes(arg)
        content += first_kex_packet_follows.to_bytes(1)
        content += (0).to_bytes(4)
        return content
    




    def name_list_to_bytes(l:list):
        content = ','.join(l).encode()
        return len(content).to_bytes(4) + content
    
    def bytes_to_name_lists(b:bytes):
        lists = []
        index = 0
        while index >= len(b):
            length = int(b[index:index+4])
            index += 4
            name_list = b[index:index+length].decode().split(',')
            index += length
            list.append(name_list)
        return lists
    
    # def generate_base_packet(payload: bytearray, cipher_block_size:int):
    #     """
    #     Description:
    #         Given the payload, it creates a packet to be encrypted and sent. The packet contains:
    #             1. Packet length field (4 bytes long)
    #             2. Random padding length field (1 byte long)
    #             3. Payload
    #             4. Random Padding

    #         Restrictions are:
    #             1. Random padding has to be at least 4 bytes long and no more than 255 bytes long.
    #             2. Packet minimum size is 16.
    #             3. Length of 1, 2, 3 and 4 must be multiple of the cipher block size or 8 if the cipher block size is smaller than 8.

    #     Parameters:
    #         `paylaod`: the payload of the packet.

    #     Returns:
    #         A byte array containing the all 4 components concatenated in that order.
    #     """
    #     PACKET_FIELD_LENGTH = 4
    #     PADDING_FIELD_LENGTH =  1
    #     len_payload = len(payload)
    #     len_no_padding = PACKET_FIELD_LENGTH + PADDING_FIELD_LENGTH + len_payload
    #     c = cipher_block_size if cipher_block_size > 8 else 8
    #     len_padding = (c - (len_no_padding % c))

    #     if len_padding < 4: len_padding += c
        
    #     assert len_padding > 3, "Padding length has te be at lest 4 bytes!"
    #     assert len_padding < 256, "Padding length can't be more than 255 bytes!"
    #     assert (len_no_padding + len_padding) % c == 0, "Length of fields excluding the HMAC have to be multiple of ciphe block size or 8!"

    #     packet_lenght_bytes = (PADDING_FIELD_LENGTH + len_payload + len_padding).to_bytes(4)
    #     padding_length_byte = len_padding.to_bytes(1)



    #     return packet_lenght_bytes + padding_length_byte + payload + padding_bytes

