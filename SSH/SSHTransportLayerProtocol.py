import socket
from SSH.SSHTransportLayerProtocolUtils import SSH_Transport_Layer_Protocol_Utils
from utils import Logs


class SSH_Transport_Layer_Protocol():
    
    SSH_PROTOVERSION = "2.0"

    # Valid keys for configuration dictionary
    VALID_CONFIGS = [
            "DEFAULT_KEX_ALGS",
            "SERVER_HOST_KEY_ALGS",
            "ENCRYP_CLIENT_TO_SERVER_ALGS",
            "ENCRYP_SERVER_TO_CLIENT_ALGS",
            "MAC_CLIENT_TO_SERVER_ALGS",
            "MAC_SERVER_TO_CLIENT_ALGS",
            "COMPRSS_CLIENT_TO_SERVER_ALGS" ,
            "COMPRSS_SERVER_TO_CLIENT_ALGS",
            "LANGUAGES_CLIENT_TO_SERVER",
            "LANGUAGES_SERVER_TO_CLIENT"
        ]
    
    # key exchange algorithms
    DEFAULT_KEX_ALGS = [] #TODO: fill up
    # 
    SERVER_HOST_KEY_ALGS = [] #TODO: fill up
    #
    ENCRYP_CLIENT_TO_SERVER_ALGS = [] #TODO: fill up
    #
    ENCRYP_SERVER_TO_CLIENT_ALGS = [] #TODO: fill up
    #
    MAC_CLIENT_TO_SERVER_ALGS = [
        "hmac-sha1-96", # RECOMMENDED     first 96 bits of HMAC-SHA1
        "hmac-sha1",    # REQUIRED        HMAC-SHA1
        "hmac-sha256",  # OPTIONAL        HMAC-SHA256
        "hmac-md5",     # OPTIONAL        HMAC-MD5
        "hmac-md5-96",  # OPTIONAL        first 96 bits of HMAC-MD5
        "none"          # OPTIONAL        no MAC; NOT RECOMMENDED
    ]
    #
    MAC_SERVER_TO_CLIENT_ALGS = [
        "hmac-sha1-96", # RECOMMENDED     first 96 bits of HMAC-SHA1
        "hmac-sha1",    # REQUIRED        HMAC-SHA1
        "hmac-sha256",  # OPTIONAL        HMAC-SHA256
        "hmac-md5",     # OPTIONAL        HMAC-MD5
        "hmac-md5-96",  # OPTIONAL        first 96 bits of HMAC-MD5
        "none"          # OPTIONAL        no MAC; NOT RECOMMENDED
    ]
    #
    COMPRSS_CLIENT_TO_SERVER_ALGS = [
        "none",         # REQUIRED        no compression
        "zlib"          # OPTIONAL        ZLIB (LZ77) compression
    ]
    #
    COMPRSS_SERVER_TO_CLIENT_ALGS = [
        "none",         # REQUIRED        no compression
        "zlib"          # OPTIONAL        ZLIB (LZ77) compression
    ]
    #
    LANGUAGES_CLIENT_TO_SERVER = [] #TODO: fill up
    #
    LANGUAGES_SERVER_TO_CLIENT = [] #TODO: fill up
    
    # DEFAULT_PUBLIC_KEY_ALGS = [
    #     "ssh-rsa",      # RECOMMENDED  sign   Raw RSA Key
    #     "ssh-dss",      # REQUIRED     sign   Raw DSS Key
    #     "pgp-sign-rsa", # OPTIONAL     sign   OpenPGP certificates (RSA key)
    #     "pgp-sign-dss", # OPTIONAL     sign   OpenPGP certificates (DSS key)
    # ]

    
    """ Constructors """
    def server(port:int, config:dict={}):
        return SSH_Transport_Layer_Protocol(port=port, ip="localhost", server_role=True, config=config)

    def client(port:int, ip:str, config:dict={}):
        return SSH_Transport_Layer_Protocol(port=port, ip=ip, server_role=False, config=config)

    def __init__(self, ip:str, port:int, server_role:bool, config:dict):
        self.ip = ip
        self.port = port
        self.server_role = server_role
        self.connection = None
        self.id_str = None

        self.__set_up_config(config)
    

    """ Configuration """
    def __set_up_config(self, config:dict):
        self.config = {
            "DEFAULT_KEX_ALGS" : SSH_Transport_Layer_Protocol.DEFAULT_KEX_ALGS,
            "SERVER_HOST_KEY_ALGS" : SSH_Transport_Layer_Protocol.SERVER_HOST_KEY_ALGS,
            "ENCRYP_CLIENT_TO_SERVER_ALGS" : SSH_Transport_Layer_Protocol.ENCRYP_CLIENT_TO_SERVER_ALGS,
            "ENCRYP_SERVER_TO_CLIENT_ALGS" : SSH_Transport_Layer_Protocol.ENCRYP_SERVER_TO_CLIENT_ALGS,
            "MAC_CLIENT_TO_SERVER_ALGS" : SSH_Transport_Layer_Protocol.MAC_CLIENT_TO_SERVER_ALGS,
            "MAC_SERVER_TO_CLIENT_ALGS" : SSH_Transport_Layer_Protocol.MAC_SERVER_TO_CLIENT_ALGS,
            "COMPRSS_CLIENT_TO_SERVER_ALGS" : SSH_Transport_Layer_Protocol.COMPRSS_CLIENT_TO_SERVER_ALGS,
            "COMPRSS_SERVER_TO_CLIENT_ALGS" : SSH_Transport_Layer_Protocol.COMPRSS_SERVER_TO_CLIENT_ALGS,
            "LANGUAGES_CLIENT_TO_SERVER" : SSH_Transport_Layer_Protocol.LANGUAGES_CLIENT_TO_SERVER,
            "LANGUAGES_SERVER_TO_CLIENT" : SSH_Transport_Layer_Protocol.LANGUAGES_SERVER_TO_CLIENT
        }

        for k,v in config.items():
            if k in SSH_Transport_Layer_Protocol.VALID_CONFIGS:
                self.config = v 
    

    """ With Methods """
    # Notes about whith methods:
    #     1. If an error occurs in `__enter__`, `__exit__` is not called.
    def __enter__(self):
        self.__connect_socket()
        self.__protocol_verion_exchange(sw_version="None", comments="None")
        self.__algorithm_negotiation()
        self.__key_exchange()
    
    def __exit__(self, *exc_details):
        self.connection.close()


    """ Connection """
    # 1st Step: Connect the sockets
    def __connect_socket(self):
        """
            Description:
                Connects sockets needed for comunication.

            Parameters: None

            Returns: Nothing
        """
        if self.server_role: # It's role is a server's role
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("localhost", self.port))
                s.listen(1)
                self.connection, _ = s.accept()
        else: # It's a client
            self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connection.connect((self.ip, self.port))

    # 2nd Step: Change ID strings
    def __protocol_verion_exchange(self, sw_version:str, comments:str):
        """
            Description:
                Does a ID String exchange and raises a exception if they are not compatible.
            
            Parameters:
                `sw_version`: software version part of the ID string. Used to create own ID string
                `comments`: comments part of the ID string. Used to create iwn ID string.
            
            Returns: Nothing
        """
        if self.server_role: # It's role is of a server
            others_id_str = self.connection.recv(SSH_Transport_Layer_Protocol_Utils.MAX_CHAR_LEN_ID_STRING*2).decode()

            self.id_str = SSH_Transport_Layer_Protocol_Utils.create_id_str(SSH_Transport_Layer_Protocol.SSH_PROTOVERSION, sw_version, comments=comments)
            self.connection.send(self.id_str.encode())
        else: # It's a client
            self.id_str = SSH_Transport_Layer_Protocol_Utils.create_id_str(SSH_Transport_Layer_Protocol.SSH_PROTOVERSION, sw_version, comments=comments)

            self.connection.send(self.id_str.encode())
            others_id_str = self.connection.recv(SSH_Transport_Layer_Protocol_Utils.MAX_CHAR_LEN_ID_STRING*2).decode()
        
        compatible, msg = self.__compare_id_strs(others_id_str)

        if not compatible:
            Logs.error(msg=msg, additional=f"Own ID string: {repr(self.id_str)}\n\tOther's ID string: {repr(others_id_str)}")

    # 3rd Step: Algorithm Negotiation
    def __algorithm_negotiation(self):
        """
            Description:
                Recieves configuration preferences and chooses them for communication.
        """
        if self.server_role:
            # Recieve
        else:
            # Send
            pass
     
    # 4th Step: Key exchange
    def __key_exchange(self):
        pass
        # if self.server_role: # It's a server
        #     text = self.connection.recv(8**6).decode()
        #     print(text)
        # else:
        #     algorithms = SSH_Transport_Layer_Protocol_Utils.create_kex_packet(
        #         False,
        #         ["hello","world"],
        #         ["hello","world"],
        #         ["hello","world"],
        #         ["hello","world"],
        #         ["hello","world"],
        #         ["hello","world"],
        #         ["hello","world"],
        #         ["hello","world"],
        #         ["hello","world"],
        #         ["hello","world"]
        #     )
        #     self.connection.send()
    

    """ Private Methods """
    def __compare_id_strs(self, other_id_str:str):
        """
        Description:
            Checks if a recieved id string and a sent one are compatible.
        
        Parameters:
            `other_id_str`: recieved id string.

        Returns:
            Returns a boolean value and a string. The boolean value will be true if the ID strings are compatible, false otherwise. The string will be empty if they are compatible or a short description of why they aren't. 
        
        Notes:
            Any version that's not 2.0 will be rejected.
        
        TODO (1*): Handle comments and software-version
        """
        if not SSH_Transport_Layer_Protocol_Utils.check_identification_str(other_id_str):
            return False, "Other's side id string does not follow SSH's format! "
        
        l_self, l_other = self.id_str.split('-', maxsplit=2), other_id_str.split('-', maxsplit=2)
        self_protoversion, others_protoversion = l_other[1], l_self[1]
        if self_protoversion != others_protoversion:
            return False, "Own and other's version of SSH protocol do not match!"
        
        if others_protoversion != SSH_Transport_Layer_Protocol.SSH_PROTOVERSION:
            return False, f"Error: any protocol version other than {SSH_Transport_Layer_Protocol.SSH_PROTOVERSION} is not accepted!"

        # 1*

        return True, ""


    """ API Methods """
    def send():
        pass
    
    def recieve():
        pass