# UnderstandingSSH
This os project made to understand the SSH Protocol.

## Steps:
1. Client initiates the connection: client establishes the connection with the server using TCP.
    Notes:
    - Oficial port is 22
2. Cliente sends a identification string:
    The string must match the following convention:
        SSH-protoversion-softwareversion SP comments CR LF
    where:
        - `protoversion` is the version of the SSH protocol
    Notes:
        - maximum length is 255 characters

## Notes:
- SSH's oficial port is 22. I will not use this due to potencial interferences with real ssh protocol
- I will no implement compatbility with any version of protocol that is not 2.0


## Documentation
https://www.ssh.com/academy/ssh/protocol#typical-uses-of-the-ssh-protocol
