'''
Module for ICMP functions used by custompk
'''

from socket import inet_ntoa
from framebuilder.tools import to_bytes, calc_chksum, get_value_at, \
                               ipv4_addr_encode

class ICMPv4Message():
    '''
    Implements a generic ICMP message
    '''

    def __init__(self, icmp_data=None):
        '''
        Initialize generic ICMP message with generic header data
        :param icmp_data: <dict> generic header data
        {
            'type': <int> Message type (1 Byte),
            'code': <int> ICMP code (1 Byte),
            'checksum': <int> ICMP checksum (2 Bytes),
            'payload': <bytes> further message data
        }
        '''
        if icmp_data is None:
            icmp_data = {}

        self._type = icmp_data.get('type', 0)
        self._code = icmp_data.get('code', 0)
        self._checksum = icmp_data.get('checksum', None)
        self._payload = icmp_data.get('payload', b'')


    @classmethod
    def from_bytes(cls, hdr_bytes):
        '''
        create ICMP message from bytes
        '''
        hdr_data = {}
        try:
            hdr_data['type'] = get_value_at(hdr_bytes, 1, 0)
            hdr_data['code'] = get_value_at(hdr_bytes, 1, 1)
            hdr_data['checksum'] = get_value_at(hdr_bytes, 2, 2)
            if len(hdr_bytes) > 4:
                # Check if we can return a known ICMP message type...
                if hdr_data['type'] == 0:
                    hdr_data['identifier'] = get_value_at(hdr_bytes, 2, 4)
                    hdr_data['seq_nr'] = get_value_at(hdr_bytes, 2, 6)
                    hdr_data['data'] = hdr_bytes[8:]
                    return ICMPEchoReply(hdr_data)

                if hdr_data['type'] == 3:
                    hdr_data['data'] = hdr_bytes[8:]
                    return ICMPDestinationUnreachable(hdr_data)

                if hdr_data['type'] == 5:
                    gw_addr = get_value_at(hdr_bytes, 4, 4)
                    hdr_data['gateway_ip'] = inet_ntoa(gw_addr)
                    hdr_data['data'] = hdr_bytes[8:]
                    return ICMPRedirect(hdr_data)

                if hdr_data['type'] == 8:
                    hdr_data['identifier'] = get_value_at(hdr_bytes, 2, 4)
                    hdr_data['seq_nr'] = get_value_at(hdr_bytes, 2, 6)
                    hdr_data['data'] = hdr_bytes[8:]
                    return ICMPEchoRequest(hdr_data)

                if hdr_data['type'] == 11:
                    hdr_data['data'] = hdr_bytes[8:]
                    return ICMPTimeExceeded(hdr_data)

                if hdr_data['type'] == 12:
                    hdr_data['pointer'] = get_value_at(hdr_bytes, 1, 4)
                    hdr_data['data'] = hdr_bytes[8:]
                    return ICMPParameterProblem(hdr_data)
                #...or a generic (i.e. unknown) one
                hdr_data['payload'] = hdr_bytes[4:]
            return cls(hdr_data)
        except:
            print('Failed to extract ICMP header data')


    @classmethod
    def from_ipv4_packet(cls, ipv4_packet):
        '''
        Create ICMP Message from IPv4 payload
        '''
        return cls.from_bytes(ipv4_packet.payload)


    def get_dict(self):
        '''
        Returns ICMP message data as dictionary
        '''
        icmp_data = {}
        icmp_data['type'] = self.icmp_type
        icmp_data['code'] = self.icmp_code
        icmp_data['checksum'] = self.icmp_checksum
        icmp_data['payload'] = self.payload
        return icmp_data


    def get_bytes(self):
        '''
        returns ICMP message as bytes
        '''
        hdr_bytes = b''
        hdr_bytes += to_bytes(self.icmp_type, 1)
        hdr_bytes += to_bytes(self.icmp_code, 1)
        hdr_bytes += to_bytes(self.icmp_checksum, 2)
        hdr_bytes += self.payload
        return hdr_bytes


    def update_checksum(self):
        '''
        updates ICMP checksum
        '''
        self._checksum = 0
        icmp_msg = self.get_bytes()
        checksum = calc_chksum(icmp_msg + (b'\x00' * (len(icmp_msg) % 2)))
        self._checksum = checksum


    def encapsulate(self, packet):
        '''
        Encapsulate ICMPv4 message in IPv4 packet
        :param packet: IPv4 packet object
        '''
        packet.payload = self.get_bytes()


    def __get_type(self):
        '''
        Getter for ICMP type
        '''
        return self._type


    def __set_type(self, icmp_type):
        '''
        Setter for ICMP type
        '''
        self._checksum = None
        self._type = icmp_type

    icmp_type = property(__get_type, __set_type)


    def __get_code(self):
        '''
        Getter for ICMP code
        '''
        return self._code


    def __set_code(self, icmp_code):
        '''
        Setter for ICMP code
        '''
        self._checksum = None
        self._code = icmp_code

    icmp_code = property(__get_code, __set_code)


    def __get_chksum(self):
        '''
        Getter for ICMP checksum
        '''
        if self._checksum is None:
            self.update_checksum()
        return self._checksum


    def __set_chksum(self, icmp_checksum):
        '''
        Setter for ICMP checksum
        '''
        self._checksum = icmp_checksum

    icmp_checksum = property(__get_chksum, __set_chksum)


    def __get_payload(self):
        '''
        Getter for payload
        '''
        return self._payload


    def __set_payload(self, payload):
        '''
        Setter for payload
        Caution: If payload is accessed from a child class, metadata that is
        specific for this child (e.g. identifier and sequence number with echo
        requests) will be overwritten as payload consists of that metadata AND
        payload bytes. Use the data attribute instead if you just want to add
        arbitrary bytes after the type-specific header information.
        '''
        self._checksum = None
        self._payload = payload

    payload = property(__get_payload, __set_payload)


    def info(self):
        '''
        Print generic ICMP message information
        '''
        print('ICM Type            : ' + str(self.icmp_type))
        print('ICM Code            : ' + str(self.icmp_code))
        print('ICM Checksum        : 0x' + format(self.icmp_checksum, '04x'))
        print('ICM message length  : ' + str(4 + len(self.payload)))


class ICMPEchoRequest(ICMPv4Message):
    '''
    Create an ICMP echo request

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |       8       |       0       |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Identifier          |        Sequence Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Data ...
    +-+-+-+-+-
    '''

    def __init__(self, data=None):
        '''
        Initialize ICMP echo request
        {
            'identifier': <int> Identifier (2 Bytes),
            'seq_nr': <int> Sequence number (2 Bytes),
            'data': <bytes> payload data
        }
        '''

        if data is None:
            data = {}

        super().__init__()

        self.icmp_type = 8
        self.icmp_code = 0

        self._identifier = data.get('identifier', 0)
        self._sequence_number = data.get('seq_nr', 0)
        self._data = data.get('data', b'')

        self.payload = to_bytes(self._identifier, 2) + \
                       to_bytes(self._sequence_number, 2) + \
                       self._data


    def get_dict(self):
        '''
        Returns ICMP message data as dictionary
        '''
        icmp_data = {}
        icmp_data['type'] = self.icmp_type
        icmp_data['code'] = self.icmp_code
        icmp_data['checksum'] = self.icmp_checksum
        icmp_data['identifier'] = self.identifier
        icmp_data['seq_nr'] = self.sequence_number
        icmp_data['data'] = self.data
        return icmp_data


    def info(self):
        '''
        Print specific ICMP message information
        '''
        super().info()
        print('ICM Message Type    : Echo request')
        print('ICM Identifier      : ' + str(self.identifier))
        print('ICM Sequence Number : ' + str(self.sequence_number))


    def __get_identifier(self):
        '''
        Getter for identifier
        '''
        return self._identifier


    def __set_identifier(self, identifier):
        '''
        Setter for identifier
        '''
        self._identifier = identifier
        self.payload = to_bytes(self._identifier, 2) + \
                       to_bytes(self._sequence_number, 2) + \
                       self._data

    identifier = property(__get_identifier, __set_identifier)


    def __get_sequence_number(self):
        '''
        Getter for sequence number
        '''
        return self._sequence_number


    def __set_sequence_number(self, sequence_number):
        '''
        Setter for sequence_number
        '''
        self._sequence_number = sequence_number
        self.payload = to_bytes(self._identifier, 2) + \
                       to_bytes(self._sequence_number, 2) + \
                       self._data

    sequence_number = property(__get_sequence_number, __set_sequence_number)


    def __get_data(self):
        '''
        Getter for data
        '''
        return self._data


    def __set_data(self, data):
        '''
        Setter for data
        '''
        self._data = data
        self.payload = to_bytes(self._identifier, 2) + \
                       to_bytes(self._sequence_number, 2) + \
                       self._data

    data = property(__get_data, __set_data)


class ICMPEchoReply(ICMPv4Message):
    '''
    Create an ICMP echo reply

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |       0       |       0       |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Identifier          |        Sequence Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Data ...
    +-+-+-+-+-
    '''

    def __init__(self, data=None):
        '''
        Initialize ICMP echo reply
        {
            'identifier': <int> Identifier (2 Bytes),
            'seq_nr': <int> Sequence number (2 Bytes),
            'data': <bytes> payload data
        }
        '''

        if data is None:
            data = {}

        super().__init__()

        self.icmp_type = 0
        self.icmp_code = 0

        self._identifier = data.get('identifier', 0)
        self._sequence_number = data.get('seq_nr', 0)
        self._data = data.get('data', b'')

        self.payload = to_bytes(self._identifier, 2) + \
                       to_bytes(self._sequence_number, 2) + \
                       self._data


    def get_dict(self):
        '''
        Returns ICMP message data as dictionary
        '''
        icmp_data = {}
        icmp_data['type'] = self.icmp_type
        icmp_data['code'] = self.icmp_code
        icmp_data['checksum'] = self.icmp_checksum
        icmp_data['identifier'] = self.identifier
        icmp_data['seq_nr'] = self.sequence_number
        icmp_data['data'] = self.data
        return icmp_data


    def info(self):
        '''
        Print specific ICMP message information
        '''
        super().info()
        print('ICM Message Type    : Echo repy')
        print('ICM Identifier      : ' + str(self.identifier))
        print('ICM Sequence Number : ' + str(self.sequence_number))


    def __get_identifier(self):
        '''
        Getter for identifier
        '''
        return self._identifier


    def __set_identifier(self, identifier):
        '''
        Setter for identifier
        '''
        self._identifier = identifier
        self.payload = to_bytes(self._identifier, 2) + \
                       to_bytes(self._sequence_number, 2) + \
                       self._data

    identifier = property(__get_identifier, __set_identifier)


    def __get_sequence_number(self):
        '''
        Getter for sequence number
        '''
        return self._sequence_number


    def __set_sequence_number(self, sequence_number):
        '''
        Setter for sequence_number
        '''
        self._sequence_number = sequence_number
        self.payload = to_bytes(self._identifier, 2) + \
                       to_bytes(self._sequence_number, 2) + \
                       self._data

    sequence_number = property(__get_sequence_number, __set_sequence_number)


    def __get_data(self):
        '''
        Getter for data
        '''
        return self._data


    def __set_data(self, data):
        '''
        Setter for data
        '''
        self._data = data
        self.payload = to_bytes(self._identifier, 2) + \
                       to_bytes(self._sequence_number, 2) + \
                       self._data

    data = property(__get_data, __set_data)


class ICMPDestinationUnreachable(ICMPv4Message):
    '''
    Create a destination unreachable message

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             unused                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Internet Header + 64 bits of Original Data Datagram      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ICMP codes:
    0 = net unreachable
    1 = host unreachable
    2 = protocol unreachable
    3 = port unreachable
    4 = fragmentation needed and DF set
    5 = source route failed
    '''

    def __init__(self, data=None):
        '''
        Initialize ICMP destination unreachble message
        {
            'icmp_code': <int> Identifier (1 Byte),
            'data': <bytes> payload data
        }
        '''

        if data is None:
            data = {}

        super().__init__()

        self.icmp_type = 3

        self.icmp_code = data.get('icmp_code', 0)
        self._data = data.get('data', b'')

        self.payload = b'\x00\x00\x00\x00' + self._data


    def __get_type_str(self):
        '''
        Returns specific message type string
        '''
        t_str = {0:'Net unreachable',
                 1:'Host unreachable',
                 2:'Protocol unreachable',
                 3:'Port unreachable',
                 4:'Fragmentation needed and DF set',
                 5:'Source route failed'}
        return t_str.get(self.icmp_code, 'unknown')


    def get_dict(self):
        '''
        Returns ICMP message data as dictionary
        '''
        icmp_data = {}
        icmp_data['type'] = self.icmp_type
        icmp_data['code'] = self.icmp_code
        icmp_data['checksum'] = self.icmp_checksum
        icmp_data['data'] = self.data
        return icmp_data


    def info(self):
        '''
        Print specific ICMP message information
        '''
        super().info()
        print('ICM Message Type    : Destination unreachable')
        print('-> Specific Message : ' + self.__get_type_str())


    def __get_data(self):
        '''
        Getter for data
        '''
        return self._data


    def __set_data(self, data):
        '''
        Setter for data
        '''
        self._data = data
        self.payload = b'\x00\x00\x00\x00' + \
                       self._data

    data = property(__get_data, __set_data)


class ICMPTimeExceeded(ICMPv4Message):
    '''
    Create a time exceeded message

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             unused                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Internet Header + 64 bits of Original Data Datagram      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ICMP codes:
    0 = time to live exceeded in transit
    1 = fragment reassembly time exceeded
    '''

    def __init__(self, data=None):
        '''
        Initialize ICMP time exceeded message
        {
            'icmp_code': <int> Identifier (1 Byte),
            'data': <bytes> payload data
        }
        '''

        if data is None:
            data = {}

        super().__init__()

        self.icmp_type = 11

        self.icmp_code = data.get('icmp_code', 0)
        self._data = data.get('data', b'')

        self.payload = b'\x00\x00\x00\x00' + \
                       self._data


    def __get_type_str(self):
        '''
        Returns specific message type string
        '''
        t_str = {0:'Time to live exceeded in transit',
                 1:'fragment reassembly time exceeded'}
        return t_str.get(self.icmp_code, 'unknown')


    def get_dict(self):
        '''
        Returns ICMP message data as dictionary
        '''
        icmp_data = {}
        icmp_data['type'] = self.icmp_type
        icmp_data['code'] = self.icmp_code
        icmp_data['checksum'] = self.icmp_checksum
        icmp_data['data'] = self.data
        return icmp_data


    def info(self):
        '''
        Print specific ICMP message information
        '''
        super().info()
        print('ICM Message Type    : Time exceeded')
        print('-> Specific Message : ' + self.__get_type_str())


    def __get_data(self):
        '''
        Getter for data
        '''
        return self._data


    def __set_data(self, data):
        '''
        Setter for data
        '''
        self._data = data
        self.payload = b'\x00\x00\x00\x00' + \
                       self._data

    data = property(__get_data, __set_data)


class ICMPParameterProblem(ICMPv4Message):
    '''
    Create a parameter problem message

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Pointer    |             unused                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Internet Header + 64 bits of Original Data Datagram      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    The pointer identifies the octet of the original datagram's header
    where the error was detected (it may be in the middle of an
    option).  For example, 1 indicates something is wrong with the
    Type of Service, and (if there are options present) 20 indicates
    something is wrong with the type code of the first option.
    '''

    def __init__(self, data=None):
        '''
        Initialize ICMP parameter problem message
        {
            'icmp_code': <int> Identifier (1 Byte),
            'pointer': <int> Identifier (1 Byte),
            'data': <bytes> payload data
        }
        '''

        if data is None:
            data = {}

        super().__init__()

        self.icmp_type = 12

        self.icmp_code = data.get('icmp_code', 0)
        self._pointer = data.get('pointer', 0)
        self._data = data.get('data', b'')

        self.payload = to_bytes(self._pointer, 1) + \
                       b'\x00\x00\x00' + \
                       self._data


    def __get_param_str(self):
        '''
        Returns IP header field string represented by pointer
        '''
        p_str = {0:'Version or IHL',
                 1:'Type of Service',
                 2:'Total Length',
                 4:'Identification',
                 6:'Flags or Fragment Offset',
                 8:'Time to Live',
                 9:'Protocol',
                 10:'Header Checksum',
                 12:'Source Address',
                 16:'Destination Address'}
        return p_str.get(self.pointer, 'Option')


    def get_dict(self):
        '''
        Returns ICMP message data as dictionary
        '''
        icmp_data = {}
        icmp_data['type'] = self.icmp_type
        icmp_data['code'] = self.icmp_code
        icmp_data['checksum'] = self.icmp_checksum
        icmp_data['pointer'] = self.pointer
        icmp_data['data'] = self.data
        return icmp_data


    def info(self):
        '''
        Print specific ICMP message information
        '''
        super().info()
        print('ICM Message Type    : Parameter Problem')
        p_str = self.__get_param_str()
        print('ICM Pointer         : {} ({})'.format(self.pointer, p_str))


    def __get_pointer(self):
        '''
        Getter for pointer
        '''
        return self._data


    def __set_pointer(self, pointer):
        '''
        Setter for pointer
        '''
        self._pointer = pointer
        self.payload = to_bytes(self._pointer, 1) + \
                       b'\x00\x00\x00' + \
                       self._data

    pointer = property(__get_pointer, __set_pointer)


    def __get_data(self):
        '''
        Getter for data
        '''
        return self._data


    def __set_data(self, data):
        '''
        Setter for data
        '''
        self._data = data
        self.payload = to_bytes(self._pointer, 1) + \
                       b'\x00\x00\x00' + \
                       self._data

    data = property(__get_data, __set_data)


class ICMPRedirect(ICMPv4Message):
    '''
    Create a redirect message

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 Gateway Internet Address                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Internet Header + 64 bits of Original Data Datagram      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ICMP codes:
    0 = Redirect datagrams for the Network.
    1 = Redirect datagrams for the Host.
    2 = Redirect datagrams for the Type of Service and Network.
    3 = Redirect datagrams for the Type of Service and Host.

    The gateway sends a redirect message to a host in the following
    situation.  A gateway, G1, receives an internet datagram from a
    host on a network to which the gateway is attached.  The gateway,
    G1, checks its routing table and obtains the address of the next
    gateway, G2, on the route to the datagram's internet destination
    network, X.  If G2 and the host identified by the internet source
    address of the datagram are on the same network, a redirect
    message is sent to the host.  The redirect message advises the
    host to send its traffic for network X directly to gateway G2 as
    this is a shorter path to the destination.  The gateway forwards
    the original datagram's data to its internet destination.
    '''

    def __init__(self, data=None):
        '''
        Initialize ICMP redirect message
        {
            'icmp_code': <int> Identifier (1 Byte),
            'gateway_ip': <str> Gateway IP address
            'data': <bytes> payload data
        }
        '''

        if data is None:
            data = {}

        super().__init__()

        self.icmp_type = 5

        self.icmp_code = data.get('icmp_code', 0)
        self._gateway_ip = data.get('gateway_ip', '0.0.0.0')
        self._data = data.get('data', b'')

        self.payload = ipv4_addr_encode(self._gateway_ip) + \
                       self._data


    def __get_redir_str(self):
        r_str = {0:'Network',
                 1:'Host',
                 2:'Service and Network',
                 3:'Service and Host'}
        return r_str.get(self.icmp_code, 'Option')


    def get_dict(self):
        '''
        Returns ICMP message data as dictionary
        '''
        icmp_data = {}
        icmp_data['type'] = self.icmp_type
        icmp_data['code'] = self.icmp_code
        icmp_data['checksum'] = self.icmp_checksum
        icmp_data['gateway_ip'] = self.gateway_ip
        icmp_data['data'] = self.data
        return icmp_data


    def info(self):
        '''
        Print specific ICMP message information
        '''
        super().info()
        print('ICM Message Type    : Redirect')
        print('ICM Redirect for    : ' + self.__get_redir_str())
        print('Suggested Gateway   : ' + self.gateway_ip)


    def __get_data(self):
        '''
        Getter for data
        '''
        return self._data


    def __set_data(self, data):
        '''
        Setter for data
        '''
        self._data = data
        self.payload = ipv4_addr_encode(self._gateway_ip) + \
                       self._data

    data = property(__get_data, __set_data)


    def __get_gateway_ip(self):
        '''
        Getter for gateway IP address
        '''
        return self._gateway_ip


    def __set_gateway_ip(self, gateway_ip):
        '''
        Setter for gateway IP address
        '''
        self._gateway_ip = gateway_ip
        self.payload = ipv4_addr_encode(self._gateway_ip) + \
                       self._data

    gateway_ip = property(__get_gateway_ip, __set_gateway_ip)
