'''Module for IPv4 functions'''

from socket import inet_aton, inet_ntoa
from copy import copy
from random import randrange
from math import ceil
from framebuilder.errors import InvalidIPv4AddrException, \
                                IncompleteIPv4HeaderException, \
                                InvalidInterfaceException, \
                                InvalidHeaderValueException
from framebuilder.defs import get_iana_protocol_str
from framebuilder import tools
from framebuilder import eth

MAX_TTL = 64

class IPv4Option:
    '''
    Create an IPv4 option
    '''

    def __init__(self, opt_data=None):
        '''
        Initialize IPv4 option
        :param opt_data: dictionary containing options data as follows
        {
            'option_type': <int> 1 byte option type identifier,
            'option_length': <int> 1 byte option length,
            'option_data': <bytes> option data
        }
        '''
        if opt_data is None:
            opt_data = {}

        self._otype = opt_data.get('option_type', 0) & 0xff
        self._olength = opt_data.get('option_length', None)
        self._odata = opt_data.get('option_data', None)

        if self._olength is not None:
            self._olength &= 0xff


    @classmethod
    def from_bytes(cls, opt_bytes):
        '''
        Initialize IPv4 options object from bytes
        :param opt_bytes: <bytes> data
        '''
        opt_data = {}

        if len(opt_bytes) >= 1:
            opt_data['option_type'] = tools.get_value_at(opt_bytes, 1, 0)
        if len(opt_bytes) > 1:
            opt_data['option_length'] = tools.get_value_at(opt_bytes, 1, 1)
        if len(opt_bytes) > 2:
            opt_data['option_data'] = opt_bytes[2:]
        return cls(opt_data)


    def info(self):
        '''
        Print option information
        '''
        print('OPT Type            : ' + str(self._otype))
        if self._olength is not None and self._odata is not None:
            print('OPT Length          : ' + str(self._olength))
            print('OPT Data            : ' + str(self._odata))


    def get_length(self):
        '''
        Get option length
        '''
        if self._olength is not None:
            return self._olength
        return 1


    def get_bytes(self):
        '''
        Return option as bytes
        '''
        otype = tools.to_bytes(self._otype, 1)
        if self._olength is not None and self._odata is not None:
            olength = tools.to_bytes(self._olength, 1)
            return bytes(otype + olength + self._odata)
        return otype


    def get_dict(self):
        '''
        Return option data as dictionary
        '''
        return {'option_type': self._otype,
                'option_length': self._olength,
                'option_data': self._odata}


class IPv4Packet:
    '''
    Create an IPv4 packet according to RFC 791

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    According to RFC 2474 the IPv4 TOS field is now used as the
    DS (Differentiated Service) Field
    '''

    def __init__(self, ip4_data=None):
        '''
        Initialize IPv4 packet
        :param ip4_data: Dictionary containing packet information as follows
        {
            'version': <int> protocol version (4),
            'ihl': <int> header length (number of 32 Bit words)
            'tos': <int> type of service / ds-field,
            'total_length': <int> total length field,
            'identification': <int> identification value for fragments,
            'flags': <int> [0b0xy] x=don't fragment / y=more fragments,
            'frag_offset': <int> fragment offset,
            'ttl': <int> time to live,
            'protocol': <int> payload protocol identifier,
            'checksum': <int> header checksum,
            'src_addr': <string> source address,
            'dst_addr': <string> destination address,
            'options': []<dict> List of IPv4 option dictionaries
            'payload': <bytes>
        }
        :param isfragment: <bool> True if packet is a fragment
        '''

        if ip4_data is None:
            ip4_data = {}

        src_addr_str = ip4_data.get('src_addr', '0.0.0.0')
        dst_addr_str = ip4_data.get('dst_addr', '0.0.0.0')

        if tools.is_valid_ipv4_address(src_addr_str):
            self._src_addr = src_addr_str
        else:
            raise InvalidIPv4AddrException(src_addr_str)

        if tools.is_valid_ipv4_address(dst_addr_str):
            self._dst_addr = dst_addr_str
        else:
            raise InvalidIPv4AddrException(dst_addr_str)

        self._version = ip4_data.get('version', 4)
        self._ihl = ip4_data.get('ihl', 5)
        self._tos = ip4_data.get('tos', 0)
        self._total_length = ip4_data.get('total_length', None)
        self._identification = ip4_data.get('identification', 0)
        self._flags = ip4_data.get('flags', 0)
        self._frag_offset = ip4_data.get('frag_offset', 0)
        self._ttl = ip4_data.get('ttl', MAX_TTL)
        self._protocol = ip4_data.get('protocol', 0)
        self._checksum = ip4_data.get('checksum', None)
        self._payload = ip4_data.get('payload', b'')
        self._options = []
        if ip4_data.get('options', None) is not None:
            for opt in ip4_data['options']:
                next_option = IPv4Option(opt)
                self._options.append(next_option)


    @classmethod
    def from_bytes(cls, ip4_bytes):
        '''
        create IPv4 packet from bytes
        '''
        ip4_data = {}

        if len(ip4_bytes) < 20:
            raise IncompleteIPv4HeaderException(ip4_bytes)

        ver_ihl = tools.get_value_at(ip4_bytes, 1, 0)
        ip4_data['version'] = ver_ihl >> 4
        ip4_data['ihl'] = ver_ihl & 0b1111
        ip4_data['tos'] = tools.get_value_at(ip4_bytes, 1, 1)
        ip4_data['total_length'] = tools.get_value_at(ip4_bytes, 2, 2)
        ip4_data['identification'] = tools.get_value_at(ip4_bytes, 2, 4)
        flags_fr_offset = tools.get_value_at(ip4_bytes, 2, 6)
        ip4_data['flags'] = flags_fr_offset >> 13
        ip4_data['frag_offset'] = flags_fr_offset & 0b1111111111111
        ip4_data['ttl'] = tools.get_value_at(ip4_bytes, 1, 8)
        ip4_data['protocol'] = tools.get_value_at(ip4_bytes, 1, 9)
        ip4_data['checksum'] = tools.get_value_at(ip4_bytes, 2, 10)
        ip4_data['src_addr'] = inet_ntoa(tools.get_bytes_at(ip4_bytes, \
                                                               4, 12))
        ip4_data['dst_addr'] = inet_ntoa(tools.get_bytes_at(ip4_bytes, \
                                                               4, 16))
        ip4_data['options'] = []
        if ip4_data['ihl'] > 5:
            options = ip4_bytes[20:ip4_data['ihl']*4]
            index = 0
            while index < len(options):
                if options[index] == 0 or \
                   options[index] == 1:
                    opt = {'option_type': options[index]}
                    ip4_data['options'].append(opt)
                    index += 1
                else:
                    olength = int(options[index+1])
                    opt = {'option_type': int(options[index]),
                           'option_length': int(options[index+1]),
                           'option_data': options[index+2:index + olength]}
                    ip4_data['options'].append(opt)
                    index += olength
        ip4_data['payload'] = ip4_bytes[ip4_data['ihl']*4:]
        return cls(ip4_data)


    def get_dict(self):
        '''
        Return header data as dictionary
        '''
        dct = {
            'version': self.version,
            'ihl': self.ihl,
            'tos': self.tos,
            'total_length': self.total_length,
            'identification': self.identification,
            'flags': self.flags,
            'frag_offset': self.frag_offset,
            'ttl': self.ttl,
            'protocol': self.protocol,
            'checksum': self.checksum,
            'src_addr': self.src_addr,
            'dst_addr': self.dst_addr,
            'options': [],
            'payload': self.payload
        }
        for opt in self.options:
            dct['options'].append(opt.get_dict())
        return dct


    def update_ihl_len_cks(self):
        '''
        Update IHL,  total length and checksum
        '''
        opt_len = 0
        if len(self.options) > 0:
            for opt in self.options:
                opt_len += opt.get_length()
        opt_hl = opt_len // 4
        if opt_len % 4 > 0:
            opt_hl += 1
        if self._ihl != 5 + opt_hl:
            self._ihl = 5 + opt_hl
        self._total_length = self._ihl * 4 + len(self._payload)
        self._checksum = 0x0000
        self._checksum = tools.calc_chksum(self.get_bytes()[0:self._ihl*4])


    def get_bytes(self):
        '''
        returns IPv4 packet bytes
        '''
        ver_ihl = (self.version << 4) + self.ihl
        flags_off = (self.flags << 13) + self.frag_offset

        options = b''
        for opt in self.options:
            options += opt.get_bytes()
        options += (len(options) % 4) * b'\x00'
        return bytes(tools.to_bytes(ver_ihl, 1)
                     + tools.to_bytes(self.tos, 1)
                     + tools.to_bytes(self.total_length, 2)
                     + tools.to_bytes(self.identification, 2)
                     + tools.to_bytes(flags_off, 2)
                     + tools.to_bytes(self.ttl, 1)
                     + tools.to_bytes(self.protocol, 1)
                     + tools.to_bytes(self.checksum, 2)
                     + inet_aton(self.src_addr)
                     + inet_aton(self.dst_addr)
                     + options
                     + self.payload)


    def encapsulate(self, frame):
        '''
        Encapsulate IPv4 packet in an Ethernet frame
        :param frame: Ethernet frame
        '''
        frame.payload = self.get_bytes()


    def __get_src_addr(self):
        '''
        Getter source address
        '''
        return self._src_addr


    def __set_src_addr(self, src_addr):
        '''
        Setter source address
        '''
        if tools.is_valid_ipv4_address(src_addr):
            self._src_addr = src_addr
            self._checksum = None
        else:
            raise InvalidIPv4AddrException

    src_addr = property(__get_src_addr, __set_src_addr)


    def __get_dst_addr(self):
        '''
        Getter destination address
        '''
        return self._dst_addr


    def __set_dst_addr(self, dst_addr):
        '''
        Setter source address
        '''
        if tools.is_valid_ipv4_address(dst_addr):
            self._dst_addr = dst_addr
            self._checksum = None
        else:
            raise InvalidIPv4AddrException

    dst_addr = property(__get_dst_addr, __set_dst_addr)


    def __get_version(self):
        '''
        Getter version
        '''
        return self._version


    def __set_version(self, version):
        '''
        Setter version
        '''
        if 0 <= version < 16:
            self._version = version
            self._checksum = None
        else:
            raise InvalidHeaderValueException('IPv4 Version {}'.format(version))

    version = property(__get_version, __set_version)


    def __get_ihl(self):
        '''
        Getter IHL
        '''
        return self._ihl


    def __set_ihl(self, ihl):
        '''
        Setter IHL
        '''
        if 0 <= ihl < 16:
            self._ihl = ihl
            self._checksum = None
        else:
            raise InvalidHeaderValueException('IPv4 IHL {}'.format(ihl))


    ihl = property(__get_ihl, __set_ihl)


    def __get_tos(self):
        '''
        Getter TOS
        '''
        return self._tos


    def __set_tos(self, tos):
        '''
        Setter TOS
        '''
        if 0 <= tos < 256:
            self._tos = tos
            self._checksum = None
        else:
            raise InvalidHeaderValueException('IPv4 TOS {}'.format(tos))

    tos = property(__get_tos, __set_tos)


    def __get_total_length(self):
        '''
        Getter total length
        '''
        if self._total_length is None:
            self.update_ihl_len_cks()
        return self._total_length


    def __set_total_length(self, total_length):
        '''
        Setter total length
        '''
        if 0 <= total_length < 2 ** 16:
            self._total_length = total_length
            self._checksum = None
        else:
            raise InvalidHeaderValueException(
                    'IPv4 Total Length {}'.format(total_length))

    total_length = property(__get_total_length, __set_total_length)


    def __get_identification(self):
        '''
        Getter identification
        '''
        return self._identification


    def __set_identification(self, identification):
        '''
        Setter identification
        '''
        if 0 <= identification < 2 ** 16:
            self._identification = identification
            self._checksum = None
        else:
            raise InvalidHeaderValueException(
                    'IPv4 Identification {}'.format(identification))

    identification = property(__get_identification, __set_identification)


    def __get_flags(self):
        '''
        Getter flags
        '''
        return self._flags


    def __set_flags(self, flags):
        '''
        Setter flags
        '''
        if 0 <= flags < 8:
            self._flags = flags
            self._checksum = None
        else:
            raise InvalidHeaderValueException('IPv4 Flags {}'.format(flags))

    flags = property(__get_flags, __set_flags)


    def __get_frag_offset(self):
        '''
        Getter fragment offset
        '''
        return self._frag_offset


    def __set_frag_offset(self, frag_offset):
        '''
        Setter fragment offset
        '''
        if 0 <= frag_offset < 2 ** 13:
            self._frag_offset = frag_offset
            self._checksum = None
        else:
            raise InvalidHeaderValueException(
                    'IPv4 Fragmentation Offset {}'.format(frag_offset))

    frag_offset = property(__get_frag_offset, __set_frag_offset)


    def __get_ttl(self):
        '''
        Getter TTL
        '''
        return self._ttl


    def __set_ttl(self, ttl):
        '''
        Setter TTL
        '''
        if 0 <= ttl < 256:
            self._ttl = ttl
            self._checksum = None
        else:
            raise InvalidHeaderValueException('IPv4 TTL {}'.format(ttl))

    ttl = property(__get_ttl, __set_ttl)


    def __get_protocol(self):
        '''
        Getter protocol
        '''
        return self._protocol


    def __set_protocol(self, protocol):
        '''
        Setter protocol
        '''
        if 0 <= protocol < 256:
            self._protocol = protocol
            self._checksum = None
        else:
            raise InvalidHeaderValueException(
                    'IPv4 Protocol {}'.format(protocol))

    protocol = property(__get_protocol, __set_protocol)


    def __get_checksum(self):
        '''
        Getter checksum
        '''
        if self._checksum is None:
            self.update_ihl_len_cks()
        return self._checksum


    def __set_checksum(self, checksum):
        '''
        Setter checksum
        '''
        if 0 <= checksum < 2 ** 16:
            self._checksum = checksum
        else:
            raise InvalidHeaderValueException(
                    'IPv4 Checksum {}'.format(checksum))

    checksum = property(__get_checksum, __set_checksum)


    def __get_options(self):
        '''
        Getter options
        '''
        return self._options


    def __set_options(self, options):
        '''
        Setter options
        '''
        self._options = options
        self._checksum = None
        self._ihl = None
        self._total_length = None

    options = property(__get_options, __set_options)


    def __get_df_flag(self):
        '''
        Get don't fragment flag
        '''
        return self._flags >> 1 & 1


    def __set_df_flag(self, f_val):
        '''
        Set the don't fragment flag
        '''
        pos = 2
        if self.__get_df_flag() == 0 and f_val & 1 == 1:
            self._flags += pos
            self._checksum = None
        if self.__get_df_flag() == 1 and f_val & 1 == 0:
            self._flags -= pos
            self._checksum = None

    df_flag = property(__get_df_flag, __set_df_flag)


    def __get_mf_flag(self):
        '''
        Get more fragments flag
        '''
        return self._flags & 1


    def __set_mf_flag(self, f_val):
        '''
        Set the more fragments flag
        '''
        pos = 1
        if self.__get_mf_flag() == 0 and f_val & 1 == 1:
            self._flags += pos
            self._checksum = None
        if self.__get_mf_flag() == 1 and f_val & 1 == 0:
            self._flags -= pos
            self._checksum = None

    mf_flag = property(__get_mf_flag, __set_mf_flag)


    def get_flag_string(self):
        '''
        Return string interpretation of IPv4 flags field

        :param ip_hdr: IPv4 header
        '''
        flag_str = ('[' + format(self._flags, '03b') + '] -> ')
        dont_fragment = self._flags & 0b010
        more_fragments = self._flags & 0b001
        if dont_fragment:
            flag_str += 'do not fragment; '
        else:
            flag_str += 'may fragment; '
        if more_fragments:
            flag_str += 'more fragments'
        else:
            flag_str += 'last fragment'

        return flag_str


    def info(self):
        '''
        Print IPv4 header information
        '''
        print('IP4 version         : ' + str(self.version))
        print('IP4 header length   : ' + str(self.ihl * 4), 'Bytes')
        print('IP4 time to live    : ' + str(self.ttl))
        print('IP4 source address  : ' + self.src_addr)
        print('IP4 dest. address   : ' + self.dst_addr)
        print('IP4 total length    : ' + str(self.total_length), 'Bytes')
        print('IP4 protocol number : ' + str(self.protocol), \
                                         get_iana_protocol_str(self.protocol))
        print('IP4 flags           : ' + self.get_flag_string())
        print('IP4 identification  : ' + str(self.identification))
        print('IP4 fragment Offset : ' + str(self.frag_offset))
        print('IP4 checksum        : 0x' + format(self.checksum, '04x'))
        opt_count = 1
        for opt in self.options:
            print('IP4 option #{}'.format(opt_count))
            opt.info()
            opt_count += 1


    def add_record_route_option(self, entries=9):
        '''
        Quick and dirty implementation of IPv4 record route option

        :param entries: Number of possible entries (Default value = 9)
        '''
        o_data = {
            'option_type': 0b00000111,
            'option_length': entries * 4 + 3
            }
        o_pointer = 4
        o_recrt_field = b'\x00' * (entries * 4)
        o_data['option_data'] = bytes(tools.to_bytes(o_pointer, 1)
                                      + o_recrt_field)
        self._options.append(IPv4Option(o_data))
        self._ihl = None
        self._checksum = None
        self._total_length = None


    def add_timestamp_option(self, entries=4):
        '''
        Quick and dirty implementation of IPv4 timestamp otion

        :param entries: Number of possible entries (Default value = 4)
        '''
        o_data = {
            'option_type': 0b01000100,
            'option_length': entries * 8 + 4
            }
        o_pointer = 5
        o_oflw_flg = 0b00000000
        o_its_field = b'\x00' * (entries * 8)
        o_data['option_data'] = bytes(tools.to_bytes(o_pointer, 1)
                                      + tools.to_bytes(o_oflw_flg, 1)
                                      + o_its_field)
        self._options.append(IPv4Option(o_data))
        self._ihl = None
        self._checksum = None
        self._total_length = None


    @classmethod
    def from_frame(cls, frame):
        '''
        Create an IPv4 packet from frame data
        '''
        return cls.from_bytes(frame.payload)


    def create_pseudo_header(self):
        '''
        Returns a pseudo header for UDP and TCP checksum calculation
        '''
        return bytes(inet_aton(self.src_addr)
                     + inet_aton(self.dst_addr)
                     + b'\x00'
                     + tools.to_bytes(self.protocol, 1)
                     + tools.to_bytes(len(self.payload), 2))


    def __set_payload(self, payload):
        '''
        Setter for Payload
        '''
        self._payload = payload
        self._checksum = None
        self._total_length = None


    def __get_payload(self):
        '''
        Getter for payload
        '''
        return self._payload

    payload = property(__get_payload, __set_payload)


class IPv4Handler(eth.EthernetHandler):
    '''
    Convenience layer for IPv4 functions
    '''

    def __init__(self, interface, remote_ip=None, src_ip=None, proto=6,
                 block=1, t_out=3.0):
        '''
        Initialize IPv4Handler
        :param interface: <str> interface (name or address) (None=auto)
        :param remote_ip: <str> IP address of the remote host
        :param src_ip: <str> optional deviant source IP address
        :param proto: <int> protocol id of payload (default 6=TCP)
        :param block: <int> make socket blocking (1), non-blocking (0) or
                            non-blocking with timeout (2)
        :param t_out: <float> set socket timeout in seconds
        '''
        self._remote_ip = remote_ip
        self._local_ip = None
        local_ip_dict = tools.get_local_IP_addresses(4)
        if tools.is_valid_ipv4_address(interface):
            self._local_ip = interface
            interface = tools.get_interface_by_address(self._local_ip)
            if interface is None:
                raise InvalidInterfaceException('address not found')
        else:
            if_addr = local_ip_dict.get(interface, None)
            if if_addr is not None and len(if_addr) > 0:
                self._local_ip = if_addr[0]
            else:
                raise InvalidInterfaceException('device not found')
        if src_ip is not None:
            self._local_ip = src_ip
        local_mac = tools.get_mac_addr(interface)
        self._protocol = proto
        # fragment dictionary for reassembly
        # {
        #   identification_1: {'written': [(ind, len)],
        #                      'last_frag_rcvd': <bool>,
        #                      'packet': <IPv4Packet>},
        #   identification_2: ...
        # }
        self._frag_list = {}
        self._next_id = randrange(65536)

        super().__init__(interface, None, 0x0800, local_mac, None, None,
                         block, t_out)


    def __init_packet(self):
        '''
        Initialize new IPv4 packet
        '''
        ip4_data = {'protocol': self._protocol,
                    'src_addr': self._local_ip,
                    'dst_addr': self._remote_ip}
        return IPv4Packet(ip4_data)


    def __get_remote_ip(self):
        '''
        Getter for remote_ip
        '''
        return self._remote_ip

    def __set_remote_ip(self, remote_ip):
        '''
        Setter for remote_ip
        '''
        self._remote_ip = remote_ip

    remote_ip = property(__get_remote_ip, __set_remote_ip)


    def __get_next_id(self):
        '''
        Getter for next identification
        '''
        next_id = self._next_id
        if self._next_id < 65535:
            self._next_id += 1
        else:
            self._next_id = 0
        return next_id

    next_id = property(__get_next_id)


    def __get_local_ip(self):
        '''
        Getter for local_ip
        '''
        return self._local_ip

    def __set_local_ip(self, local_ip):
        '''
        Setter for local_ip
        '''
        self._local_ip = local_ip

    local_ip = property(__get_local_ip, __set_local_ip)


    def __get_protocol(self):
        '''
        Getter for protocol
        '''
        return self._protocol

    def __set_protocol(self, proto):
        '''
        Getter for protocol
        '''
        self._protocol = proto

    protocol = property(__get_protocol, __set_protocol)


    def send(self, dgram, dont_frag=False):
        '''
        Send datagram via an IPv4Packet
        :param dgram: datagram
        :param dont_frag: set DF flag?
        '''
        bytes_sent = 0
        packet = self.__init_packet()
        dgram.encapsulate(packet)
        if packet.total_length <= self.mtu:
            packet.df_flag = 1 if dont_frag else 0
            bytes_sent = super().send(packet) - packet.ihl * 4
            return bytes_sent

        if dont_frag:
            return 0

        frag = copy(packet)
        frag.identification = self.next_id
        frag.mf_flag = 1

        chunk_sz = ((self.mtu - frag.ihl * 4) // 8) * 8
        chunk_cnt = ceil(len(packet.payload) / chunk_sz)
        for i in range(chunk_cnt):
            offset = i * chunk_sz
            frag.frag_offset = offset // 8
            if i < chunk_cnt - 1:
                frag.payload = packet.payload[offset:offset + chunk_sz]
            else:
                frag.mf_flag = 0
                frag.payload = packet.payload[offset:]
            bytes_sent += super().send(frag) - packet.ihl * 4
        return bytes_sent


    def __packet_complete(self, identification):
        '''
        Check if all fragments of a fragmented packet have arrived. Only call
        if last fragment has arrived
        '''
        offset_list = self._frag_list[identification]['written']
        offset_list.sort(key=lambda item: item[0])
        expected_index = 0
        for item in offset_list:
            if item[0] != expected_index:
                return False
            expected_index += item[1] / 8
        return True


    def receive(self, pass_on_error=True, promisc=False):
        '''
        Receive next packet that belongs to this connection, i.e. either set
        packet to None or IPv4Packet object created from received frame
        Return True if a full packet is received and false if only a fragment
        or nothing suitable has been received
        :param pass_on_error: <bool> ignore exceptions thrown by socket.recv
        :any_source: <bool> accept packets from any source
        :promisc: <bool> receive packets that are not for us
        '''
        frame, frame_type = super().receive(pass_on_error, promisc)

        if frame is None:
            return None
        
        # frame_type != 4 -> don't process frames that we have sent
        if frame_type != 4 and frame is not None:
            ip4_pk = IPv4Packet.from_frame(frame)

            if not promisc:
                if self.local_ip is not None and \
                   self.local_ip != ip4_pk.dst_addr:
                    return None

            if self.remote_ip is not None and \
               self.remote_ip != ip4_pk.src_addr:
                return None

            if ip4_pk.protocol != self._protocol:
                return None

            frag_entry = self._frag_list.get(ip4_pk.identification, None)
            if frag_entry is None:

                # First check if this is a fragment; if not return packet
                if ip4_pk.mf_flag == 0 and ip4_pk.frag_offset == 0:
                    return ip4_pk

                new_pk = ip4_pk
                new_pk.payload = b'\x00' * ip4_pk.frag_offset * 8 \
                                 + ip4_pk.payload

                self._frag_list[ip4_pk.identification] = {
                            'written': [(ip4_pk.frag_offset,
                                         ip4_pk.total_length - ip4_pk.ihl * 4)],
                            'last_frag_rcvd': ip4_pk.mf_flag == 0,
                            'packet': new_pk
                        }
                return None
            if len(frag_entry['packet'].payload) > ip4_pk.frag_offset * 8:
                frag_entry['packet'].payload = tools.set_bytes_at(
                        frag_entry['packet'].payload,
                        ip4_pk.payload,
                        ip4_pk.frag_offset * 8)
            else:
                add_payload = b'\x00' * (ip4_pk.frag_offset * 8 \
                        - len(frag_entry['packet'].payload)) \
                        + ip4_pk.payload
                frag_entry['packet'].payload += add_payload

            frag_entry['written'].append((ip4_pk.frag_offset,
                    ip4_pk.total_length - ip4_pk.ihl * 4))

            if ip4_pk.mf_flag == 0:
                frag_entry['last_frag_rcvd'] = True

            self._frag_list[ip4_pk.identification] = frag_entry

            if frag_entry['last_frag_rcvd']:
                if self.__packet_complete(ip4_pk.identification):
                    new_pk = frag_entry['packet']
                    new_pk.flags = 0
                    new_pk.total_length = len(new_pk.payload) + new_pk.ihl * 4
                    del self._frag_list[ip4_pk.identification]
                    return new_pk
        return None
