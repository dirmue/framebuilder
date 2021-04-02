'''Module for IPv4 functions used by custompk'''

from socket import inet_aton, inet_ntoa
from framebuilder.errors import InvalidIPv4AddrException, \
                                IncompleteIPv4HeaderException
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

    def __init__(self, ip4_data=None, is_fragment=False):
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
            raise InvalidIPv4AddrException

        if tools.is_valid_ipv4_address(dst_addr_str):
            self._dst_addr = dst_addr_str
        else:
            raise InvalidIPv4AddrException

        self._version = ip4_data.get('version', 4) & 0xf
        self._ihl = ip4_data.get('ihl', 5) & 0xf
        self._tos = ip4_data.get('tos', 0) & 0xff
        self._total_length = ip4_data.get('total_length', 0) & 0xffff
        self._identification = ip4_data.get('identification', 0) & 0xffff
        self._flags = ip4_data.get('flags', 0) & 0b111
        self._frag_offset = ip4_data.get('frag_offset', 0) & 0b1111111111111
        self._ttl = ip4_data.get('ttl', MAX_TTL) & 0xff
        self._protocol = ip4_data.get('protocol', 0) & 0xff
        self._checksum = ip4_data.get('checksum', 0) & 0xffff
        self._payload = ip4_data.get('payload', b'')
        self.is_fragment = is_fragment
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
        if ip4_data['total_length'] > len(ip4_data['payload']):
            return cls(ip4_data, True)
        return cls(ip4_data)


    def get_dict(self):
        '''
        Return header data as dictionary
        '''
        dct = {
            'version': self._version,
            'ihl': self._ihl,
            'tos': self._tos,
            'total_length': self._total_length,
            'identification': self._identification,
            'flags': self._flags,
            'frag_offset': self._frag_offset,
            'ttl': self._ttl,
            'protocol': self._protocol,
            'checksum': self._checksum,
            'src_addr': self._src_addr,
            'dst_addr': self._dst_addr,
            'options': [],
            'payload': self._payload
        }
        for opt in self._options:
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
        returns IPv4 header bytes
        '''
        ver_ihl = (self._version << 4) + self._ihl
        flags_off = (self._flags << 13) + self._frag_offset

        options = b''
        for opt in self._options:
            options += opt.get_bytes()
        options += (len(options) % 4) * b'\x00'
        return bytes(tools.to_bytes(ver_ihl, 1)
                     + tools.to_bytes(self._tos, 1)
                     + tools.to_bytes(self._total_length, 2)
                     + tools.to_bytes(self._identification, 2)
                     + tools.to_bytes(flags_off, 2)
                     + tools.to_bytes(self._ttl, 1)
                     + tools.to_bytes(self._protocol, 1)
                     + tools.to_bytes(self._checksum, 2)
                     + inet_aton(self._src_addr)
                     + inet_aton(self._dst_addr)
                     + options
                     + self._payload)


    def encapsulate(self, frame):
        '''
        Encapsulate IPv4 packet in an Ethernet frame
        :param frame: Ethernet frame
        '''
        self.update_ihl_len_cks()
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
        self._version = version & 0xf

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
        self._ihl = ihl & 0xf

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
        self._tos = tos & 0xff

    tos = property(__get_tos, __set_tos)


    def __get_total_length(self):
        '''
        Getter total length
        '''
        return self._total_length


    def __set_total_length(self, total_length):
        '''
        Setter total length
        '''
        self._total_length = total_length & 0xffff

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
        self._identification = identification & 0xffff

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
        self._flags = flags & 0b111

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
        self._frag_offset = frag_offset & 0b1111111111111

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
        self._ttl = ttl & 0xff

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
        self._protocol = protocol & 0xff

    protocol = property(__get_protocol, __set_protocol)


    def __get_checksum(self):
        '''
        Getter checksum
        '''
        return self._checksum


    def __set_checksum(self, checksum):
        '''
        Setter checksum
        '''
        self._checksum = checksum & 0xffff

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

    options = property(__get_options, __set_options)


    def dont_fragment(self):
        '''
        Is the don't fragment flag set?
        '''
        return bool(self._flags & 0b010)


    def set_df_flag(self):
        '''
        Set the don't fragment flag
        '''
        self._flags |= 0b010


    def more_fragments(self):
        '''
        Is the don't fragment flag set?
        '''
        return bool(self._flags & 0b001)


    def set_mf_flag(self):
        '''
        Set the more fragments flag
        '''
        self._flags |= 0b001


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


    def info(self, calc_cs=False):
        '''
        Print IPv4 header information
        :param calc_cs: <bool> Calculate checkum?
        '''
        if calc_cs:
            self.update_ihl_len_cks()
        print('IP4 version         : ' + str(self._version))
        print('IP4 header length   : ' + str(self._ihl * 4), 'Bytes')
        print('IP4 time to live    : ' + str(self._ttl))
        print('IP4 source address  : ' + self._src_addr)
        print('IP4 dest. address   : ' + self._dst_addr)
        print('IP4 total length    : ' + str(self._total_length), 'Bytes')
        print('IP4 protocol number : ' + str(self._protocol), \
                                         get_iana_protocol_str(self._protocol))
        print('IP4 flags           : ' + self.get_flag_string())
        print('IP4 identification  : ' + str(self._identification))
        print('IP4 fragment Offset : ' + str(self._frag_offset))
        print('IP4 checksum        : 0x' + format(self._checksum, '04x'))
        opt_count = 1
        for opt in self._options:
            print('IP4 option #{}'.format(opt_count))
            opt.info()
            opt_count += 1


    # IPv4 options are rarely used. Hence, only the following two types (record
    # route and internet timestamp) are implemented as quick and dirty examples.
    # All types of options can be passed to create_ipv4_header as bytes object
    # though.
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
        return bytes(inet_aton(self._src_addr)
                     + inet_aton(self._dst_addr)
                     + b'\x00'
                     + tools.to_bytes(self._protocol, 1)
                     + tools.to_bytes(len(self._payload), 2))


    def __set_payload(self, payload):
        '''
        Setter for Payload
        '''
        self._payload = payload


    def __get_payload(self):
        '''
        Getter for payload
        '''
        return self._payload

    payload = property(__get_payload, __set_payload)


class IPv4Handler(eth.EthernetHandler):
    '''
    Manage an IPv4 connection between two hosts (multicast might be added
    later). Here is where fragmentation should be handled.
    The latest inbound packet is stored in nextpk_in
    The current outbound packet is stored in nextpk_out
    '''

    def __init__(self, remote_ip, proto=6, local_ip=None, vlan_tag=None,
                 block=1, t_out=3.0):
        '''
        Initialize IPv4Handler
        :param remote_ip: <str> IP address of the remote host
        :param proto: <int> protocol id of payload (default 6=TCP)
        :param local_ip: <str> local IP address (None=auto)
        :param vlan_tag: <dict> VLAN tag {
                                    'vlan_id': <int> VLAN identifier,
                                    'vlan_pcp': <int> priority code point,
                                    'vlan_dei': <int> drop eligible indicator
                                }
        :param block: <int> make socket blocking (1), non-blocking (0) or
                            non-blocking with timeout (2)
        :param t_out: <float> set socket timeout in seconds
        '''
        rt_info = tools.get_route(remote_ip)
        n_cache = tools.get_neigh_cache()

        self._remote_ip = remote_ip
        if local_ip is None:
            self._local_ip = rt_info.get('prefsrc', '0.0.0.0')
        else:
            self._local_ip = local_ip

        interface = rt_info.get('dev', 'lo')
        src_mac = tools.get_mac_addr(interface)
        dst_mac = '00:00:00:00:00:00'

        # check if there is a gateway and query neighbor cache for MAC address
        if rt_info.get('gateway', None) is not None:
            for n_entry in n_cache:
                if n_entry['dst'] == rt_info['gateway']:
                    dst_mac = n_entry['lladdr']
                    break
        # if not query destination IP address
        else:
            for n_entry in n_cache:
                if n_entry['dst'] == remote_ip:
                    dst_mac = n_entry['lladdr']
                    break
        self._protocol = proto
        self._nextpk_in = None
        self._nextpk_out = None
        self.init_nextpk_out()

        # fragment dictionary for reassembly
        # {
        #   identification_1: {'written': [(ind, len)],
        #                      'last_frag_rcvd': <bool>,
        #                      'packet': <IPv4Packet>},
        #   identification_2: {'written': [(ind, len)], 'packet': <IPv4Packet>},
        #   identification_3: {'written': [(ind, len)], 'packet': <IPv4Packet>},
        #   ...
        #   identification_n: {'written': [(ind, len)], 'packet': <IPv4Packet>}
        # }
        self._frag_list = {}

        super().__init__(interface, dst_mac, 0x0800, src_mac, vlan_tag, None,
                         block, t_out)


    def init_nextpk_out(self):
        '''
        Initialize nextpk_out with local and remote IP address
        '''
        ip4_data = {'protocol': self._protocol,
                    'src_addr': self._local_ip,
                    'dst_addr': self._remote_ip}
        self._nextpk_out = IPv4Packet(ip4_data)


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

    protocol = property(__get_protocol)


    def __get_nextpk_out(self):
        '''
        Getter for nextpk_out
        '''
        return self._nextpk_out

    nextpk_out = property(__get_nextpk_out)


    def __get_nextpk_in(self):
        '''
        Getter for nextpk_in
        '''
        return self._nextpk_in

    nextpk_in = property(__get_nextpk_in)


    def send(self):
        '''
        Send data via an IPv4Packet
        '''
        if self._nextpk_out is not None:
            self._nextpk_out.encapsulate(self._frame)
            super().send()


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
            
    
    def receive(self, pass_on_error=True):
        '''
        Receive next packet that belongs to this connection, i.e. either set
        packet to None or IPv4Packet object created from received frame
        Return True if a full packet is received and false if only a fragment
        or nothing suitable has been received
        :param pass_on_error: <bool> ignore exceptions thrown by socket.recv
        '''
        addr = super().receive(pass_on_error)
        if addr[2] == 0 and self.frame is not None:
            ip4_pk = IPv4Packet.from_frame(self.frame)
            if not (ip4_pk.src_addr == self._remote_ip and \
                    ip4_pk.dst_addr == self._local_ip and \
                    ip4_pk.protocol == self._protocol):
                return False
            # Fragmentation check
            if ip4_pk.dont_fragment():
                self._nextpk_in = ip4_pk
                return True
            frag_entry = self._frag_list.get(ip4_pk.identification, None)
            if frag_entry is None:
                new_pk = ip4_pk
                new_pk.is_fragment = True
                new_pk.payload = b'\x00' * ip4_pk.frag_offset * 8 \
                                 + ip4_pk.payload

                self._frag_list[ip4_pk.identification] = {
                            'written': [(ip4_pk.frag_offset,
                                         ip4_pk.total_length - ip4_pk.ihl * 4)],
                            'last_frag_rcvd': not ip4_pk.more_fragments(),
                            'packet': new_pk
                        }
                return False
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
            if not ip4_pk.more_fragments():
                frag_entry['last_frag_rcvd'] = True

            self._frag_list[ip4_pk.identification] = frag_entry

            if frag_entry['last_frag_rcvd']:
                if self.__packet_complete(ip4_pk.identification):
                    pk = frag_entry['packet']
                    pk.flags = 0
                    pk.total_length = len(pk.payload) + pk.ihl * 4
                    self._nextpk_in = pk
                    del self._frag_list[ip4_pk.identification]
                    return True            
        return False
