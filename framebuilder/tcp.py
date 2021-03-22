'''Module for TCP functions used by custompk'''

from framebuilder import tools, errors

class TCPOption:
    '''
    Create a TCP option
    '''

    def __init__(self, opt_data=None):
        '''
        Initialize TCP Option
        :param opt_data: Dictionary containing option data as follows
        {
            'kind': <int> specifies the option type (1 Byte)
            'length': <int> length of the option incl. kind and length (1 Byte)
            'option_data': <bytes> option data
        }
        '''

        if opt_data is None:
            opt_data = {}

        self._okind = opt_data.get('kind', 0) & 0xff
        self._olength = opt_data.get('length', None)
        self._odata = opt_data.get('option_data', None)

        if self._olength is not None:
            self._olength &= 0xff


    @classmethod
    def from_bytes(cls, opt_bytes):
        '''
        Initialize TCP options object from bytes
        :param opt_bytes: <bytes> data
        '''
        opt_data = {}

        if len(opt_bytes) >= 1:
            opt_data['kind'] = tools.get_value_at(opt_bytes, 1, 0)
        if len(opt_bytes) > 1:
            opt_data['length'] = tools.get_value_at(opt_bytes, 1, 1)
        if len(opt_bytes) > 2:
            opt_data['option_data'] = opt_bytes[2:]
        return cls(opt_data)


    def get_opt_str(self):
        '''
        Returns the name of the TCP option
        '''
        opt_str = {0: 'End of option list',
                   1: 'No operation',
                   2: 'Maximum segment size',
                   3: 'Window scaling',
                   4: 'SACK permitted',
                   8: 'Timestamp option'}

        return opt_str.get(self._okind, 'Unknown')


    def info(self):
        '''
        Print option information
        '''
        print('OPT Kind            : ' + self.get_opt_str())
        if self._olength is not None:
            print('OPT Length          : ' + str(self._olength))
        if self._odata is not None:
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
        otype = tools.to_bytes(self._okind, 1)
        if self._olength is not None:
            olength = tools.to_bytes(self._olength, 1)
            if self._odata is not None:
                return bytes(otype + olength + self._odata)
            return bytes(otype + olength)
        return otype


    def get_dict(self):
        '''
        Return option data as dictionary
        '''
        return {'kind': self._okind,
                'length': self._olength,
                'option_data': self._odata}


class TCPSegment:
    '''
    Create a TCP segment according to RFC 793

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |0 0 0 0|C|E|U|A|P|R|S|F|                               |
    | Offset| Rsrvd.|W|C|R|C|S|S|Y|I|            Window             |
    |       |       |R|E|G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''

    def __init__(self, tcp_data=None):
        '''
        Initialize TCP segment
        :param tcp_data: Dictionary containing TCP data as follows:
        {
            layer3_proto: <int> Id of layer 3 protocol; eq. ethertype
            pseudo_header: <bytes> Pseudo header of network layer protocol
            src_port: <int> Source port (2 Bytes)
            dst_port: <int> Destination port (2 bytes)
            seq_nr: <int> Sequence number (4 Bytes)
            ack_nr: <int> Acknowledgment number (4 Bytes)
            data_offset: <int> Header length in 32 Bit blocks (4 Bits)
            flags: <int> TCP flags (1 Byte)
            window: <int> Size of the sender's receive window (2 Bytes)
            checksum: <int> TCP checksum (2 Bytes)
            urg_ptr: <int> points to the first byte after urgent data (2 Bytes)
            options: []<dict> List of TCP option dictionaries
            payload: <bytes> Payload data
        }
        '''
        if tcp_data is None:
            tcp_data = {}

        self._layer3_proto = tcp_data.get('layer3_proto', 0x0800)
        if self._layer3_proto == 0x0800:
            # IPv4 pseudo header
            self._pseudo_header = tcp_data.get('pseudo_header', b'\x00' * 12)
        if self._layer3_proto == 0x86dd:
            # IPv6 pseudo header
            self._pseudo_header = tcp_data.get('pseudo_header', b'\x00' * 40)
        if self._pseudo_header is None:
            # empty pseudo header for unknown layer 3 protocols
            self._pseudo_header = tcp_data.get('pseudo_header', b'')
        self._src_port = tcp_data.get('src_port', 0) & 0xffff
        self._dst_port = tcp_data.get('dst_port', 0) & 0xffff
        self._seq_nr = tcp_data.get('seq_nr', 0) & 0xffffffff
        self._ack_nr = tcp_data.get('ack_nr', 0) & 0xffffffff
        self._data_offset = tcp_data.get('data_offset', 5) & 0xf
        self._flags = tcp_data.get('flags', 0) & 0xff
        self._window = tcp_data.get('window', 0) & 0xffff
        self._checksum = tcp_data.get('checksum', 0) & 0xffff
        self._urg_ptr = tcp_data.get('urg_ptr', 0) & 0xffff
        self._payload = tcp_data.get('payload', b'')
        self._options = []
        if tcp_data.get('options', None) is not None:
            for opt in tcp_data['options']:
                next_option = TCPOption(opt)
                self._options.append(next_option)
        if tcp_data.get('checksum', None) is None:
            self.update_checksum()


    @classmethod
    def from_bytes(cls, tcp_bytes):
        '''
        create TCP segment from bytes
        '''
        tcp_data = {}

        tcp_data['src_port'] = tools.get_value_at(tcp_bytes, 2, 0)
        tcp_data['dst_port'] = tools.get_value_at(tcp_bytes, 2, 2)
        tcp_data['seq_nr'] = tools.get_value_at(tcp_bytes, 4, 4)
        tcp_data['ack_nr'] = tools.get_value_at(tcp_bytes, 4, 8)
        tcp_data['data_offset'] = tools.get_value_at(tcp_bytes, 1, 12) >> 4
        tcp_data['flags'] = tools.get_value_at(tcp_bytes, 1, 13)
        tcp_data['window'] = tools.get_value_at(tcp_bytes, 2, 14)
        tcp_data['checksum'] = tools.get_value_at(tcp_bytes, 2, 16)
        tcp_data['urg_ptr'] = tools.get_value_at(tcp_bytes, 2, 18)
        tcp_data['options'] = []
        if tcp_data['data_offset'] > 5:
            options = tcp_bytes[20:(tcp_data['data_offset'])*4]
            index = 0
            while index < len(options):
                if options[index] == 0 or \
                   options[index] == 1:
                    opt = {'kind': options[index]}
                    tcp_data['options'].append(opt)
                    index += 1
                else:
                    olength = int(options[index+1])
                    opt = {'kind': int(options[index]),
                           'length': int(options[index+1]),
                           'option_data': options[index+2:index + olength]}
                    tcp_data['options'].append(opt)
                    index += olength
        tcp_data['payload'] = tcp_bytes[tcp_data['data_offset']*4:]
        return cls(tcp_data)


    @classmethod
    def from_packet(cls, packet):
        '''
        Create TCP segment from payload of layer 3 packet
        '''
        segment = cls.from_bytes(packet.payload)
        segment.create_pseudo_header(packet)
        return segment


    def get_dict(self):
        '''
        Return TCP segment data as dictionary
        '''
        tcp_data = {}

        tcp_data['layer3_proto'] = self._layer3_proto
        tcp_data['pseudo_header'] = self._pseudo_header
        tcp_data['src_port'] = self._src_port
        tcp_data['dst_port'] = self._dst_port
        tcp_data['seq_nr'] = self._seq_nr
        tcp_data['ack_nr'] = self._ack_nr
        tcp_data['data_offset'] = self._data_offset
        tcp_data['flags'] = self._flags
        tcp_data['window'] = self._window
        self.update_checksum()
        tcp_data['checksum'] = self._checksum
        tcp_data['urg_ptr'] = self._urg_ptr
        tcp_data['options'] = []
        for opt in self._options:
            tcp_data['options'].append(opt.get_dict())
        tcp_data['payload'] = self._payload
        return tcp_data


    def get_bytes(self):
        '''
        Return segment data as bytes
        '''
        opt_bytes = b''
        for opt in self._options:
            opt_bytes += opt.get_bytes()
        return bytes(tools.to_bytes(self._src_port, 2) +
                     tools.to_bytes(self._dst_port, 2) +
                     tools.to_bytes(self._seq_nr, 4) +
                     tools.to_bytes(self._ack_nr, 4) +
                     tools.to_bytes(self._data_offset << 4, 1) +
                     tools.to_bytes(self._flags, 1) +
                     tools.to_bytes(self._window, 2) +
                     tools.to_bytes(self._checksum, 2) +
                     tools.to_bytes(self._urg_ptr, 2) +
                     opt_bytes +
                     self._payload)


    def encapsulate(self, packet):
        '''
        Encapsulate TCP segment into packet
        :param packet: Layer 3 packet object
        '''
        self.create_pseudo_header(packet)
        self.update_checksum()
        packet.payload = self.get_bytes()


    def create_pseudo_header(self, packet):
        '''
        Create the layer 3 pseudo header and update its length field
        :param packet: Layer 3 packet object
        '''
        self._pseudo_header = packet.create_pseudo_header()

        # Quick and dirty protocol check. isinstance() is probably better.
        if len(self._pseudo_header) == 12:
            # IPv4
            self._layer3_proto = 0x0800
            new_len_bytes = tools.to_bytes(len(self.get_bytes()), 2)
            self._pseudo_header = tools.set_bytes_at(self._pseudo_header,
                                                     new_len_bytes, 10)
        if len(self._pseudo_header) == 40:
            # IPv6
            self._layer3_proto = 0x86dd
            new_len_bytes = tools.to_bytes(len(self.get_bytes()), 4)
            self._pseudo_header = tools.set_bytes_at(self._pseudo_header,
                                                     new_len_bytes, 32)


    def update_checksum(self):
        '''
        Update TCP checksum
        '''
        self._checksum = 0
        self._checksum = tools.calc_chksum(self._pseudo_header +
                                           self.get_bytes() +
                                           b'\x00' * (len(self._payload) % 2))


    def verify_checksum(self):
        '''
        Verify TCP checksum
        '''
        result = tools.calc_chksum(self._pseudo_header +
                                   self.get_bytes() +
                                   b'\x00' * (len(self._payload) % 2))
        if result == 0xffff:
            return True
        return False


    def get_flag_str(self):
        '''
        Return string representation of set flags
        '''
        f_str_lst = []
        if 1 & self._flags != 0:
            f_str_lst.append('fin')
        if 2 & self._flags != 0:
            f_str_lst.append('syn')
        if 4 & self._flags != 0:
            f_str_lst.append('rst')
        if 8 & self._flags != 0:
            f_str_lst.append('psh')
        if 16 & self._flags != 0:
            f_str_lst.append('ack')
        if 32 & self._flags != 0:
            f_str_lst.append('urg')
        if 64 & self._flags != 0:
            f_str_lst.append('ece')
        if 128 & self._flags != 0:
            f_str_lst.append('cwr')
        if len(f_str_lst) == 0:
            return 'no flags'
        return '|'.join(f_str_lst)


    def info(self, calc_cs=False):
        '''
        Print TCP segment info
        :param calc_cs: <bool> Calculate checksum?
        '''
        print('TCP source port     : ' + str(self._src_port))
        print('TCP destination port: ' + str(self._dst_port))
        print('TCP sequence number : ' + str(self._seq_nr))
        print('TCP ack number      : ' + str(self._ack_nr))
        print('TCP data offset     : ' + str(self._data_offset))
        print('TCP flags           : ' + self.get_flag_str())
        print('TCP receive window  : ' + str(self._window))
        if calc_cs:
            self.update_checksum()
        valid_str = '(incorrect)'
        if self.verify_checksum():
            valid_str = '(correct)'
        print('TCP checksum        : 0x' + format(self._checksum, '04x'),
              valid_str)
        print('TCP urgent pointer  : ' + str(self._urg_ptr))
        print('TCP payload length  : ' + str(len(self._payload)))
        opt_count = 1
        for opt in self._options:
            print('TCP Option #{}'.format(opt_count))
            opt.info()
            opt_count += 1


    def __get_length(self):
        '''
        Getter for length
        '''
        return len(self.payload)

    length = property(__get_length)


    def __get_src_port(self):
        '''
        Getter for src_port
        '''
        return self._src_port


    def __set_src_port(self, src_port):
        '''
        Setter for src_port
        '''
        self._src_port = src_port

    src_port = property(__get_src_port, __set_src_port)


    def __get_dst_port(self):
        '''
        Getter for dst_port
        '''
        return self._dst_port


    def __set_dst_port(self, dst_port):
        '''
        Setter for dst_port
        '''
        self._dst_port = dst_port

    dst_port = property(__get_dst_port, __set_dst_port)


    def __get_pseudo_header(self):
        '''
        Getter for pseudo_header
        '''
        return self._pseudo_header


    def __set_pseudo_header(self, pseudo_header):
        '''
        Setter for pseudo_header
        '''
        self._pseudo_header = pseudo_header

    pseudo_header = property(__get_pseudo_header, __set_pseudo_header)


    def __get_seq_nr(self):
        '''
        Getter for seq_nr
        '''
        return self._seq_nr


    def __set_seq_nr(self, seq_nr):
        '''
        Setter for seq_nr
        '''
        self._seq_nr = seq_nr

    seq_nr = property(__get_seq_nr, __set_seq_nr)


    def __get_ack_nr(self):
        '''
        Getter for ack_nr
        '''
        return self._ack_nr


    def __set_ack_nr(self, ack_nr):
        '''
        Setter for ack_nr
        '''
        self._ack_nr = ack_nr

    ack_nr = property(__get_ack_nr, __set_ack_nr)


    def __get_data_offset(self):
        '''
        Getter for data_offset
        '''
        return self._data_offset


    def __set_data_offset(self, data_offset):
        '''
        Setter for data_offset
        '''
        self._data_offset = data_offset

    data_offset = property(__get_data_offset, __set_data_offset)


    def __get_flags(self):
        '''
        Getter for flags
        '''
        return self._flags


    def __set_flags(self, flags):
        '''
        Setter for flags
        '''
        self._flags = flags

    flags = property(__get_flags, __set_flags)


    def __get_fin(self):
        '''
        Get value of fin flag
        '''
        return self._flags & 1


    def __set_fin(self, f_val):
        '''
        Set fin flag
        '''
        pos = 1
        if self.__get_fin() == 0 and f_val & 1 == 1:
            self._flags += pos
        if self.__get_fin() == 1 and f_val & 1 == 0:
            self._flags -= pos

    fin = property(__get_fin, __set_fin)


    def __get_syn(self):
        '''
        Get value of syn flag
        '''
        return self._flags >> 1 & 1


    def __set_syn(self, f_val):
        '''
        Set syn flag
        '''
        pos = 2
        if self.__get_syn() == 0 and f_val & 1 == 1:
            self._flags += pos
        if self.__get_syn() == 1 and f_val & 1 == 0:
            self._flags -= pos

    syn = property(__get_syn, __set_syn)


    def __get_rst(self):
        '''
        Get value of rst flag
        '''
        return self._flags >> 2 & 1


    def __set_rst(self, f_val):
        '''
        Set rst flag
        '''
        pos = 4
        if self.__get_rst() == 0 and f_val & 1 == 1:
            self._flags += pos
        if self.__get_rst() == 1 and f_val & 1 == 0:
            self._flags -= pos

    rst = property(__get_rst, __set_rst)


    def __get_psh(self):
        '''
        Get value of psh flag
        '''
        return self._flags >> 3 & 1


    def __set_psh(self, f_val):
        '''
        Set psh flag
        '''
        pos = 8
        if self.__get_psh() == 0 and f_val & 1 == 1:
            self._flags += pos
        if self.__get_psh() == 1 and f_val & 1 == 0:
            self._flags -= pos

    psh = property(__get_psh, __set_psh)


    def __get_ack(self):
        '''
        Get value of ack flag
        '''
        return self._flags >> 4 & 1


    def __set_ack(self, f_val):
        '''
        Set ack flag
        '''
        pos = 16
        if self.__get_ack() == 0 and f_val & 1 == 1:
            self._flags += pos
        if self.__get_ack() == 1 and f_val & 1 == 0:
            self._flags -= pos

    ack = property(__get_ack, __set_ack)


    def __get_urg(self):
        '''
        Get value of urg flag
        '''
        return self._flags >> 5 & 1


    def __set_urg(self, f_val):
        '''
        Set urg flag
        '''
        pos = 32
        if self.__get_urg() == 0 and f_val & 1 == 1:
            self._flags += pos
        if self.__get_urg() == 1 and f_val & 1 == 0:
            self._flags -= pos

    urg = property(__get_urg, __set_urg)


    def __get_ece(self):
        '''
        Get value of ece flag
        '''
        return self._flags >> 6 & 1


    def __set_ece(self, f_val):
        '''
        Set ece flag
        '''
        pos = 64
        if self.__get_ece() == 0 and f_val & 1 == 1:
            self._flags += pos
        if self.__get_ece() == 1 and f_val & 1 == 0:
            self._flags -= pos

    ece = property(__get_ece, __set_ece)


    def __get_cwr(self):
        '''
        Get value of cwr flag
        '''
        return self._flags >> 7 & 1


    def __set_cwr(self, f_val):
        '''
        Set cwr flag
        '''
        pos = 128
        if self.__get_cwr() == 0 and f_val & 1 == 1:
            self._flags += pos
        if self.__get_cwr() == 1 and f_val & 1 == 0:
            self._flags -= pos

    cwr = property(__get_cwr, __set_cwr)


    def __get_window(self):
        '''
        Getter for window
        '''
        return self._window


    def __set_window(self, window):
        '''
        Setter for window
        '''
        self._window = window

    window = property(__get_window, __set_window)


    def __get_checksum(self):
        '''
        Getter for checksum
        '''
        return self._checksum


    def __set_checksum(self, checksum):
        '''
        Setter for checksum
        '''
        self._checksum = checksum

    checksum = property(__get_checksum, __set_checksum)


    def __get_urg_ptr(self):
        '''
        Getter for urg_ptr
        '''
        return self._urg_ptr


    def __set_urg_ptr(self, urg_ptr):
        '''
        Setter for urg_ptr
        '''
        self._urg_ptr = urg_ptr

    urg_ptr = property(__get_urg_ptr, __set_urg_ptr)


    def __get_payload(self):
        '''
        Getter for payload
        '''
        return self._payload


    def __set_payload(self, payload):
        '''
        Setter for payload
        '''
        self._payload = payload

    payload = property(__get_payload, __set_payload)


    def __get_options(self):
        '''
        Setter for options
        '''
        return self._options


    def __set_options(self, options):
        '''
        Setter for options
        '''
        self._options = options

    options = property(__get_options, __set_options)


    def delete_options(self):
        '''
        Deletes all options and resets data offset
        '''
        self._options = []
        self.data_offset = 5


    def add_tcp_mss_option(self, mss=1460):
        '''
        Add a TCP maximum segment size option

        If this option is present, then it communicates the maximum
        receive segment size at the TCP which sends this segment.
        This field must only be sent in the initial connection request
        (i.e., in segments with the SYN control bit set).  If this
        option is not used, any segment size is allowed.

        +--------+--------+---------+--------+
        |00000010|00000100|   max seg size   |
        +--------+--------+---------+--------+
            1        1              2

        :param mss: Maximum segment size (Default value = 1460)
        '''
        o_kind = 2
        o_length = 4
        o_val = mss

        opt = TCPOption({'kind': o_kind,
                         'length': o_length,
                         'option_data': tools.to_bytes(o_val, 2)})

        self._options.append(opt)
        self._data_offset += 1
        if self._data_offset > 15:
            raise errors.MaxTCPHeaderSizeExceeded('Data offset greater than 16')


    def add_tcp_wscale_option(self, shift_ct=0):
        '''
        Add a TCP window scaling option according to RFC 7323

        The three-byte Window Scale option MAY be sent in a <SYN> segment by
        a TCP.  It has two purposes: (1) indicate that the TCP is prepared to
        both send and receive window scaling, and (2) communicate the
        exponent of a scale factor to be applied to its receive window.
        Thus, a TCP that is prepared to scale windows SHOULD send the option,
        even if its own scale factor is 1 and the exponent 0.  The scale
        factor is limited to a power of two and encoded logarithmically, so
        it may be implemented by binary shift operations.  The maximum scale
        exponent is limited to 14 for a maximum permissible receive window
        size of 1 GiB (2^(14+16)).

        +---------+---------+---------+
        | Kind=3  |Length=3 |shift.cnt|
        +---------+---------+---------+
            1         1         1

        :param shift_ct: Shift count (Default value = 0)
        '''
        o_kind = 3
        o_length = 3
        o_val = shift_ct

        opt = TCPOption({'kind': o_kind,
                         'length': o_length,
                         'option_data': tools.to_bytes(o_val, 1)})

        self.add_tcp_noop_option()
        self._options.append(opt)
        self._data_offset += 1
        if self._data_offset > 15:
            raise errors.MaxTCPHeaderSizeExceeded('Data offset greater than 16')


    def add_tcp_ts_option(self, ts_val=0, ts_ecr=0):
        '''
        Add a TCP timestamp option

        :param ts_val: Timestamp value (Default value = 0)
        :param ts_ecr: Timestamp echo request (Default value = 0)
        '''
        o_kind = 8
        o_length = 10


        opt = TCPOption({'kind': o_kind,
                         'length': o_length,
                         'option_data': tools.to_bytes(ts_val, 4)
                         + tools.to_bytes(ts_ecr, 4)})

        self.add_tcp_noop_option()
        self.add_tcp_noop_option()
        self._options.append(opt)
        self._data_offset += 3
        if self._data_offset > 15:
            raise errors.MaxTCPHeaderSizeExceeded('Data offset greater than 16')


    def add_tcp_sack_perm_option(self):
        '''
        Add a TCP SACK permitted option (RFC2018)
        '''
        o_kind = 4
        o_length = 2

        opt = TCPOption({'kind': o_kind, 'length': o_length})

        self.add_tcp_noop_option()
        self.add_tcp_noop_option()
        self._options.append(opt)
        self._data_offset += 1
        if self._data_offset > 15:
            raise errors.MaxTCPHeaderSizeExceeded('Data offset greater than 16')


    def add_tcp_sack_option(self, sack_blocks):
        '''
        Add a TCP SACK option (RFC2018)

        Left Edge of Block. 32 bits.
        The first sequence number of this block.

        Right Edge of Block. 32 bits.
        The sequence number immediately following the last sequence number of
        this block.

        :param sack_blocks: list of SACK blocks where every block is a tuple of
        (<int> left_edge, <int> right_edge)
        '''
        o_kind = 5
        o_length = 2
        o_data = b''

        for sack_blk in sack_blocks:
            o_data += tools.to_bytes(sack_blk[0], 4)
            o_data += tools.to_bytes(sack_blk[1], 4)
            o_length += 8

        opt = TCPOption({'kind': o_kind, 'length': o_length,
                         'option_data': o_data})

        self.add_tcp_noop_option()
        self.add_tcp_noop_option()
        self._data_offset += (o_length + 2) / 4
        if self._data_offset > 15:
            raise errors.MaxTCPHeaderSizeExceeded('Data offset greater than 16')
        self._options.append(opt)


    def add_tcp_noop_option(self):
        '''
        Add a TCP no operation option
        '''
        opt = TCPOption({'kind': 1})

        self._options.append(opt)


    def add_tcp_eol_option(self):
        '''
        Add a TCP end of option list option
        '''
        opt = TCPOption({'kind': 0})

        self.add_tcp_noop_option()
        self.add_tcp_noop_option()
        self.add_tcp_noop_option()
        self._options.append(opt)
        self._data_offset += 1
        if self._data_offset > 15:
            raise errors.MaxTCPHeaderSizeExceeded('Data offset greater than 16')


class TCPConnection:
    '''
    A take on implementing basic custom TCP connection management

    RFCs:   793     TCP core RFC
            1122    Requirements for Internet Hosts
            2018    Selective Acknowledgement Options
            2525    Known TCP Implemenation Problems
            5681    Congestion Control
            6298    Computing the Retransmission Timer
            6691    MSS and TCP Options
            7414    Implementation Roadmap

    Todo:
    - prevent kernel from interfering with our connection
    - local port selection for client connections
    '''


    # define connection state constants
    CLOSED = 0
    LISTEN = 1
    SYN_SENT = 2
    SYN_RECEIVED = 3
    ESTABLISHED = 4
    FIN_WAIT_1 = 5
    FIN_WAIT_2 = 6
    CLOSE_WAIT = 7
    CLOSING = 8
    LAST_ACK = 9
    TIME_WAIT = 10


    def __init__(self, local_port, remote_port):
        '''
        initialize TCP connection parameters
        '''
        self._tcb = {'local_port': 0,
                     'remote_port': 0,
                     'send_buffer': None,
                     'recv_buffer': None,
                     'rtx_queue': None,
                     'current_seg': 0,
                     'snd_una': 0,
                     'snd_nxt': 0,
                     'snd_wnd': 0,
                     'snd_up': 0,
                     'snd_wl1': 0,
                     'snd_wl2': 0,
                     'snd_isn': 0,
                     'rcv_nxt': 0,
                     'rcv_wnd': 0,
                     'rcv_up': 0,
                     'rcv_isn': 0}
        self._state = self.CLOSED
