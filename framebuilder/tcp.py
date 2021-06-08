'''Module for TCP functions'''

import copy
import queue
from time import time_ns
from framebuilder import tools, errors as err, layer4, ipv4

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

        self._okind = opt_data.get('kind', 0)
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


class TCPSegment(layer4.Base):
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

        self._seq_nr = tcp_data.get('seq_nr', 0)
        self._ack_nr = tcp_data.get('ack_nr', 0)
        self._data_offset = tcp_data.get('data_offset', 5)
        self._flags = tcp_data.get('flags', 0)
        self._window = tcp_data.get('window', 0)
        self._urg_ptr = tcp_data.get('urg_ptr', 0)
        self._options = []
        if tcp_data.get('options', None) is not None:
            for opt in tcp_data['options']:
                next_option = TCPOption(opt)
                self._options.append(next_option)

        proto = tcp_data.get('layer3_proto', 0x0800)
        if proto == 0x0800:
            # IPv4 pseudo header
            pseudo_header = tcp_data.get('pseudo_header', None)
        elif proto == 0x86dd:
            # IPv6 pseudo header
            pseudo_header = tcp_data.get('pseudo_header', None)
        super().__init__(
            tcp_data.get('src_port', 0),
            tcp_data.get('dst_port', 0),
            proto,
            pseudo_header,
            tcp_data.get('payload', b''),
            tcp_data.get('checksum', 0)
            )


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
        # strip ethernet padding
        packet.payload = packet.payload[0:packet.total_length - packet.ihl * 4]
        segment = cls.from_bytes(packet.payload)
        segment.create_pseudo_header(packet)
        return segment


    def get_dict(self):
        '''
        Return TCP segment data as dictionary
        '''
        tcp_data = {}

        tcp_data['pseudo_header'] = self.pseudo_header
        tcp_data['src_port'] = self.src_port
        tcp_data['dst_port'] = self.dst_port
        tcp_data['seq_nr'] = self.seq_nr
        tcp_data['ack_nr'] = self.ack_nr
        tcp_data['data_offset'] = self.data_offset
        tcp_data['flags'] = self.flags
        tcp_data['window'] = self.window
        tcp_data['checksum'] = self.checksum
        tcp_data['urg_ptr'] = self.urg_ptr
        tcp_data['options'] = []
        for opt in self.options:
            tcp_data['options'].append(opt.get_dict())
        tcp_data['payload'] = self.payload
        return tcp_data


    def get_bytes(self):
        '''
        Return segment data as bytes
        '''
        opt_bytes = b''
        for opt in self.options:
            opt_bytes += opt.get_bytes()
        return bytes(tools.to_bytes(self.src_port, 2) +
                     tools.to_bytes(self.dst_port, 2) +
                     tools.to_bytes(self.seq_nr, 4) +
                     tools.to_bytes(self.ack_nr, 4) +
                     tools.to_bytes(self.data_offset << 4, 1) +
                     tools.to_bytes(self.flags, 1) +
                     tools.to_bytes(self.window, 2) +
                     tools.to_bytes(self.checksum, 2) +
                     tools.to_bytes(self.urg_ptr, 2) +
                     opt_bytes +
                     self.payload)


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


    def info(self):
        '''
        Print TCP segment info
        :param calc_cs: <bool> Calculate checksum?
        '''
        print('TCP source port     : ' + str(self.src_port))
        print('TCP destination port: ' + str(self.dst_port))
        print('TCP sequence number : ' + str(self.seq_nr))
        print('TCP ack number      : ' + str(self.ack_nr))
        print('TCP data offset     : ' + str(self.data_offset))
        print('TCP flags           : ' + self.get_flag_str())
        print('TCP receive window  : ' + str(self.window))
        if self.pseudo_header is not None:
            valid_str = '(incorrect)'
            if self.verify_checksum():
                valid_str = '(correct)'
            print('TCP checksum        : 0x' + format(self.checksum, '04x'),
                  valid_str)
        print('TCP urgent pointer  : ' + str(self.urg_ptr))
        print('TCP payload length  : ' + str(len(self.payload)))
        opt_count = 1
        for opt in self.options:
            print('TCP Option #{}'.format(opt_count))
            opt.info()
            opt_count += 1


    def __get_seq_nr(self):
        '''
        Getter for seq_nr
        '''
        return self._seq_nr


    def __set_seq_nr(self, seq_nr):
        '''
        Setter for seq_nr
        '''
        self.checksum = None
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
        self.checksum = None
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
        self.checksum = None
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
        self.checksum = None
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
            self.checksum = None
            self._flags += pos
        if self.__get_fin() == 1 and f_val & 1 == 0:
            self.checksum = None
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
            self.checksum = None
            self._flags += pos
        if self.__get_syn() == 1 and f_val & 1 == 0:
            self.checksum = None
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
            self.checksum = None
            self._flags += pos
        if self.__get_rst() == 1 and f_val & 1 == 0:
            self.checksum = None
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
            self.checksum = None
            self._flags += pos
        if self.__get_psh() == 1 and f_val & 1 == 0:
            self.checksum = None
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
            self.checksum = None
            self._flags += pos
        if self.__get_ack() == 1 and f_val & 1 == 0:
            self.checksum = None
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
            self.checksum = None
            self._flags += pos
        if self.__get_urg() == 1 and f_val & 1 == 0:
            self.checksum = None
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
            self.checksum = None
            self._flags += pos
        if self.__get_ece() == 1 and f_val & 1 == 0:
            self.checksum = None
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
            self.checksum = None
            self._flags += pos
        if self.__get_cwr() == 1 and f_val & 1 == 0:
            self.checksum = None
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
        self.checksum = None
        self._window = window

    window = property(__get_window, __set_window)


    def __get_urg_ptr(self):
        '''
        Getter for urg_ptr
        '''
        return self._urg_ptr


    def __set_urg_ptr(self, urg_ptr):
        '''
        Setter for urg_ptr
        '''
        self.checksum = None
        self._urg_ptr = urg_ptr

    urg_ptr = property(__get_urg_ptr, __set_urg_ptr)


    def __get_options(self):
        '''
        Setter for options
        '''
        return self._options


    def __set_options(self, options):
        '''
        Setter for options
        '''
        self.checksum = None
        self._options = options

    options = property(__get_options, __set_options)


    def delete_options(self):
        '''
        Deletes all options and resets data offset
        '''
        self.options = []
        self.data_offset = 5


    def __get_length(self):
        '''
        Getter for (payload) length
        '''
        return len(self.payload)

    length = property(__get_length)


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

        self.options.append(opt)
        self.data_offset += 1
        if self.data_offset > 15:
            raise err.MaxTCPHeaderSizeExceeded('Data offset greater than 16')


    def get_mss(self):
        '''
        Search for TCP MSS otion and return MSS or None
        '''
        for opt in self.options:
            odict = opt.get_dict()
            if odict['kind'] == 2:
                return tools.get_value_at(odict['option_data'], 2)
        return None


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
        self.options.append(opt)
        self.data_offset += 1
        if self.data_offset > 15:
            raise err.MaxTCPHeaderSizeExceeded('Data offset greater than 16')


    def get_wscale(self):
        '''
        Search for TCP window scaling otion and return shift count or None
        '''
        for opt in self.options:
            odict = opt.get_dict()
            if odict['kind'] == 3:
                return tools.get_value_at(odict['option_data'], 1)
        return None


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
        self.options.append(opt)
        self.data_offset += 3
        if self._data_offset > 15:
            raise err.MaxTCPHeaderSizeExceeded('Data offset greater than 16')


    def get_time_stamp(self):
        '''
        Search for TCP time stamp otion and return time stamp value and echo
        request as tuple (tsval, tsecr) or None
        '''
        for opt in self.options:
            odict = opt.get_dict()
            if odict['kind'] == 8:
                return (tools.get_value_at(odict['option_data'], 4),
                        tools.get_value_at(odict['option_data'], 4, 4))
        return None


    def add_tcp_sack_perm_option(self):
        '''
        Add a TCP SACK permitted option (RFC2018)
        '''
        o_kind = 4
        o_length = 2

        opt = TCPOption({'kind': o_kind, 'length': o_length})

        self.add_tcp_noop_option()
        self.add_tcp_noop_option()
        self.options.append(opt)
        self.data_offset += 1
        if self.data_offset > 15:
            raise err.MaxTCPHeaderSizeExceeded('Data offset greater than 16')


    def sack_permitted(self):
        '''
        Search for TCP SACK permitted option and return True if found and False
        if not
        '''
        for opt in self.options:
            odict = opt.get_dict()
            if odict['kind'] == 4:
                return True
        return False


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
        self.data_offset += (o_length + 2) / 4
        if self.data_offset > 15:
            raise err.MaxTCPHeaderSizeExceeded('Data offset greater than 16')
        self.options.append(opt)


    def add_tcp_noop_option(self):
        '''
        Add a TCP no operation option
        '''
        opt = TCPOption({'kind': 1})

        self.options.append(opt)


    def add_tcp_eol_option(self):
        '''
        Add a TCP end of option list option
        '''
        opt = TCPOption({'kind': 0})

        self.add_tcp_noop_option()
        self.add_tcp_noop_option()
        self.add_tcp_noop_option()
        self.options.append(opt)
        self.data_offset += 1
        if self.data_offset > 15:
            raise err.MaxTCPHeaderSizeExceeded('Data offset greater than 16')


class TCPHandler(ipv4.IPv4Handler):
    '''
    Convenience layer for TCP functions

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

    ##### define connection state constants #####
    # no connection state at all
    CLOSED = 0
    # represents waiting for a connection request from any remote TCP and port
    LISTEN = 1
    # represents waiting for a matching connection request after having sent a
    # connection request
    SYN_SENT = 2
    # represents waiting for a confirming connection request acknowledgment
    # after having both received and sent a connection request
    SYN_RECEIVED = 3
    # represents an open connection, data received can be delivered to the
    # user; the normal state for the data transfer phase of the connection.
    ESTABLISHED = 4
    # represents waiting for a connection termination request from the remote
    # TCP, or an acknowledgment of the connection termination request
    # previously sent
    FIN_WAIT_1 = 5
    # represents waiting for a connection termination request from remote TCP
    FIN_WAIT_2 = 6
    # represents waiting for a connection termination request from the local
    # user
    CLOSE_WAIT = 7
    # represents waiting for a connection termination request acknowledgment
    # from the remote TCP
    CLOSING = 8
    # represents waiting for an acknowledgment of the connection termination
    # request previously sent to the remote TCP (which includes an
    # acknowledgment of its connection termination request)
    LAST_ACK = 9
    # represents waiting for enough time to pass to be sure the remote TCP
    # received the acknowledgment of its connection termination request
    # -- not implemented here --
    TIME_WAIT = 10

    ##### define segment categories #####
    SEG_UNKNOWN = 0
    SEG_SYN = 1
    SEG_SYN_ACK = 2
    SEG_FIRST_ACK = 4
    SEG_PURE_ACK = 8
    SEG_ACK = 16
    SEG_DUP_ACK = 32
    SEG_FIN = 64
    SEG_RST = 128
    SEG_SPUR_RETRANS = 256

    def __init__(self, interface, local_port=None, remote_ip=None, block=1,
                 t_out=3.0, debug=False):
        '''
        initialize TCP connection parameters

        :param interface: <str> local interface (name or address)
        :param local_port: local port

        Send Sequence Space

                   1         2          3          4
              ----------|----------|----------|----------
                     SND.UNA    SND.NXT    SND.UNA
                                          +SND.WND

        Receive Sequence Space

                       1          2          3
                   ----------|----------|----------
                          RCV.NXT    RCV.NXT
                                    +RCV.WND
        '''
        self.debug = debug
        self._interface = interface
        self._local_port = local_port
        self._remote_port = None
        self._remote_ip = remote_ip

        # retransmission Queue
        # [{
        #   'segment': <TCPSegment>,
        #   'time': <int>,
        #   'delay': <int>
        # }, ...]
        self._rtx_queue = []

        # initial retransmission timeout 1s
        self._rto = 10**9

        self._send_buffer = queue.Queue()
        self._recv_buffer = bytearray()

        # initial send sequence number
        self._iss = tools.get_rfc793_isn()

        # lowest unacknowledged sequence number
        self._snd_una = self._iss

        # sequence number of next segment to be sent
        self._snd_nxt = self._iss

        # sequence number of next segment to be received
        self._rcv_next = 0

        # receive urgent pointer
        self._rcv_up = None

        # initial receive sequence number
        self._irs = None

        self.state = self.CLOSED

        # list of functions to be implemented that handle incoming packets
        # in different connection states
        self._recv_seg_handlers = {
                self.LISTEN: self.__recv_listen,
                self.SYN_SENT: self.__recv_syn_sent,
                self.SYN_RECEIVED: self.__recv_syn_recv,
                self.ESTABLISHED: self.__recv_established,
                self.FIN_WAIT_1: self.__recv_fin_wait1,
                self.FIN_WAIT_2: self.__recv_fin_wait2,
                self.CLOSE_WAIT: self.__recv_close_wait,
                self.CLOSING: self.__recv_closing,
                self.LAST_ACK: self.__recv_last_ack,
                self.TIME_WAIT: self.__recv_time_wait
                }

        super().__init__(interface, remote_ip, block=0, t_out=t_out)

        self._mss = self.mtu - 40

        # receive window
        self._max_rwin = 65535
        self._rcv_wnd = (self._max_rwin // self._mss) * self._mss

        # remote receive window
        self._rem_rwnd = 0

        # send window size (multiply by MSS)
        # let's start with 1 segment
        self._snd_wnd = 1

        # slow start threshold (multiply by MSS)
        self._ssthresh = 20

        # round trip time
        self._rtt = None

        # smoothed round trip time
        self._srtt = None

        # rtt variance
        self._rttvar = None


    def __del__(self):
        '''
        Remove iptables rules
        '''
        tools.unhide_from_kernel(self.interface, self.remote_ip,
                self.remote_port)
        tools.unhide_from_krnl_in(self.interface, self.local_ip,
                self.local_port)


    def info(self):
        '''
        Print debugging inormation
        '''
        print('MTU: {} -- RCV WIN: {} -- STATE: {}'.format(self.mtu,
            self._rcv_wnd, self.get_state_str()))
        print('LOCAL ADDR:', self.local_ip, self.local_port)
        print('REMOTE ADDR:', self.remote_ip, self.remote_port)
        print('ISN:', self._iss)
        print('NEXT RCV SEQNR:', self._rcv_next)
        print('RCV BUFFER LEN:', len(self._recv_buffer))
        print('NEXT SND SEQNR:', self._snd_nxt)
        print('UNACK:', self._snd_una)


    def get_state_str(self):
        '''
        Return the current state as string
        '''
        stat = {
            self.CLOSED: 'closed',
            self.LISTEN: 'listen',
            self.SYN_SENT: 'SYN sent',
            self.SYN_RECEIVED: 'SYN received',
            self.ESTABLISHED: 'established',
            self.FIN_WAIT_1: 'FIN wait 1',
            self.FIN_WAIT_2: 'FIN wait 2',
            self.CLOSE_WAIT: 'close wait',
            self.CLOSING: 'closing',
            self.LAST_ACK: 'last ACK',
            self.TIME_WAIT: 'time wait'
            }
        return stat.get(self.state, 'unknown!')


    def __get_remote_port(self):
        '''
        Getter for remote port
        '''
        return self._remote_port


    def __set_remote_port(self, remote_port):
        '''
        Setter for remote port
        '''
        if self._remote_port is None:
            self._remote_port = remote_port

    remote_port = property(__get_remote_port, __set_remote_port)


    def __get_local_port(self):
        '''
        Getter for local port
        '''
        return self._local_port


    def __set_local_port(self, local_port):
        '''
        Setter for local port
        '''
        if self._local_port is None:
            self._local_port = local_port

    local_port = property(__get_local_port, __set_local_port)


    @classmethod
    def listen(cls, interface, local_port, debug=False):
        '''
        Wait for incoming connections on interface and local port
        :param interface: interface (name or address) to listen on
        :param local_port: port number to bind to
        '''
        handler = cls(interface, local_port, debug=debug)
        handler.state = cls.LISTEN
        if handler.debug:
            tools.print_rgb('LISTEN on interface {} port {}'.format(
                interface, local_port),
                rgb=(127, 127, 127), bold=True)
        tools.hide_from_krnl_in(handler.interface, handler.local_ip,
                handler.local_port)
        while True:
            handler.receive_segment()
            if handler.state == cls.ESTABLISHED:
                return handler


    def open(self, remote_ip, remote_port, local_port=None):
        '''
        Establish a TCP connection to a remote TCP server and return a new
        TCP Handler

        :param remote_ip: IP address of the server
        :param remote_port: TCP port to connect to
        :param local_port: local TCP port
        '''
        if self.state != self.CLOSED:
            raise err.NoTCPConnectionException('open() while status not closed')
        rt_info = tools.get_route(remote_ip)
        self.interface = rt_info['dev']
        if local_port is not None:
            self.local_port = local_port
        else:
            self.local_port = tools.get_local_tcp_port()
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        tools.hide_from_kernel(self.interface, self.remote_ip, self.remote_port)

        segment = TCPSegment()
        segment.src_port = self.local_port
        segment.dst_port = self.remote_port
        segment.seq_nr = self._snd_nxt
        segment.ack_nr = self._rcv_next
        segment.window = self._rcv_wnd
        segment.syn = 1
        segment.add_tcp_mss_option(self._mss)
        self.send_segment(segment)
        self.state = self.SYN_SENT
        if self.debug:
            tools.print_rgb('SYN-SENT to {}:{}'.format(
                self.remote_ip, self.remote_port),
                rgb=(127, 127, 127), bold=True)
        while self.state != self.CLOSED:
            self.receive_segment()
            if self.state == self.ESTABLISHED:
                break


    def receive(self, size=0, pass_on_error=True):
        '''
        Receive size bytes of data
        :param size: if less or equal 0 read everything
        '''
        self.receive_segment(pass_on_error)
        result = b''
        if size > 0:
            if len(self._recv_buffer) >= size:
                if self.debug:
                    tools.print_rgb(f'state: {self.state} ', rgb=(255, 0, 0), end='')
                    tools.print_rgb(f'una: {self._snd_una} ', rgb=(255, 0, 0), end='')
                    tools.print_rgb(f'rcv_buf_len: {len(self._recv_buffer)} Bytes', rgb=(255, 0, 0), end='')
                    tools.print_rgb(f's_nxt: {self._snd_nxt} ', rgb=(255, 0, 0), end='')
                    tools.print_rgb(f'r_nxt: {self._rcv_next}', rgb=(255, 0, 0))
                result = self._recv_buffer[:size]
                self._recv_buffer = self._recv_buffer[size:]
        else:
            result = copy.copy(self._recv_buffer)
            self._recv_buffer.clear()
        self._rcv_wnd = self._max_rwin - len(self._recv_buffer)
        return result


    def send(self, data, dont_frag=True):
        '''
        Send data over a TCP connection
        '''
        if self.state == self.CLOSED:
            raise err.NoTCPConnectionException('send() while status closed')

        if self.remote_port is None:
            raise err.InvalidPortException('remote TCP port missing')

        if self.remote_ip is None:
            raise err.InvalidIPv4AddrException('None')

        index = 0
        while True:
            if index + self._mss > len(data):
                self._send_buffer.put(data[index:])
                break
            self._send_buffer.put(data[index:index+self._mss])
            index += self._mss

        while ((not self._send_buffer.empty()) or len(self._rtx_queue) > 0) \
                and self.state != self.CLOSED:
            # choose the lower of send window or remote receive window as
            # effective send window
            eff_snd_wnd = min(self._snd_wnd * self._mss, self._rem_rwnd)
            if eff_snd_wnd == 0 and self.debug:
                tools.print_rgb('\t\t\t! Zero Window !', rgb=(255, 50, 50))
            while tools.tcp_sn_lt(self._snd_nxt,
                    tools.mod32(self._snd_una + eff_snd_wnd)) \
                            and not self._send_buffer.empty() \
                            and eff_snd_wnd > 0 \
                            and len(self._rtx_queue) <= self._snd_wnd \
                            and self.state != self.CLOSED:
                segment = TCPSegment()
                segment.payload = self._send_buffer.get()
                segment.src_port = self.local_port
                segment.dst_port = self.remote_port
                segment.ack = 1
                if self._send_buffer.empty():
                    segment.psh = 1
                segment.seq_nr = self._snd_nxt
                segment.ack_nr = self._rcv_next
                segment.window = self._rcv_wnd
                self.send_segment(segment)
                self.receive_segment()
                self.__process_rtx_queue()
            self.receive_segment()
            self.__process_rtx_queue()


    def close(self):
        '''
        Close the connection
        '''
        if self.state != self.ESTABLISHED:
            raise err.NoTCPConnectionException('invalid state: ' + \
                    self.get_state_str())
        segment = TCPSegment()
        segment.src_port = self.local_port
        segment.dst_port = self.remote_port
        segment.fin = 1
        segment.ack = 1
        segment.seq_nr = self._snd_nxt
        segment.ack_nr = self._rcv_next
        segment.window = self._rcv_wnd
        self.send_segment(segment)
        self.state = self.FIN_WAIT_1
        while self.state != self.CLOSING and self.state != self.TIME_WAIT and \
                self.state != self.CLOSED:
            self.receive_segment()
        self.state = self.CLOSED
        if self.debug:
            tools.print_rgb('connection CLOSED',
                    rgb=(127, 127, 127), bold=True)


    def abort(self):
        '''
        Actively reset the connection and send RST
        '''
        segment = TCPSegment()
        segment.src_port = self.local_port
        segment.dst_port = self.remote_port
        segment.rst = 1
        segment.seq_nr = self._snd_nxt
        segment.window = self._rcv_wnd
        self.send_segment(segment)
        self.state = self.CLOSED


    def __send_ack(self):
        '''
        Send acknowledgement
        '''
        answer = TCPSegment()
        answer.ack = 1
        if not self._send_buffer.empty():
            answer.payload = self._send_buffer.get()
        if self.state == self.CLOSE_WAIT \
                and len(self._recv_buffer) == 0: #????
            answer.fin = 1
            self.state = self.LAST_ACK
        if self.state == self.SYN_RECEIVED:
            answer.syn = 1
            answer.add_tcp_mss_option(self._mss)
        answer.src_port = self.local_port
        answer.dst_port = self.remote_port
        answer.window = self._rcv_wnd
        answer.seq_nr = self._snd_nxt
        answer.ack_nr = self._rcv_next
        return self.send_segment(answer)


    def __recv_listen(self, segment: TCPSegment):
        '''
        Process incoming segment in LISTEN state
        :param packet: Incoming packet
        '''
        conditions = (
                segment.ack == 0,
                segment.rst == 0,
                segment.fin == 0,
                segment.syn == 1
                )

        if all(conditions):
            seg_mss = segment.get_mss()
            if seg_mss is not None:
                if seg_mss < self._mss:
                    self._mss = seg_mss
            else:
                self._mss = 536
            self._irs = segment.seq_nr
            self._rcv_next = self._irs
            self.remote_port = segment.src_port
            self.state = self.SYN_RECEIVED
            if self.debug:
                tools.print_rgb('entering SYN-RECEIVED state',
                        rgb=(127, 127, 127), bold=True)
            return segment
        return None


    def __recv_syn_sent(self, segment: TCPSegment):
        '''
        Process incoming segment in SYN_SENT state
        :param packet: Incoming packet
        '''
        conditions = (
                segment.ack == 1,
                segment.rst == 0,
                segment.fin == 0,
                segment.syn == 1
                )

        if all(conditions):
            seg_mss = segment.get_mss()
            if seg_mss is not None:
                if seg_mss < self._mss:
                    self._mss = seg_mss
            self._irs = segment.seq_nr
            self._rcv_next = self._irs
            self.remote_port = segment.src_port
            self.state = self.ESTABLISHED
            if self.debug:
                tools.print_rgb('entering ESTABLISHED state',
                        rgb=(127, 127, 127), bold=True)
            return segment
        if segment.rst == 1:
            if self.debug:
                tools.print_rgb('RST received, entering CLOSED state',
                        rgb=(127, 127, 127), bold=True)
            self.state = self.CLOSED
            return segment
        return None


    def __recv_syn_recv(self, segment: TCPSegment):
        '''
        Process incoming segment in SYN_RECV state
        :param packet: Incoming packet
        '''
        conditions = (
                segment.ack == 1,
                segment.rst == 0,
                segment.fin == 0,
                segment.syn == 0
                )

        if all(conditions):
            self.state = self.ESTABLISHED
            if self.debug:
                tools.print_rgb('entering ESTABLISHED state',
                        rgb=(127, 127, 127), bold=True)
            return segment
        if segment.rst == 1:
            self.state = self.LISTEN
            if self.debug:
                tools.print_rgb('RST received, entering LISTEN state',
                        rgb=(127, 127, 127), bold=True)
            return segment
        if segment.fin == 1:
            self.state = self.FIN_WAIT_1
            if self.debug:
                tools.print_rgb('FIN received, entering FIN-WAIT-1 state',
                        rgb=(127, 127, 127), bold=True)
            return segment
        return None


    def __recv_established(self, segment: TCPSegment):
        '''
        Process incoming segment in ESTABLISHED state
        :param packet: Incoming packet
        '''
        conditions = (
                segment.ack == 1,
                segment.rst == 0,
                segment.syn == 0
                )

        if all(conditions):
            if segment.fin == 1:
                self.state = self.CLOSE_WAIT
                if self.debug:
                    tools.print_rgb('FIN received, entering CLOSE-WAIT state',
                            rgb=(127, 127, 127), bold=True)
            return segment
        if segment.rst == 1:
            if self.debug:
                tools.print_rgb('RST received, aborting connection',
                        rgb=(127, 127, 127), bold=True)
            self.state = self.CLOSED
            return segment
        return None


    def __recv_fin_wait1(self, segment: TCPSegment):
        '''
        Process incoming segment in FIN_WAIT_1 state
        :param packet: Incoming packet
        '''
        conditions = (
                segment.ack == 1,
                segment.rst == 0,
                segment.syn == 0
                )

        if all(conditions):
            self.state = self.FIN_WAIT_2
            if self.debug:
                tools.print_rgb('entering FIN-WAIT-2 state',
                        rgb=(127, 127, 127), bold=True)
            if segment.fin == 1:
                self.state = self.CLOSING
                if self.debug:
                    tools.print_rgb('FIN received, entering CLOSING state',
                            rgb=(127, 127, 127), bold=True)
            return segment
        if segment.rst == 1:
            if self.debug:
                tools.print_rgb('RST received, aborting connection',
                        rgb=(127, 127, 127), bold=True)
            self.state = self.CLOSED
            return segment
        return None


    def __recv_fin_wait2(self, segment: TCPSegment):
        '''
        Process incoming segment in FIN_WAIT2 state
        :param packet: Incoming packet
        '''
        conditions = (
                segment.ack == 1,
                segment.rst == 0,
                segment.syn == 0
                )

        if all(conditions):
            if segment.fin == 1:
                self.state = self.TIME_WAIT
                if self.debug:
                    tools.print_rgb('FIN received, entering TIME-WAIT state',
                            rgb=(127, 127, 127), bold=True)
            return segment
        if segment.rst == 1:
            self.state = self.CLOSED
            if self.debug:
                tools.print_rgb('RST received, entering CLOSED state',
                        rgb=(127, 127, 127), bold=True)
        return None


    def __recv_close_wait(self, segment: TCPSegment):
        '''
        Process incoming segment in CLOSE_WAIT state
        :param packet: Incoming packet
        '''
        conditions = (
                segment.ack == 1,
                segment.rst == 0,
                segment.fin == 0,
                segment.syn == 0
                )

        if all(conditions):
            return segment
        if segment.rst == 1:
            self.state = self.CLOSED
            if self.debug:
                tools.print_rgb('RST received, entering CLOSED state',
                        rgb=(127, 127, 127), bold=True)
            return segment
        return None


    def __recv_closing(self, segment: TCPSegment):
        '''
        Process incoming segment in CLOSING state
        :param packet: Incoming packet
        '''
        if segment.ack == 1:
            self.state = self.TIME_WAIT
            if self.debug:
                tools.print_rgb('entering TIME-WAIT state',
                        rgb=(127, 127, 127), bold=True)
            return segment
        return None


    def __recv_time_wait(self, segment: TCPSegment):
        '''
        Process incoming segment in TIME_WAIT state
        :param packet: Incoming packet
        '''
        if self.debug:
            tools.print_rgb('received segment in TIME-WAIT state, sending RST',
                    rgb=(127, 127, 127), bold=True)
            tools.print_rgb('droped segment SEQ {}'.format(segment.ack_nr),
                    rgb=(127, 127, 127))
            self.state = self.CLOSED


    def __recv_last_ack(self, segment: TCPSegment):
        '''
        Process incoming segment in LAST_ACK state
        :param packet: Incoming packet
        '''
        if segment.ack == 1:
            self.state = self.CLOSED
            if self.debug:
                tools.print_rgb('entering CLOSED state',
                        rgb=(127, 127, 127), bold=True)
            tools.unhide_from_krnl_in(self.interface, self.local_ip,
                    self.local_port)
            return segment
            if self.debug:
                tools.print_rgb('entering TIME-WAIT state',
                        rgb=(127, 127, 127), bold=True)
        if segment.rst == 1:
            return segment
        return None


    def __clean_rtx_queue(self):
        '''
        remove acknowledged segments from rtx_queue
        '''
        index = 0
        for rtx_entry in self._rtx_queue:
            if tools.tcp_sn_gt(self._snd_una,\
                    tools.mod32(rtx_entry['segment'].seq_nr + \
                            rtx_entry['segment'].length - 1)):
                if rtx_entry['delay'] == 0:
                    self.__calc_rto(time_ns() - rtx_entry['time'])
                self._rtx_queue.remove(self._rtx_queue[index])
                if self.debug:
                    tools.print_rgb(
                            '\tremoving segment from retransmission queue',
                            rgb=(127, 127, 127))
                    tools.print_rgb('\t\tSEQNR {} ACKNR {} UNA {}'.format(
                        rtx_entry['segment'].seq_nr,
                        rtx_entry['segment'].ack_nr,
                        self._snd_una), rgb=(127, 127, 127))
                    tools.print_rgb('\t\t{} segments in queue'.format(
                        len(self._rtx_queue)), rgb=(127, 127, 127))
            elif tools.tcp_sn_gt(self._snd_una,
                    rtx_entry['segment'].seq_nr):
                pl_slice = rtx_entry['segment'].payload[self._snd_una:]
                rtx_entry['segment'].payload = pl_slice
                if rtx_entry['delay'] == 0:
                    self.__calc_rto(time_ns() - rtx_entry['time'])
                if self.debug:
                    tools.print_rgb(
                            '\tcutting segment payload in retransmission queue',
                            rgb=(127, 100, 100))
                    tools.print_rgb('\t\tSEQNR {} ACKNR {}'.format(
                        rtx_entry['segment'].seq_nr,
                        rtx_entry['segment'].ack_nr), rgb=(127, 100, 100))
                    tools.print_rgb('\t\tUNA {} > {}? length {} Bytes'.format(
                        self._snd_una,
                        rtx_entry['segment'].seq_nr,
                        rtx_entry['segment'].length), rgb=(255, 0, 0))
                index += 1
            else:
                index += 1


    def __process_rtx_queue(self, dont_frag=True):
        '''
        resend unacknowledged segments if rto is exceeded
        '''
        self.__clean_rtx_queue()
        # resend timed out segments
        curr_time = time_ns()
        for rtx_entry in self._rtx_queue:
            if rtx_entry['time'] + (self._rto << rtx_entry['delay']) \
                    < curr_time:
                # Timeout! Set send window to 1 MSS and divide ssthresh by 2
                if self.debug:
                    tools.print_rgb(
                        '\tretransmission timeout exceeded, resending segment',
                        rgb=(255, 50, 50), bold=True)
                    tools.print_rgb(
                        '\t\tSEQNR {} ACKNR {} WAITT {} ns RTO {} ns'.format(
                            rtx_entry['segment'].seq_nr,
                            rtx_entry['segment'].ack_nr,
                            curr_time - rtx_entry['time'],
                            self._rto), rgb=(255, 50, 50))
                if self._ssthresh > 1:
                    self._ssthresh = self._ssthresh // 2
                self._snd_wnd = 1
                if rtx_entry['delay'] > 8:
                    self.abort()
                    break
                rtx_entry['time'] = time_ns()
                rtx_entry['delay'] += 1
                super().send(rtx_entry['segment'], dont_frag)


    def send_segment(self, segment, dont_frag=True):
        '''
        Send a single TCP segment to remote host
        Remote port and remote IP must be set appropriately

        :param segment: <TCPSegment> segment to send
        :param dont_frag: Add DF Flag in IP header?
        '''
        ack_len = segment.length
        # SYN and FIN are treated as 1 virtual byte
        if segment.syn == 1 or segment.fin == 1:
            ack_len += 1
        if ack_len > 0:
            self._rtx_queue.append({'segment': segment,
                                    'time': time_ns(),
                                    'delay': 0})
            self._snd_nxt = tools.mod32(self._snd_nxt + ack_len)
        if self.debug:
            tools.print_rgb(
                    '\n-{:->9}-Bytes--SEQ-{:-<10}--ACK-{:-<10}'.format(
                        segment.length,
                        segment.seq_nr,
                        segment.ack_nr) + \
                        '--RWND-{:-<8}--FLAGS-{:-<15}> '.format(
                        segment.window,
                        segment.get_flag_str()), rgb=(50, 255, 50), bold=True)
        return super().send(segment, dont_frag) - segment.data_offset * 4


    def __get_cat_str(self, cat_bitmap):
        '''
        Return a string representation of the category bitmap
        :param cat_bitmap: category bitmap
        '''
        cat_list = []
        if cat_bitmap == self.SEG_UNKNOWN:
            return 'unknown'
        if cat_bitmap & self.SEG_SYN:
            cat_list.append('SYN')
        if cat_bitmap & self.SEG_SYN_ACK:
            cat_list.append('SYN-ACK')
        if cat_bitmap & self.SEG_DUP_ACK:
            cat_list.append('DUP-ACK')
        if cat_bitmap & self.SEG_FIN:
            cat_list.append('FIN')
        if cat_bitmap & self.SEG_FIRST_ACK:
            cat_list.append('FIRST-ACK')
        if cat_bitmap & self.SEG_ACK:
            cat_list.append('ACK')
        if cat_bitmap & self.SEG_PURE_ACK:
            cat_list.append('PURE-ACK')
        if cat_bitmap & self.SEG_RST:
            cat_list.append('RST')
        if cat_bitmap & self.SEG_SPUR_RETRANS:
            cat_list.append('SPUR-RETRANS')
        return '|'.join(cat_list)


    def __categorize_segment(self, segment: TCPSegment):
        '''
        Categorize segment, OR-ing all category flags together and return result
        
        :param segment: segment to evaluate
        '''
        result = 0
        seg_size = segment.length
        if segment.syn == 1 and segment.ack == 0:
            result |= self.SEG_SYN
        if segment.syn == 1 and segment.ack == 1:
            result |= self.SEG_SYN_ACK
        if segment.rst == 1:
            result |= self.SEG_RST
        if segment.fin == 1:
            result |= self.SEG_FIN
        if seg_size == 0 \
                and tools.tcp_sn_lt(segment.ack_nr, self._snd_una) \
                and segment.window == self._rem_rwnd \
                and self._rcv_next != 0 \
                and self._snd_nxt != self._iss \
                and result & self.SEG_SYN == 0 \
                and result & self.SEG_FIN == 0 \
                and result & self.SEG_SYN_ACK == 0 \
                and result & self.SEG_RST == 0:
            result |= self.SEG_DUP_ACK
        if seg_size > 0 and tools.tcp_sn_lt(segment.ack_nr, self._snd_una) \
                and result & self.SEG_SYN == 0:
            result |= self.SEG_SPUR_RETRANS
        if result == 0 and self._is_in_rcv_seq_space(segment):
            if seg_size == 0:
                if segment.ack_nr == tools.mod32(self._iss + 1):
                    result |= self.SEG_FIRST_ACK
                result |= self.SEG_PURE_ACK
            result |= self.SEG_ACK
        return result


    def receive_segment(self, pass_on_error=True):
        '''
        Reveive a single TCP segment
        local port and local IP must be set appropriately

        :param pass_on_error: <bool> return None if non-blocking socket does
                                     not receive anything
        '''

        if self.state == self.CLOSED:
            # do not process any segments if connection is closed
            return None

        if self.local_port is None:
            raise err.InvalidPortException('local TCP port missing')

        if self.local_ip is None:
            raise err.InvalidIPv4AddrException('None')

        packet = super().receive(pass_on_error)
        if packet is None:
            return None

        segment = TCPSegment.from_packet(packet)
        if segment.dst_port != self.local_port:
            return None

        if self.remote_port is not None:
            if segment.src_port != self.remote_port:
                return None

        if self._rcv_next is not None and self.state != self.SYN_SENT \
                and self.state != self.LISTEN:
            if not self._is_in_rcv_seq_space(segment):
                return None

        next_seg = self._recv_seg_handlers[self.state](segment)

        if next_seg is not None:

            # evaluate checksum
            if not next_seg.verify_checksum:
                return None

            seg_cat = self.__categorize_segment(next_seg)

            # drop out of order segments
            if next_seg.seq_nr != self._rcv_next \
                    and self.state != self.LISTEN \
                    and self.state != self.SYN_SENT:
                return None

            # update receive window size
            pl_len = next_seg.length
            if pl_len > 0:
                self._recv_buffer.extend(next_seg.payload)
                rwin_bytes = self._rcv_wnd * self._mss
                buf_len = len(self._recv_buffer)
                if rwin_bytes > buf_len:
                    self._rcv_wnd = (rwin_bytes - buf_len) // self._mss
                else:
                    self._rcv_wnd = 0

            if self.state == self.SYN_RECEIVED:
                self.remote_ip = packet.src_addr

            self._rcv_next = tools.mod32(self._rcv_next + next_seg.length)
            # SYN and FIN flag are treated as one virtual byte
            if next_seg.syn == 1 or next_seg.fin == 1:
                self._rcv_next = tools.mod32(self._rcv_next + 1)

            # advance self._una and check retransmission queue
            if tools.tcp_sn_gt(next_seg.ack_nr, tools.mod32(self._snd_una - 1)):
                self._snd_una = next_seg.ack_nr

            # update remote receive window, if necessary
            if self._rem_rwnd != next_seg.window:
                self._rem_rwnd = next_seg.window

            if self.debug:
                tools.print_rgb(
                        '\n<{:->9}-Bytes--SEQ-{:-<10}--ACK-{:-<10}'.format(
                            next_seg.length,
                            next_seg.seq_nr,
                            next_seg.ack_nr) + \
                            '--RWND-{:-<8}--FLAGS-{:-<16}'.format(
                            next_seg.window,
                            next_seg.get_flag_str()),
                        rgb=(150, 150, 255), bold=True)
                tools.print_rgb('\tsegment categories: [{}]'.format(
                        self.__get_cat_str(seg_cat)),
                        rgb=(75, 75, 127), bold=True)

            # only acknowledge if segment is not a pure ACK and not a reset
            if not seg_cat & self.SEG_PURE_ACK and not seg_cat & self.SEG_RST:
                self.__send_ack()
            if seg_cat & self.SEG_ACK:
                # ACK received
                if (self._snd_wnd << 1) <= self._ssthresh:
                    # Slow Start
                    self._snd_wnd <<= 1
                    if self.debug:
                        tools.print_rgb(
                                '\tincreased cwnd to {} segments'.format(
                                    self._snd_wnd), rgb=(127, 127, 127))
                elif (self._snd_wnd + 1) * self._mss < self._max_rwin:
                    # Congestion Avoidance
                    self._snd_wnd += 1
                    if self.debug:
                        tools.print_rgb(
                                '\tincreased cwnd to {} segments'.format(
                                    self._snd_wnd), rgb=(127, 127, 127))
            return next_seg
        return None


    def _is_in_rcv_seq_space(self, segment: TCPSegment):
        '''
        Check if incoming TCP segment lies within receive sequence space

        :param segment: <TCPSegment> incoming TCP segment
        '''
        seg_length = segment.length

        if self._rcv_wnd == 0:
            if seg_length == 0:
                return segment.seq_nr == self._rcv_next
            return False
        if seg_length == 0:
            return (self._rcv_next == segment.seq_nr or \
                    tools.tcp_sn_lt(self._rcv_next, segment.seq_nr)) and \
                    tools.tcp_sn_gt(self._rcv_next + self._rcv_wnd,
                                    segment.seq_nr)
        return (self._rcv_next == segment.seq_nr or \
                tools.tcp_sn_lt(self._rcv_next, segment.seq_nr)) and \
                tools.tcp_sn_gt(self._rcv_next + self._rcv_wnd,
                                segment.seq_nr) or \
               (self._rcv_next == segment.seq_nr + seg_length - 1 or \
                tools.tcp_sn_lt(self._rcv_next,
                                segment.seq_nr + seg_length - 1)) and \
                tools.tcp_sn_gt(self._rcv_next + self._rcv_wnd,
                                segment.seq_nr + seg_length - 1)


    def __calc_rto(self, newrtt, alpha=0.125, beta=0.25):
        '''
        Calculates the retransmission timeout

        :param newrtt: new round trip time
        :param alpha: smoothing factor for _srtt
        :param beta: smoothing factor for _rttvar
        '''
        if self._rtt is None:
            self._rtt = newrtt
            self._srtt = self._rtt
            self._rttvar = self._rtt >> 1
        else:
            self._rtt = newrtt
            self._rttvar = (1 - beta) * self._rttvar + \
                    beta * abs(self._srtt - self._rtt)
            self._srtt = (1 - alpha) * self._srtt + alpha * self._rtt
        self._rto = int(self._srtt + (self._rttvar * 4))
        if self._rto < 10 ** 9:
            self._rto = 10 ** 9
