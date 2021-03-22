'''Module for UDP functions used by custompk'''

from framebuilder import tools


class UDPDatagram():
    '''
    Creata a UDP datagram according to RFC 768

     0      7 8     15 16    23 24    31
    +--------+--------+--------+--------+
    |     Source      |   Destination   |
    |      Port       |      Port       |
    +--------+--------+--------+--------+
    |                 |                 |
    |     Length      |    Checksum     |
    +--------+--------+--------+--------+
    |
    |          data octets ...
    +---------------- ...
    '''

    def __init__(self, udp_data=None):
        '''
        Initialize UDP datagram
        :param udp_data: Dictionary containing UDP data as follows
        {
            layer3_proto: <int> Layer 3 protocol ID
            pseudo_header: <bytes> Pseudo header of network layer protocol
            src_port: <int> Source port (2 Bytes)
            dst_port: <int> Destination port (2 Bytes)
            length: <int> Length (2 Bytes)
            checksum: <int> UDP Checksum (2 Bytes)
            payload: <bytes> payload data
        }
        '''
        if udp_data is None:
            udp_data = {}

        self._layer3_proto = udp_data.get('layer3_proto', 0x0800)
        if self._layer3_proto == 0x0800:
            # IPv4 pseudo header
            self._pseudo_header = udp_data.get('pseudo_header', b'\x00' * 12)
        if self._layer3_proto == 0x86dd:
            # IPv6 pseudo header
            self._pseudo_header = udp_data.get('pseudo_header', b'\x00' * 40)
        if self._pseudo_header is None:
            # pseudo header for unknown layer 3 protocols
            self._pseudo_header = udp_data.get('pseudo_header', b'')
        self._src_port = udp_data.get('src_port', 0) & 0xffff
        self._dst_port = udp_data.get('dst_port', 0) & 0xffff
        self._length = udp_data.get('length', 0) & 0xffff
        self._checksum = udp_data.get('checksum', 0) & 0xffff
        self._payload = udp_data.get('payload', b'')


    @classmethod
    def from_bytes(cls, udp_bytes):
        '''
        Create UDPDatagram object from bytes
        '''
        udp_data = {}
        udp_data['src_port'] = tools.get_value_at(udp_bytes, 2, 0)
        udp_data['dst_port'] = tools.get_value_at(udp_bytes, 2, 2)
        udp_data['length'] = tools.get_value_at(udp_bytes, 2, 4)
        udp_data['checksum'] = tools.get_value_at(udp_bytes, 2, 6)
        udp_data['payload'] = udp_bytes[8:]
        return cls(udp_data)


    @classmethod
    def from_packet(cls, packet):
        '''
        Create UDP datagram object from layer 3 packet payload
        '''
        dgram = cls.from_bytes(packet.payload)
        dgram.create_pseudo_header(packet)
        return dgram


    def info(self, calc_cs=False):
        '''
        Print datagram information
        :param calc_cs: <bool> Calculate checksum?
        '''
        if calc_cs:
            self.update_checksum()
        print('UDP source port     : ' + str(self._src_port))
        print('UDP destination port: ' + str(self._dst_port))
        print('UDP length          : ' + str(self._length))
        valid_str = '(incorrect)'
        if self.verify_checksum():
            valid_str = '(correct)'
        print('UDP checksum        : 0x' + format(self._checksum, '04x'),
              valid_str)


    def get_dict(self):
        '''
        Returns UDP data as dictionary
        '''
        udp_data = {}
        udp_data['layer3_proto'] = self._layer3_proto
        udp_data['pseudo_header'] = self._pseudo_header
        udp_data['src_port'] = self._src_port
        udp_data['dst_port'] = self._dst_port
        udp_data['length'] = self._length
        udp_data['checksum'] = self._checksum
        udp_data['payload'] = self._payload
        return udp_data


    def encapsulate(self, packet):
        '''
        Encapsulate UDP datagram into packet
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
            new_len_bytes = tools.to_bytes(self._length, 2)
            self._pseudo_header = tools.set_bytes_at(self._pseudo_header,
                                                     new_len_bytes, 10)
        if len(self._pseudo_header) == 40:
            # IPv6
            self._layer3_proto = 0x86dd
            new_len_bytes = tools.to_bytes(self._length, 4)
            self._pseudo_header = tools.set_bytes_at(self._pseudo_header,
                                                     new_len_bytes, 32)


    def update_checksum(self):
        '''
        Update UDP checksum and length
        '''
        self._checksum = 0
        self._checksum = tools.calc_chksum(self._pseudo_header +
                                           self.get_bytes() +
                                           b'\x00' * (len(self._payload) % 2))

    def verify_checksum(self):
        '''
        Verify UDP checksum
        '''
        result = tools.calc_chksum(self._pseudo_header +
                                   self.get_bytes() +
                                   b'\x00' * (len(self._payload) % 2))
        if result == 0xffff:
            return True
        return False


    def get_bytes(self):
        '''
        Return UDP datagram as bytes
        '''
        return bytes(tools.to_bytes(self._src_port, 2) +
                     tools.to_bytes(self._dst_port, 2) +
                     tools.to_bytes(self._length, 2) +
                     tools.to_bytes(self._checksum, 2) +
                     self._payload)


    def __get_src_port(self):
        '''
        Getter source port
        '''
        return self._src_port


    def __set_src_port(self, src_port):
        '''
        Setter source port
        '''
        self._src_port = src_port

    src_port = property(__get_src_port, __set_src_port)


    def __get_dst_port(self):
        '''
        Getter destination port
        '''
        return self._dst_port


    def __set_dst_port(self, dst_port):
        '''
        Setter destination port
        '''
        self._dst_port = dst_port

    dst_port = property(__get_dst_port, __set_dst_port)


    def __get_length(self):
        '''
        Getter length
        '''
        return self._length


    def __set_length(self, length):
        '''
        Setter length
        '''
        self._length = length

    length = property(__get_length, __set_length)


    def __get_checksum(self):
        '''
        Getter checksum
        '''
        return self._checksum


    def __set_checksum(self, checksum):
        '''
        Setter checksum
        '''
        self._checksum = checksum

    checksum = property(__get_checksum, __set_checksum)


    def __get_payload(self):
        '''
        Getter payload
        '''
        return self._payload


    def __set_payload(self, payload):
        '''
        Setter payload
        '''
        self._payload = payload
        self._length = len(self.get_bytes())

    payload = property(__get_payload, __set_payload)


    def __get_pseudo_header(self):
        '''
        Getter pseudo header
        '''
        return self._pseudo_header


    def __set_pseudo_header(self, pseudo_header):
        '''
        Setter pseudo header
        '''
        self._pseudo_header = pseudo_header

    pseudo_header = property(__get_pseudo_header, __set_pseudo_header)
