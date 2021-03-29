'''Module for UDP functions used by custompk'''

from framebuilder import tools, layer3


class UDPDatagram(layer3.Base):
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

        self._length = udp_data.get('length', 0) & 0xffff

        proto = udp_data.get('layer3_proto', 0x0800)
        if proto == 0x0800:
            # IPv4 pseudo header
            pseudo_header = udp_data.get('pseudo_header', b'\x00' * 12)
        elif self._layer3_proto == 0x86dd:
            # IPv6 pseudo header
            pseudo_header = udp_data.get('pseudo_header', b'\x00' * 40)
        if pseudo_header is None:
            # pseudo header for unknown layer 3 protocols
            pseudo_header = udp_data.get('pseudo_header', b'')
        super().__init__(
            udp_data.get('src_port', 0) & 0xffff,
            udp_data.get('dst_port', 0) & 0xffff,
            proto,
            pseudo_header,
            udp_data.get('payload', b''),
            udp_data.get('checksum', 0) & 0xffff,
            )


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


    def get_bytes(self):
        '''
        Return UDP datagram as bytes
        '''
        return bytes(tools.to_bytes(self._src_port, 2) +
                     tools.to_bytes(self._dst_port, 2) +
                     tools.to_bytes(self._length, 2) +
                     tools.to_bytes(self._checksum, 2) +
                     self._payload)


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
