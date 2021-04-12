'''Module for UDP functions used by custompk'''

from framebuilder import tools, layer4


class UDPDatagram(layer4.Base):
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

        self._length = udp_data.get('length', 0)

        proto = udp_data.get('layer3_proto', 0x0800)
        if proto == 0x0800:
            # IPv4 pseudo header
            pseudo_header = udp_data.get('pseudo_header', None)
        elif self._layer3_proto == 0x86dd:
            # IPv6 pseudo header
            pseudo_header = udp_data.get('pseudo_header', None)
        super().__init__(
            udp_data.get('src_port', 0),
            udp_data.get('dst_port', 0),
            proto,
            pseudo_header,
            udp_data.get('payload', b''),
            udp_data.get('checksum', None)
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
        print('UDP source port     : ' + str(self.src_port))
        print('UDP destination port: ' + str(self.dst_port))
        print('UDP length          : ' + str(self.length))
        if self.pseudo_header is not None:
            valid_str = '(incorrect)'
            if self.verify_checksum():
                valid_str = '(correct)'
            print('UDP checksum        : 0x' + format(self.checksum, '04x'),
                  valid_str)


    def get_dict(self):
        '''
        Returns UDP data as dictionary
        '''
        udp_data = {}
        udp_data['layer3_proto'] = self._layer3_proto
        udp_data['pseudo_header'] = self.pseudo_header
        udp_data['src_port'] = self.src_port
        udp_data['dst_port'] = self.dst_port
        udp_data['length'] = self.length
        udp_data['checksum'] = self.checksum
        udp_data['payload'] = self.payload
        return udp_data


    def get_bytes(self):
        '''
        Return UDP datagram as bytes
        '''
        return bytes(tools.to_bytes(self.src_port, 2) +
                     tools.to_bytes(self.dst_port, 2) +
                     tools.to_bytes(self.length, 2) +
                     tools.to_bytes(self.checksum, 2) +
                     self.payload)


    def __get_length(self):
        '''
        Getter length
        '''
        return self._length


    def __set_length(self, length):
        '''
        Setter length
        '''
        self._checksum = None
        self._length = length

    length = property(__get_length, __set_length)


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
        self.length = len(payload) + 8
        self._checksum = None

    payload = property(__get_payload, __set_payload)
