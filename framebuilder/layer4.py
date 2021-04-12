'''Module providing a Layer4 base class'''
from framebuilder import tools

class Base:
    '''
    Layer4 base class for shared logic
    '''
    def __init__(self, src_port, dst_port, proto, pseudo_header, payload, checksum):
        self._src_port = src_port
        self._dst_port = dst_port
        self._layer3_proto = proto
        self._pseudo_header = pseudo_header
        self._payload = payload
        self._checksum = checksum


    def get_bytes(self):
        '''
        Return packet as bytes, to be implemented by child class
        '''
        pass


    def create_pseudo_header(self, packet):
        '''
        Create the layer 4 pseudo header and update its length field
        :param packet: Layer 3 packet object
        '''
        self.pseudo_header = packet.create_pseudo_header()

        if packet.version == 4:
            # IPv4
            self._layer3_proto = 0x0800
            new_len_bytes = tools.to_bytes(len(self.get_bytes()), 2)
            self.pseudo_header = tools.set_bytes_at(self.pseudo_header,
                    new_len_bytes, 10)
        elif packet.version == 6:
            # IPv6
            self._layer3_proto = 0x86dd
            new_len_bytes = tools.to_bytes(len(self.get_bytes()), 4)
            self.pseudo_header = tools.set_bytes_at(self.pseudo_header,
                    new_len_bytes, 32)


    def update_checksum(self):
        '''
        Update Layer4 checksum
        '''
        if self.pseudo_header is not None:
            self._checksum = 0
            self._checksum = tools.calc_chksum(self.pseudo_header +
                    self.get_bytes() +
                    b'\x00' * (len(self.payload) % 2))


    def verify_checksum(self):
        '''
        Verify Layer4 checksum
        '''
        result = tools.calc_chksum(self.pseudo_header +
                self.get_bytes() +
                b'\x00' * (len(self.payload) % 2))
        return result == 0xffff


    def encapsulate(self, packet):
        '''
        Encapsulate TCP segment into packet
        :param packet: Layer 3 packet object
        '''
        self.create_pseudo_header(packet)
        packet.payload = self.get_bytes()


    def __get_src_port(self):
        '''
        Getter for src_port
        '''
        return self._src_port


    def __set_src_port(self, src_port):
        '''
        Setter for src_port
        '''
        self.checksum = None
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
        self.checksum = None
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
        self.checksum = None
        self._pseudo_header = pseudo_header

    pseudo_header = property(__get_pseudo_header, __set_pseudo_header)


    def __get_payload(self):
        '''
        Getter for payload
        '''
        return self._payload


    def __set_payload(self, payload):
        '''
        Setter for payload
        '''
        self.checksum = None
        self._payload = payload

    payload = property(__get_payload, __set_payload)


    def __get_checksum(self):
        '''
        Getter for checksum
        '''
        if self._checksum is None and self.pseudo_header is not None:
            self.update_checksum()
            self.info()
            print(self.get_dict())
        return self._checksum


    def __set_checksum(self, checksum):
        '''
        Setter for checksum
        '''
        self._checksum = checksum

    checksum = property(__get_checksum, __set_checksum)
