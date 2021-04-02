'''Module for layer 2 functions'''

import struct
import sys

from framebuilder.tools import to_bytes, ipv4_addr_encode, \
                               is_valid_mac_address, \
                               get_bytes_at, get_value_at, \
                               is_valid_ipv4_address, \
                               format_mac_addr, get_mac_addr, create_socket, \
                               get_mtu

from framebuilder.errors import InvalidMACAddrException, \
                                InvalidIPv4AddrException, \
                                IncompleteFrameHeaderException, \
                                MTUExceededException

from framebuilder.defs import get_protocol_str

class VlanTag:
    '''
    IEEE 802.1Q VLAN tag
    '''

    def __init__(self, vlan_tag):
        '''
        :param vlan_tag: Dictionary containing all VLAN tag information
        'vlan_tag: <dict> VLAN tag {
            'vlan_id': <int> VLAN identifier,
            'vlan_pcp': <int> priority code point,
            'vlan_dei': <int> drop eligible indicator
        }
        '''
        try:
            self._vlan_id = vlan_tag.get('vlan_id', 1) & 0xfff
            self._pcp = vlan_tag.get('vlan_pcp', 0) & 0b111
            self._dei = vlan_tag.get('vlan_dei', 0) & 0b1
            self._tpi = 0x8100
        except ValueError:
            # TODO Do not use sys.exit in library code, raise an exception
            print('Invalid field data in VLAN tag!')
            sys.exit(1)


    @classmethod
    def from_bytes(cls, vlt_bytes):
        '''
        create VlanTag object from bytes
        '''
        v_tag = {}
        v_tag['vlan_id'] = get_value_at(vlt_bytes, 2, 2) & 0xfff
        v_tag['vlan_pcp'] = get_value_at(vlt_bytes, 1, 2) >> 5
        v_tag['vlan_dei'] = (get_value_at(vlt_bytes, 1, 2) >> 4) & 0b1
        return cls(v_tag)


    def info(self):
        '''
        Print 802.1Q VLAN information
        '''
        print('VLAN ID             : ' + str(self._vlan_id))
        print('VLAN Priority       : ' + str(self._pcp))
        print('VLAN DEI            : ' + str(self._dei))


    def __get_vlan_id(self):
        '''
        return current VLAN ID
        '''
        return self._vlan_id


    def __set_vlan_id(self, vlan_id):
        '''
        set VLAN ID
        '''
        if 0 <= vlan_id <= 4095:
            self._vlan_id = vlan_id

    vlan_id = property(__get_vlan_id, __set_vlan_id)


    def __get_pcp(self):
        '''
        return priority code point
        '''
        return self._pcp


    def __set_pcp(self, pcp):
        '''
        set priority code point
        '''
        self._pcp = pcp & 0b111

    pcp = property(__get_pcp, __set_pcp)


    def __get_dei(self):
        '''
        return drop eligible indicator
        '''
        return self._dei


    def __set_dei(self, dei):
        '''
        set drop eligible indicator
        '''
        self._dei = dei & 0b1

    dei = property(__get_dei, __set_dei)


    def get_bytes(self):
        '''
        return VLAN tag as bytes
        '''
        tci = (((self.pcp << 1) + self.dei) << 12) + self.vlan_id
        return bytes(to_bytes(self._tpi, 2) + to_bytes(tci, 2))


    def get_dict(self):
        '''
        return VLAN tag data as dictionary
        '''
        dct = {'vlan_id': self._vlan_id,
               'vlan_pcp': self._pcp,
               'vlan_dei': self.dei}
        return dct


class Frame:
    '''
    IEEE 802.3 ethernet frame
    '''

    def __init__(self, frame_data=None, vlan_tag=None):
        '''
        :param frame_data: Dictionary containing frame data as follows
            {
                'src_addr': <string> source address,
                'dst_addr': <string> destination address,
                'ether_type': <int> EtherType,
                'vlan_tag: <dict> VLAN tag {
                    'vlan_id': <int> VLAN identifier,
                    'vlan_pcp': <int> priority code point,
                    'vlan_dei': <int> drop eligible indicator
                    },
                'payload': <bytes> payload
            }
        :param vlan_tag: optional VlanTag object (overrides frame_data)
        '''
        if frame_data is None:
            frame_data = {}
        src_addr = frame_data.get('src_addr', '00:00:00:00:00:00')
        dst_addr = frame_data.get('dst_addr', '00:00:00:00:00:00')

        if is_valid_mac_address(src_addr):
            self._src_addr = src_addr.replace(':', '')
        else:
            raise InvalidMACAddrException(src_addr)
        if is_valid_mac_address(dst_addr):
            self._dst_addr = dst_addr.replace(':', '')
        else:
            raise InvalidMACAddrException(src_addr)

        self._ether_type = frame_data.get('ether_type', 0) & 0xffff

        if self._ether_type is None:
            raise IncompleteFrameHeaderException(frame_data)

        if frame_data.get('vlan_tag', None) is not None:
            self._vlan_tag = VlanTag(frame_data.get('vlan_tag'))
        else:
            self._vlan_tag = None

        #If VlanTag object is passed, use this one regardless of what is passed
        #in frame_data.
        if vlan_tag is not None:
            self._vlan_tag = vlan_tag

        self._payload = frame_data.get('payload', b'')


    @classmethod
    def from_bytes(cls, frame_bytes):
        '''
        create Frame object from bytes
        '''
        frame_data = {}
        frame_data['src_addr'] = get_bytes_at(frame_bytes, 6, 6).hex()
        frame_data['dst_addr'] = get_bytes_at(frame_bytes, 6, 0).hex()
        frame_data['ether_type'] = get_value_at(frame_bytes, 2, 12)
        if frame_data['ether_type'] == 0x8100:
            vlan_tag = VlanTag.from_bytes(get_bytes_at(frame_bytes, 4, 12))
            frame_data['vlan_tag'] = vlan_tag.get_dict()
            frame_data['ether_type'] = get_value_at(frame_bytes, 2, 16)
            frame_data['payload'] = frame_bytes[18:]
        else:
            frame_data['vlan_tag'] = None
            frame_data['payload'] = frame_bytes[14:]
        return cls(frame_data)


    def get_bytes(self):
        '''
        returns frame data as bytes
        '''
        if self._vlan_tag is None:
            vlan_tag_bytes = b''
        else:
            vlan_tag_bytes = self._vlan_tag.get_bytes()
        return bytes(bytes.fromhex(self._dst_addr)
                     + bytes.fromhex(self._src_addr)
                     + vlan_tag_bytes
                     + to_bytes(self._ether_type, 2)
                     + self._payload)


    def __get_src_addr(self):
        '''
        return source MAC address as string
        '''
        return format_mac_addr(self._src_addr)


    def __set_src_addr(self, mac):
        '''
        set source MAC address

        :param mac: MAC address as string
        '''
        if is_valid_mac_address(mac):
            self._src_addr = mac.replace(':', '')
        else:
            raise InvalidMACAddrException(mac)

    src_addr = property(__get_src_addr, __set_src_addr)


    def __get_dst_addr(self):
        '''
        return destination MAC address as string
        '''
        return format_mac_addr(self._dst_addr)


    def __set_dst_addr(self, mac):
        '''
        set destination MAC address
        :param mac: MAC address as string
        '''
        if is_valid_mac_address(mac):
            self._dst_addr = mac.replace(':', '')
        else:
            raise InvalidMACAddrException(mac)

    dst_addr = property(__get_dst_addr, __set_dst_addr)


    def __get_ether_type(self):
        '''
        get ether type
        '''
        return self._ether_type


    def __set_ether_type(self, ether_type):
        '''
        set ether type
        '''
        self._ether_type = ether_type

    ether_type = property(__get_ether_type, __set_ether_type)


    def __get_vlan_tag(self):
        '''
        get VLAN tag instance
        '''
        return self._vlan_tag


    def __set_vlan_tag(self, vlan_tag):
        '''
        set VLAN tag
        '''
        self._vlan_tag = vlan_tag

    vlan_tag = property(__get_vlan_tag, __set_vlan_tag)


    def __get_payload(self):
        '''
        return payload
        '''
        return self._payload


    def __set_payload(self, payload):
        '''
        set payload
        :param payload: new payload
        '''
        self._payload = payload
        # TODO check whether commented out code can be removed
        ### Padding should be done by driver I guess
        #fr_len = len(self.get_bytes())
        #if fr_len < 64:
        #    pad_len = 64 - fr_len
        #    self._payload += b'\x00' * pad_len

    payload = property(__get_payload, __set_payload)


    def get_dict(self):
        '''
        return frame data as dictionary
        '''
        dct = {'src_addr': self._src_addr,
               'dst_addr': self._dst_addr,
               'ether_type': self._ether_type,
               'payload': self._payload}
        if self._vlan_tag is None:
            dct['vlan_tag'] = None
        else:
            dct['vlan_tag'] = self._vlan_tag.get_dict()
        return dct


    def info(self):
        '''
        Print Ethernet frame information
        '''
        print('ETH source address  : ' + self.src_addr)
        print('ETH dest. address   : ' + self.dst_addr)
        if self._vlan_tag is not None:
            self._vlan_tag.info()
        print('ETH ethertype       : 0x' + format(self._ether_type, '04x'), \
              get_protocol_str(self._ether_type))
        print('ETH payload length  : {}'.format(len(self.payload)))


    def send(self, socket, mtu=1500):
        '''
        Send ethernet frame via socket

        :param socket:
        :returns: Number of bytes sent
        '''
        if len(self._payload) > mtu:
            raise MTUExceededException('{} Bytes'.format(len(self.payload)))
        frame_data = struct.pack('!{}s'.format(len(self.get_bytes())),
                                 self.get_bytes())
        return socket.send(frame_data)


class ArpMessage(Frame):
    '''
    implements RFC 826 ARP messages

    +-----+-----------------------------+--------------------------------+
    |Octet|	             0 	            |                1               |
    +-----+-----------------------------+--------------------------------+
    |0 	  |                   Hardware type (HTYPE)                      |
    +-----+--------------------------------------------------------------+
    |2 	  |                   Protocol type (PTYPE)                      |
    +-----+-----------------------------+--------------------------------+
    |4 	  | Hardware addr length (HLEN) | Protocol address length (PLEN) |
    +-----+-----------------------------+--------------------------------+
    |6 	  |                      Operation (OPER)                        |
    +-----+--------------------------------------------------------------+
    |8 	  |        Sender hardware address (SHA) (first 2 bytes)         |
    +-----+--------------------------------------------------------------+
    |10   |                       (next 2 bytes)                         |
    +-----+--------------------------------------------------------------+
    |12   |                       (last 2 bytes)                         |
    +-----+--------------------------------------------------------------+
    |14   |       Sender protocol address (SPA) (first 2 bytes)          |
    +-----+--------------------------------------------------------------+
    |16   | 	                  (last 2 bytes)                         |
    +-----+--------------------------------------------------------------+
    |18   |       Target hardware address (THA) (first 2 bytes)          |
    +-----+--------------------------------------------------------------+
    |20   |                       (next 2 bytes)                         |
    +-----+--------------------------------------------------------------+
    |22   |  	                  (last 2 bytes)                         |
    +-----+--------------------------------------------------------------+
    |24   |       Target protocol address (TPA) (first 2 bytes)          |
    +-----+--------------------------------------------------------------+
    |26   |                       (last 2 bytes)                         |
    +-----+--------------------------------------------------------------+
    '''

    def __init__(self, arp_data, vlan_tag=None):
        '''
        :param arp_data: dict {
            'operation': <int> [1=request; 2=reply],
            'src_addr': <string> [source hw address],
            'dst_addr': <string> [destination hw address],
            'snd_hw_addr': <string> [sender's hw address],
            'snd_ip_addr': <string> [sender's IP address],
            'tgt_hw_addr': <string> [target's hw address],
            'tgt_ip_addr': <string> [target's IP address],
            }
        :param vlan_tag: VlanTag object
        '''
        self._operation = arp_data['operation']

        if is_valid_mac_address(arp_data['snd_hw_addr']):
            self._snd_hw_addr = arp_data['snd_hw_addr'].replace(':', '')
        else:
            raise InvalidMACAddrException(arp_data['snd_hw_addr'])
        if is_valid_mac_address(arp_data['tgt_hw_addr']):
            self._tgt_hw_addr = arp_data['tgt_hw_addr'].replace(':', '')
        else:
            raise InvalidMACAddrException(arp_data['tgt_hw_addr'])
        if is_valid_ipv4_address(arp_data['snd_ip_addr']):
            self._snd_ip_addr = arp_data['snd_ip_addr']
        else:
            raise InvalidIPv4AddrException(arp_data['snd_ip_addr'])
        if is_valid_ipv4_address(arp_data['tgt_ip_addr']):
            self._tgt_ip_addr = arp_data['tgt_ip_addr']
        else:
            raise InvalidIPv4AddrException(arp_data['tgt_ip_addr'])

        arp_msg = bytes(b'\x00\x01'
                        + b'\x08\x00'
                        + b'\x06\x04'
                        + to_bytes(self._operation, 2)
                        + bytes.fromhex(self.snd_hw_addr)
                        + bytes.fromhex(ipv4_addr_encode(self.snd_ip_addr))
                        + bytes.fromhex(self.tgt_hw_addr)
                        + bytes.fromhex(ipv4_addr_encode(self.tgt_ip_addr)))

        frame_data = {'dst_addr': arp_data['dst_addr'],
                      'src_addr': arp_data['src_addr'],
                      'ether_type': 0x0806,
                      'payload': arp_msg}

        super().__init__(frame_data, vlan_tag)


    @classmethod
    def from_frame(cls, arp_frame):
        '''
        create ArpMessage object from Frame object with corresponding payload
        :param arp_frame: Frame object containing an ARP message as payload
        '''
        arp_msg = arp_frame.payload
        vlan_tag = arp_frame.vlan_tag
        arp_data = {}
        arp_data['operation'] = get_value_at(arp_msg, 2, 6)
        arp_data['src_addr'] = arp_frame.src_addr
        arp_data['dst_addr'] = arp_frame.dst_addr
        arp_data['snd_hw_addr'] = get_bytes_at(arp_msg, 6, 8).hex()
        arp_data['snd_ip_addr'] = '.'.join(str(int(b)) for b in \
                                           get_bytes_at(arp_msg, 4, 14))
        arp_data['tgt_hw_addr'] = get_bytes_at(arp_msg, 6, 18).hex()
        arp_data['tgt_ip_addr'] = '.'.join(str(int(b)) for b in \
                                           get_bytes_at(arp_msg, 4, 24))
        return cls(arp_data, vlan_tag)


    def get_dict(self):
        '''
        return ARP data as dictionary
        '''
        return {'operation': self.operation,
                'src_addr': self.src_addr,
                'dst_addr': self.dst_addr,
                'snd_hw_addr': self.snd_hw_addr,
                'snd_ip_addr': self.snd_ip_addr,
                'tgt_hw_addr': self.tgt_hw_addr,
                'tgt_ip_addr': self.tgt_ip_addr}


    def __get_operation(self):
        '''
        Getter for operation
        :returns operation:
        '''
        return self._operation


    def __set_operation(self, operation):
        '''
        Setter for operation
        :param operation:
        '''
        self._operation = operation

    operation = property(__get_operation, __set_operation)


    def __get_snd_hw_addr(self):
        '''
        Getter for senders hardware address
        :returns snd_hw_addr:
        '''
        return format_mac_addr(self._snd_hw_addr)


    def __set_snd_hw_addr(self, snd_hw_addr):
        '''
        Setter for sender's hardware address
        :param snd_hw_addr:
        '''
        if is_valid_mac_address(snd_hw_addr):
            self._snd_hw_addr = snd_hw_addr.replace(':', '')
        else:
            raise InvalidMACAddrException(snd_hw_addr)

    snd_hw_addr = property(__get_snd_hw_addr, __set_snd_hw_addr)


    def __get_tgt_hw_addr(self):
        '''
        Getter for target hardware address
        :returns tgt_hw_addr:
        '''
        return format_mac_addr(self._tgt_hw_addr)


    def __set_tgt_hw_addr(self, tgt_hw_addr):
        '''
        Setter for target hardware address
        :param tgt_hw_addr:
        '''
        if is_valid_mac_address(tgt_hw_addr):
            self._tgt_hw_addr = tgt_hw_addr.replace(':', '')
        else:
            raise InvalidMACAddrException(tgt_hw_addr)

    tgt_hw_addr = property(__get_tgt_hw_addr, __set_tgt_hw_addr)


    def __get_snd_ip_addr(self):
        '''
        Getter for sender's IP address
        :returns snd_ip_addr:
        '''
        return self._snd_ip_addr


    def __set_snd_ip_addr(self, snd_ip_addr):
        '''
        Setter for sender's IP address
        :param snd_ip_addr:
        '''
        if is_valid_ipv4_address(snd_ip_addr):
            self._snd_ip_addr = snd_ip_addr
        else:
            raise InvalidIPv4AddrException(snd_ip_addr)

    snd_ip_addr = property(__get_snd_ip_addr, __set_snd_ip_addr)


    def __get_tgt_ip_addr(self):
        '''
        Getter for target IP address
        :returns tgt_ip_addr:
        '''
        return self._tgt_ip_addr


    def __set_tgt_ip_addr(self, tgt_ip_addr):
        '''
        Setter for targer IP address
        :param tgt_ip_addr:
        '''
        if is_valid_mac_address(tgt_ip_addr):
            self._tgt_ip_addr = tgt_ip_addr
        else:
            raise InvalidIPv4AddrException(tgt_ip_addr)

    tgt_ip_addr = property(__get_tgt_ip_addr, __set_tgt_ip_addr)


class EthernetHandler:
    '''
    Represents a relationship of two L2 endpoints, defined by an interface, a
    local Ethernet address and a remote Ethernet address. Its purpose is to
    act as a parent class for and handle packets from upper layers.
    The latest processed frame (ragardless of incoming or outgoing) can be
    accessed via the frame attribute
    '''

    def __init__(self, interface, remote_mac=None, ether_type=None,
                 local_mac=None, vlan_tag=None, mtu=None, block=1, t_out=3.0):
        '''
        Initialize Ethernet handler
        Data is send or received via an inherent frame object (frame)
        :param interface: <str> network interface
        :param remote_mac: <str> remote MAC address
        :param ethertype: <int> upper layer protocol number
        :param local_mac: <str> local MAC address (optional)
        :param vlan_tag: <dict> VLAN tag {
                                    'vlan_id': <int> VLAN identifier,
                                    'vlan_pcp': <int> priority code point,
                                    'vlan_dei': <int> drop eligible indicator
                                }
        :param mtu: <int> maximum transfer unit; None = auto-detect
        :param block: <int> make socket blocking (1), non-blocking (0) or
                            non-blocking with timeout (2)
        :param t_out: <float> set socket timeout in seconds
        '''
        if local_mac is None:
            local_mac = get_mac_addr(interface)

        if mtu is None:
            mtu = get_mtu(interface)

        self._interface = interface
        self._mtu = mtu
        if vlan_tag is not None:
            self._vlan_tag = VlanTag(vlan_tag)
        else:
            self._vlan_tag = None

        if is_valid_mac_address(local_mac):
            self._local_mac = local_mac
        else:
            raise InvalidMACAddrException

        if is_valid_mac_address(remote_mac) or remote_mac is None:
            self._remote_mac = remote_mac
        else:
            raise InvalidMACAddrException

        self._ether_type = ether_type
        self._socket = create_socket(interface, blocking=block,
                                     timeout_sec=t_out)
        self._frame_out = None
        self.init_frame_out()
        self._frame_in = None


    def init_frame_out(self):
        '''
        Initialize frame with class attributes and empty payload
        Use to reset the initial state of the object
        '''
        frame_data = {'src_addr': self.local_mac,
                      'dst_addr': self.remote_mac,
                      'ether_type': self._ether_type}
        self._frame_out = Frame(frame_data, self._vlan_tag)


    def __del__(self):
        '''
        Make sure to close socket when instance is deleted
        '''
        self._socket.close()


    def __get_interface(self):
        '''
        Getter for interface
        '''
        return self._interface

    def __set_interface(self, interface):
        '''
        Setter for interface
        '''
        self._interface = interface

    interface = property(__get_interface, __set_interface)


    def __get_local_mac(self):
        '''
        Getter for local_mac
        '''
        return self._local_mac

    def __set_local_mac(self, local_mac):
        '''
        Setter for local_mac
        '''
        if is_valid_mac_address(local_mac):
            self._local_mac = local_mac
        else:
            raise InvalidMACAddrException

    local_mac = property(__get_local_mac, __set_local_mac)


    def __get_remote_mac(self):
        '''
        Getter for remote_mac
        '''
        return self._remote_mac

    def __set_remote_mac(self, remote_mac):
        '''
        Setter for remote_mac
        '''
        if is_valid_mac_address(remote_mac):
            self._remote_mac = remote_mac
        else:
            raise InvalidMACAddrException

    remote_mac = property(__get_remote_mac, __set_remote_mac)


    def __get_mtu(self):
        '''
        Getter for mtu
        '''
        return self._mtu

    def __set_mtu(self, mtu):
        '''
        Setter for mtu
        '''
        self._mtu = mtu

    mtu = property(__get_mtu, __set_mtu)


    def __get_socket(self):
        '''
        Getter for socket
        '''
        return self._socket

    socket = property(__get_socket)


    def __get_frame_in(self):
        '''
        Getter for frame_in
        '''
        return self._frame_in

    frame_in = property(__get_frame_in)
    

    def __get_frame_out(self):
        '''
        Setter for frame_out
        Allows for overriding addresses, ethertype, vlan settings
        '''
        return self._frame_out

    frame_out = property(__get_frame_out)


    def send(self):
        '''
        Send data via an Ethernet frame
        '''
        if self._frame_out is not None:
            self._frame_out.send(self._socket, self._mtu)


    def receive(self, pass_on_error=True):
        '''
        Receive next frame that belongs to this connection, i.e. either set
        frame to None or frame object created from incoming bytes
        :param pass_on_error: <bool> ignore exceptions thrown by socket.recv
                                     (may be useful with non-blocking sockets)
        '''
        self._frame_in = None
        try:
            frame_bytes, address = self._socket.recvfrom(65536)
            frame = Frame.from_bytes(frame_bytes)

            if self.remote_mac is not None and \
               self.remote_mac != frame.src_addr:
                return None

            if self.local_mac is not None and \
               self.local_mac != frame.dst_addr:
                return None

            if self._ether_type is not None and \
               self._ether_type != frame.ether_type:
                return None

            if frame.vlan_tag is None and self._vlan_tag is None:
                self._frame_in = frame
                return address[2]
            if self._vlan_tag is not None and frame.vlan_tag is not None:
                if frame.vlan_tag.vlan_id == self._vlan_tag.vlan_id:
                    self._frame_in = frame
                    return address[2]
            return None
        except Exception as ex:
            if pass_on_error:
                pass
            raise ex
