'''Module containing helper functions and utilities used by custompk'''

import socket
import signal
import re
import struct
import time
import os
import json
import framebuilder.errors as err

def to_bytes(value, num_bytes):
    '''
    Convert numeric values into n bytes with leading zeros

    :param value: Numeric Value
    :param num_bytes: Number of bytes
    '''
    return bytes.fromhex(format(value, '0%dx' % (2 * num_bytes)))


def get_value_at(b_obj, length=1, offset=0):
    '''
    Return a numeric value represented by length bytes at offset position in
    bytes object or bytearray

    :param b_obj: Byte object
    :param length: Number of bytes to read (Default value = 1)
    :param offset: Start posistion (Default value = 0)
    '''
    result = 0
    value_list = list(b_obj[offset:offset+length])
    for i in range(length):
        result = (result << 8) + value_list[i]
    return result


def set_bytes_at(b_obj, b_data, offset=0):
    '''
    Overwrites bytes object or bytearray b_data with bytes object or bytearray
    b_obj at offset (starting from 0) and returns b_obj as bytes

    :param b_obj: Target object
    :param b_data: Data
    :param offset: Position (Default value = 0)
    '''
    b_obj = bytearray(b_obj)
    struct.pack_into('!%ds' % len(b_data), b_obj, offset, b_data)
    b_obj = bytes(b_obj)
    return b_obj


def get_bytes_at(b_obj, length=1, offset=0):
    '''
    Return length bytes read from bytes object or bytearray

    :param b_obj: Bytes object
    :param length: Number of bytes to read (Default value = 1)
    :param offset: Start position (Default value = 0)
    '''
    return b_obj[offset:offset+length]


def print_pkg_data_ascii(pkgdata, bytes_per_row=32):
    '''
    Print binary data as table of printable characters
    '''
    _print_pkg_data(pkgdata, 'ascii', bytes_per_row=bytes_per_row)


def print_pkg_data_hex(pkgdata, bytes_per_row=32):
    '''
    Print binary data as table of hex values
    '''
    _print_pkg_data(pkgdata, 'hex', bytes_per_row=bytes_per_row)


def _print_pkg_data(pkgdata, mode, bytes_per_row):
    '''
    Print binary data as table
    '''
    bytes_cnt = 0
    data = struct.unpack('!%dc' % len(pkgdata), pkgdata)

    if len(pkgdata) < bytes_per_row:
        print('+--------' + '+--' * len(pkgdata) + '+')
    else:
        print('+--------' + '+--' * bytes_per_row + '+')

    for byte in data:
        chars = ' '
        if mode == 'hex':
            chars = byte.hex()
        elif mode == 'ascii':
            if byte.decode('latin_1').isprintable():
                chars = byte.decode('latin_1')
        if bytes_cnt == 0:
            print('| 0x0000 |', end = '')
        bytes_cnt += 1
        if bytes_cnt % bytes_per_row != 0:
            print(chars, end = '|')
        else:
            print(chars, end = '|\n')
            if bytes_cnt != len(data):
                print('|        ' + '+--' * bytes_per_row + '+')
                print('| 0x%s |' % format((bytes_cnt // bytes_per_row) * \
                        bytes_per_row, '04x'), end = '')
            else:
                print('+--------' + '+--' * bytes_per_row + '+')

    if bytes_cnt % bytes_per_row != 0:
        print('\n+--------', end = '')
        print('+--' * (bytes_cnt % bytes_per_row) + '+')


def create_socket(interface, proto_id=3, blocking=1, timeout_sec=3.0):
    '''
    Create and return a packet socket

    For reasonable values of proto_id see linux/if_ether.h, e.g.

    #define ETH_P_802_3     0x0001          /* Dummy type for 802.3 frames  */
    #define ETH_P_AX25      0x0002          /* Dummy protocol id for AX.25  */
    #define ETH_P_ALL       0x0003          /* Every packet (be careful!!!) */
    #define ETH_P_802_2     0x0004          /* 802.2 frames                 */
    #define ETH_P_SNAP      0x0005          /* Internal only                */

    :param interface: <string> Network interface to bind to
    :param proto_id: <int> Protocol id (Default value = 3)
    :param blocking: <int> Determines if the socket is blocking
                     0 = non-blocking
                     1 = blocking (default)
                     2 = timeout
                     other values lead to system default behavior
    :param timeout_sec: <float> Default timeout for blocking == 2
    '''
    try:
        packet_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        if blocking == 1:
            packet_socket.settimeout(None)
        if blocking == 0:
            packet_socket.settimeout(0.0)
        if blocking == 2:
            packet_socket.settimeout(timeout_sec)
    except OSError as create_ex:
        raise err.SocketCreationException(create_ex.args[1])
    try:
        packet_socket.bind((interface, proto_id))
    except OSError as bind_ex:
        packet_socket.close()
        raise err.SocketBindException(bind_ex.args[1])
    return packet_socket


def calc_chksum(data):
    '''
    Checksum algorithm used by IPv4, ICMP, UDP, TCP

    The checksum is the 16-bit ones's complement of the one's complement sum of
    the message. For computing the checksum , the checksum field should be zero.

    Example with 4 bytes of data

     -- Sender --                  -- Receiver --
     data:                         data:
           0011 0110 1101 0010 --->      0011 0110 1101 0010
           1010 0101 1111 0101 --->      1010 0101 1111 0101
     checksum:                     checksum:
           1100 1001 0010 1101  +->      0010 0011 0011 1000
         + 0101 1010 0000 1010  |  sum of 1s complements has to be 0xffff:
     = 1 + 0010 0011 0011 0111  |        1100 1001 0010 1101
     =     0010 0011 0011 1000 -+      + 0101 1010 0000 1010
           ===================         + 1101 1100 1100 0111
                                   = 1 + 1111 1111 1111 1110
                                   =     1111 1111 1111 1111 -> correct
                                         ===================

    :param data:
    :returns: Numeric value of the calculated checksum
    '''
    # Split data into 16 bit words
    count = len(data) // 2
    words = struct.unpack('!%dH' % count, data)

    # initialize check sum
    chksum = 0x0000

    for i in range(count):
        carry = 0
        chksum += 0xffff - words[i]
        if chksum > 0xffff:
            carry = chksum >> 16
            chksum &= 0xffff
            chksum += carry

    return chksum


def is_valid_mac_address(mac):
    '''
    Check if string mac contains a valid MAC address, either with or without
    colons
    :param mac: String containing a MAC address
    '''
    is_valid = bool(re.fullmatch('([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', mac))
    if not is_valid:
        is_valid = bool(re.fullmatch('([0-9A-Fa-f]{2}){6}', mac))
    return is_valid


def format_mac_addr(mac):
    '''
    Check if mac has colons and make sure that bytes are divided by colons
    '''
    mac = mac.replace(':', '')
    return ':'.join(mac[0+x*2:2+x*2] for x in range(6))


def is_valid_ipv4_address(ip_addr):
    '''
    Check if string ip is a valid IP v 4 address
    :param ip: IP address in dotted decimal notation
    '''
    if not isinstance(ip_addr, str):
        return False
    def isIPv4(seg):
        return str(int(seg)) == seg and 0 <= int(seg) <= 255
    if not (ip_addr.count(".") == 3 and all(isIPv4(part) for part in ip_addr.split("."))):
        return False
    try:
        socket.inet_aton(ip_addr)
        return True
    except:
        return False


def ipv4_addr_encode(ip_addr):
    '''
    Return IPv4 address as a hex string

    :param ip: IPv4 address string in dotted decimal notation
    '''
    return format(struct.unpack('!I', socket.inet_aton(ip_addr))[0], '08x')


def hide_from_kernel(in_iface, remote_ip, remote_port, proto='tcp'):
    '''
    Block all incoming packets for this connection on interface in order to
    prevent the kernel from interfering with this connection.

    Attention: Make sure to unhide the port again and be aware that this can
               interfere with other services!
    :param in_iface: <str> inbound interface
    :param remote_ip: <str> IP adress of the remote host
    :param remote_port: <int> remote port
    :param proto: <str> protocol (tcp, udp, icmp or all)
    '''
    if proto not in ['tcp', 'udp', 'icmp']:
        proto = 'all'
    try:
        if proto != 'icmp':
            cmd = 'iptables -A INPUT -i {} -p {} -s {} --sport {} -j DROP'
            os.system(cmd.format(in_iface, proto, remote_ip, remote_port))
        else:
            cmd = 'iptables -A INPUT -i {} -p {} -s {} -j DROP'
            os.system(cmd.format(in_iface, proto, remote_ip))
    except Exception as ex:
        print(ex)


def unhide_from_kernel(in_iface, remote_ip, remote_port, proto='tcp', delay=1):
    '''
    Removes the iptable rule that was created by hide_from_kernel. As there
    still might be incoming packets (e.g. ACKs), it is reasonable to wait some
    time before removing the rule.
    :param in_iface: <str> inbound interface
    :param remote_ip: <str> IP adress of the remote host
    :param remote_port: <int> remote port
    :param proto: <str> protocol (tcp, udp, icmp or all)
    :param delay: <float> delay before removing the rule in seconds
    '''
    # ignore Ctrl-C during delay
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if proto not in ['tcp', 'udp', 'icmp']:
        proto = 'all'
    try:
        time.sleep(delay)
        if proto != 'icmp':
            cmd = 'iptables -D INPUT -i {} -p {} -s {} --sport {} -j DROP'
            os.system(cmd.format(in_iface, proto, remote_ip, remote_port))
        else:
            cmd = 'iptables -D INPUT -i {} -p {} -s {} -j DROP'
            os.system(cmd.format(in_iface, proto, remote_ip))
    except Exception as ex:
        print(ex)


def get_ip_dict_list(ip_cmd):
    '''
    Returns the output of an iproute2 command as list of dictionaries
    '''
    if not '--json' in ip_cmd.split():
        ip_cmd = ip_cmd.replace('ip', 'ip --json')

    try:
        return json.loads(os.popen(ip_cmd).read())
    except:
        return None


def get_route(dst_ip_addr):
    '''
    Return selected route for dst_ip_addr
    '''
    rt_info = get_ip_dict_list('ip route get {}'.format(dst_ip_addr))
    if rt_info is None:
        return None
    return rt_info[0]


def get_neigh_cache():
    '''
    Return ARP/NDP cache
    '''
    return get_ip_dict_list('ip neigh show')


def get_mac_addr(ifname):
    '''
    Return hardware address of an interface
    '''
    dev_info = get_ip_dict_list('ip link show dev {}'.format(ifname))
    if dev_info is None:
        return None
    return dev_info[0].get('address', None)


def get_interface_by_address(ip_address):
    '''
    Return look up local IP addresses and return interface name if given IP
    address is found
    '''
    if_addr = get_ip_dict_list('ip addr show')
    for if_data in if_addr:
        addr_info = if_data.get('addr_info', None)
        if addr_info is None:
            break
        for addr in addr_info:
            if addr['local'] == ip_address:
                return if_data['ifname']
    return None


def get_local_IP_addresses(family=None):
    '''
    Return all local IP addresses as dictionary
    {
        'if_1': [addr1, addr2, ..., addr n],
        'if_2': [addr1, addr2, ..., addr n],
        ...
        'if_n': [addr1, addr2, ..., addr n],
    }
    :param family: address family (optional, 4=IPv4, 6=IPv6)
    '''
    result = {}
    if family in [4,6]:
        if_addr = get_ip_dict_list('ip -{} addr show'.format(family))
    else:
        if_addr = get_ip_dict_list('ip addr show')
    for if_data in if_addr:
        result[if_data['ifname']] = []
        addr_info = if_data.get('addr_info', None)
        if addr_info is None:
            break
        for addr in addr_info:
            result[if_data['ifname']].append(addr['local'])
    return result


def get_mac_for_dst_ip(ip_addr):
    '''
    Query neighbor cache for destination MAC address
    '''
    local_if = get_interface_by_address(ip_addr)
    if local_if is not None:
        return get_mac_addr(local_if)
    rt_info = get_route(ip_addr)
    n_cache = get_neigh_cache()
    # check if there is a gateway and query neighbor cache for MAC address
    if rt_info.get('gateway', None) is not None:
        for n_entry in n_cache:
            if n_entry['dst'] == rt_info['gateway']:
                return n_entry['lladdr']
    # if not query neighbor cache for destination IP address directly
    else:
        for n_entry in n_cache:
            if n_entry['dst'] == ip_addr:
                return n_entry['lladdr']
    raise err.FailedMACQueryException(ip_addr)

def get_mtu(ifname):
    '''
    Return MTU of an interface
    '''
    dev_info = get_ip_dict_list('ip link show dev {}'.format(ifname))
    if dev_info is None:
        return None
    return int(dev_info[0].get('mtu', '0'))


def print_rgb(string, rgb=(255, 255, 255), bold=False, end=None):
    '''
    Print a string in given color
    :param string: <str> string to print out
    :param rgb: (<int>, <int>, <int>) tuple of rgb values
    :param bold: <bool> bold font (default is False)
    :param end: <str> end line with this string instead of line break
    '''
    if bold:
        f_str = '\033[1;38;2;{};{};{}m{}\033[0m'
    else:
        f_str = '\033[38;2;{};{};{}m{}\033[0m'

    if end is None:
        print(f_str.format(rgb[0], rgb[1], rgb[2], string))
    else:
        print(f_str.format(rgb[0], rgb[1], rgb[2], string), end=end)
