'''Module containing helper functions and utilities used by framebuilder'''

import socket
import re
import struct
import time
import os
import json
import framebuilder.errors as err
from pyroute2 import NDB, IPRoute
from pr2modules.netlink.rtnl import ndmsg

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
    line_str = '+--' if mode == 'hex' else '+-'

    if len(pkgdata) < bytes_per_row:
        print('+--------' + line_str * len(pkgdata) + '+')
    else:
        print('+--------' + line_str * bytes_per_row + '+')

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
                print('|        ' + line_str * bytes_per_row + '+')
                print('| 0x%s |' % format((bytes_cnt // bytes_per_row) * \
                        bytes_per_row, '04x'), end = '')
            else:
                print('+--------' + line_str * bytes_per_row + '+')

    if bytes_cnt % bytes_per_row != 0:
        print('\n+--------', end = '')
        print(line_str * (bytes_cnt % bytes_per_row) + '+')


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
    if mac is None:
        return False
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
               interfer with other services!
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


def unhide_from_kernel(in_iface, remote_ip, remote_port, proto='tcp', delay=0):
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
    if proto not in ['tcp', 'udp', 'icmp']:
        proto = 'all'
    try:
        time.sleep(delay)
        if proto != 'icmp':
            cmd = 'iptables -D INPUT -i {} -p {} -s {} --sport {} -j DROP'
            cmd += ' 2>/dev/null'
            os.system(cmd.format(in_iface, proto, remote_ip, remote_port))
        else:
            cmd = 'iptables -D INPUT -i {} -p {} -s {} -j DROP'
            cmd += ' 2>/dev/null'
            os.system(cmd.format(in_iface, proto, remote_ip))
    except Exception as ex:
        print(ex)


def hide_from_krnl_in(in_iface, local_ip, local_port, proto='tcp'):
    '''
    Block all incoming packets for this connection on interface in order to
    prevent the kernel from interfering with this connection.

    Attention: Make sure to unhide the port again and be aware that this can
               interfer with other services!
    :param in_iface: <str> inbound interface
    :param local_ip: <str> local IP adress
    :param local_port: <int> local port
    :param proto: <str> protocol (tcp, udp, icmp or all)
    '''
    if proto not in ['tcp', 'udp', 'icmp']:
        proto = 'all'
    try:
        if proto != 'icmp':
            cmd = 'iptables -A INPUT -i {} -p {} -d {} --dport {} -j DROP'
            os.system(cmd.format(in_iface, proto, local_ip, local_port))
        else:
            cmd = 'iptables -A INPUT -i {} -p {} -d {} -j DROP'
            os.system(cmd.format(in_iface, proto, local_ip))
    except Exception as ex:
        print(ex)


def unhide_from_krnl_in(in_iface, local_ip, local_port, proto='tcp', delay=0):
    '''
    Removes the iptable rule that was created by hide_from_kernel. As there
    still might be incoming packets (e.g. ACKs), it is reasonable to wait some
    time before removing the rule.
    :param in_iface: <str> inbound interface
    :param local_ip: <str> local IP adress
    :param local_port: <int> local port
    :param proto: <str> protocol (tcp, udp, icmp or all)
    :param delay: <float> delay before removing the rule in seconds
    '''
    if proto not in ['tcp', 'udp', 'icmp']:
        proto = 'all'
    try:
        time.sleep(delay)
        if proto != 'icmp':
            cmd = 'iptables -D INPUT -i {} -p {} -d {} --dport {} -j DROP'
            cmd += ' 2>/dev/null'
            os.system(cmd.format(in_iface, proto, local_ip, local_port))
        else:
            cmd = 'iptables -D INPUT -i {} -p {} -d {} -j DROP'
            cmd += ' 2>/dev/null'
            os.system(cmd.format(in_iface, proto, local_ip))
    except Exception as ex:
        print(ex)


def get_route(dst_ip_addr):
    '''
    Return information on selected route for dst_ip_addr
    '''
    with IPRoute() as ip:
        try:
            return ip.route('get', dst=dst_ip_addr)[0]
        except Exception as e:
            return None


def get_route_if_name(dst_ip):
    '''
    Return outgoing interface name for destination address dst_ip
    '''
    route = get_route(dst_ip)
    if route is not None:
        with IPRoute() as ip:
            link = ip.link('get', index=route.get_attr('RTA_OIF'))[0]
            return link.get_attr('IFLA_IFNAME')
    raise err.DestinationUnreachableException(dst_ip) 


def get_route_gateway(dst_ip):
    '''
    Return gateway IP address for destination address dst_ip
    '''
    route = get_route(dst_ip)
    if route is not None:
        return route.get_attr('RTA_GATEWAY')
    raise err.DestinationUnreachableException(dst_ip) 


def get_ifattr(ifname, attr):
    '''
    Return MTU of an interface
    '''
    with NDB() as ndb:
        try:
            return ndb.interfaces[ifname].get(attr)
        except KeyError:
            return None


def get_mac_addr(ifname):
    '''
    Return hardware address of an interface
    '''
    return get_ifattr(ifname, 'address')


def get_mtu(ifname):
    '''
    Return MTU of an interface
    '''
    return get_ifattr(ifname, 'mtu')


def get_interface_by_address(ip_address):
    '''
    Look up local IP addresses and return interface name if given IP
    address is found
    '''
    with IPRoute() as ip:
        try:
            addr_info = ip.get_addr(address=ip_address)[0]
            if_index = addr_info['index']
            return ip.get_links(if_index)[0].get_attr('IFLA_IFNAME')
        except IndexError:
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
    ifaddr = ()
    with IPRoute() as ip:
        if family == 6:
            if_addr = ip.get_addr(family=10)
        elif family == 4:
            if_addr = ip.get_addr(family=2)
        else:
            if_addr = ip.get_addr()
        for if_data in if_addr:
            if_name = ip.link('get', index=if_data['index'])[0].get_attr('IFLA_IFNAME')
            if result.get(if_name, None) == None:
                result[if_name] = [if_data.get_attr('IFA_ADDRESS')]
            else:
                result[if_name].append(if_data.get_attr('IFA_ADDRESS'))
    return result


def get_if_ipv4_addr(ifname):
    '''
    Return the first IPv4 address of an interface

    :param ifname: interface name
    '''
    if_data = get_local_IP_addresses(family=4)
    result = if_data.get(ifname, None)
    if result is None:
        return None
    if len(result) == 0:
        return None
    return result[0]


def get_mac_for_dst_ip(ip_addr):
    '''
    Query neighbor cache for destination MAC address
    '''
    local_if = get_interface_by_address(ip_addr)
    if local_if is not None:
        return get_mac_addr(local_if)
    rt_info = get_route(ip_addr)
    if rt_info is None:
        raise err.FailedMACQueryException(ip_addr)
    gateway = rt_info.get_attr('RTA_GATEWAY')
    # check if there is a gateway and query neighbor cache for MAC address
    if gateway is not None:
        with IPRoute() as ip:
            for n_entry in ip.get_neighbours():
                if n_entry.get_attr('NDA_DST') == gateway:
                    return n_entry.get_attr('NDA_LLADDR')
    # if not query neighbor cache for destination IP address directly
    else:
        with IPRoute() as ip:
            for n_entry in ip.get_neighbours():
                if n_entry.get_attr('NDA_DST') == ip_addr:
                    return n_entry.get_attr('NDA_LLADDR')
    raise err.FailedMACQueryException(ip_addr)


def set_neigh(if_name, ip_addr, mac_addr='00:00:00:00:00:00', state='failed'):
    '''
    Set or add a neighbour cache entry

    :param if_name: interface name
    :param ip_addr: target IP address
    :param mac_addr: MAC address
    '''
    with IPRoute() as ip:
        idx = ip.link_lookup(ifname=if_name)[0]
        ip.neigh('set',
                 dst=ip_addr,
                 lladdr=mac_addr,
                 ifindex=idx,
                 state=ndmsg.states[state])


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


def get_rfc793_isn():
    '''
    Return a new 32 bit initial TCP segment number based on the insecure
    (but simple) RFC793 timer method
    '''
    return (int(time.time_ns() // 1e3) >> 2) & 0xffffffff


def tcp_sn_lt(val1, val2):
    '''
    Is TCP sequence number val1 lower than val2 according to RFC 1982?
    :param val1: first sequence number
    :param val2: second sequence number
    '''
    return (val1 < val2 and val2 - val1 < 2**31) or \
           (val1 > val2 and val1 - val2 > 2**31)


def tcp_sn_gt(val1, val2):
    '''
    Is TCP sequence number val1 greater than val2 according to RFC 1982?
    :param val1: first sequence number
    :param val2: second sequence number
    '''
    return (val1 < val2 and val2 - val1 > 2**31) or \
           (val1 > val2 and val1 - val2 < 2**31)


def get_local_tcp_port():
    '''
    Return an available TCP client port
    '''
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(('127.0.0.1', 0))
    except:
        pass
    local_port = sock.getsockname()[1]
    sock.close()
    return local_port


def mod32(value: int):
    '''
    Wrap around if value is greater that 2 ** 32 - 1
    '''
    return value % 2 ** 32
