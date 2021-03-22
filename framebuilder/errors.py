'''Module for custom exceptions'''

class MTUExceededException(Exception):
    '''
    Exception raised if the supposed payload of an ethernet frame is larger
    than the MTU
    '''
    def __init__(self, err_msg):
        self.err_msg = err_msg

    def __str__(self):
        return 'Frame payload larger than MTU: {}'.format(self.err_msg)


class MaxTCPHeaderSizeExceeded(Exception):
    '''
    Exception raised in case TCP header size is exceeded (mostly due to too
    many TCP options)
    '''
    def __init__(self, err_msg):
        self.err_msg = err_msg

    def __str__(self):
        return 'TCP header too big: {}'.format(self.err_msg)


class SocketCreationException(Exception):
    '''
    Exception raised in case socket creation fails
    '''
    def __init__(self, err_msg):
        self.err_msg = err_msg

    def __str__(self):
        return 'Could not create socket: {}'.format(self.err_msg)


class SocketBindException(Exception):
    '''
    Exception raised in case socket binding fails
    '''
    def __init__(self, err_msg):
        self.err_msg = err_msg

    def __str__(self):
        return 'Could not bind socket: {}'.format(self.err_msg)


class InvalidMACAddrException(Exception):
    '''
    Exception raised when invalid MAC address is passed
    '''
    def __init__(self, mac):
        self.mac = mac

    def __str__(self):
        return 'Invalid MAC address: {}'.format(self.mac)


class InvalidIPv4AddrException(Exception):
    '''
    Exception raised when invalid IPv4 address is passed
    '''
    def __init__(self, ip):
        self.ip = ip

    def __str__(self):
        return 'Invalid IPv4 address: {}'.format(self.ip)


class IncompleteIPv4HeaderException(Exception):
    '''
    Exception raised when no or incomplete IPv4 header is passed
    '''
    def __init__(self, data):
        self.data = data

    def __str__(self):
        return 'IPv4 header missing or incomplete!'


class IncompleteFrameHeaderException(Exception):
    '''
    Exception raised when no or an incomplete frame header is passed
    '''
    def __init__(self, data):
        self.data = data

    def __str__(self):
        return 'Frame header missing or incomplete!'
