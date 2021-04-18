'''Module for custom exceptions'''

class NoTCPConnectionException(Exception):
    '''
    Exception is raised if send() or receive() are called in TCPHandler while
    the connection is in an invalid state
    '''
    def __init__(self, err_msg):
        self.err_msg = err_msg
        super().__init__(err_msg)

    def __str__(self):
        return 'TCP connection state invalid: {}'.format(self.err_msg)


class MSSExceededException(Exception):
    '''
    Exception is raised if maximum segment size is exceeded
    '''
    def __init__(self, err_msg):
        self.err_msg = err_msg
        super().__init__(err_msg)

    def __str__(self):
        return 'MSS exceeded: {}'.format(self.err_msg)


class InvalidPortException(Exception):
    '''
    Exception is raised if UDP/TCP port is invalid or not existing
    '''
    def __init__(self, err_msg):
        self.err_msg = err_msg
        super().__init__(err_msg)

    def __str__(self):
        return 'Invalid port number: {}'.format(self.err_msg)


class FailedMACQueryException(Exception):
    '''
    Exception is raised if no MAC address for a destination IP address can be
    obtained
    '''
    def __init__(self, err_msg):
        self.err_msg = err_msg
        super().__init__(err_msg)

    def __str__(self):
        return 'Could not find MAC address: {}'.format(self.err_msg)


class InvalidHeaderValueException(Exception):
    '''
    Exception raised if a header value is invalid, i.e. it is probably out of
    bound
    '''
    def __init__(self, err_msg):
        self.err_msg = err_msg
        super().__init__(err_msg)

    def __str__(self):
        return 'Invalid Header Value: {}'.format(self.err_msg)


class InvalidInterfaceException(Exception):
    '''
    Exception raised if an unknown interface is passed
    '''
    def __init__(self, err_msg):
        self.err_msg = err_msg
        super().__init__(err_msg)

    def __str__(self):
        return 'Invalid Interface: {}'.format(self.err_msg)


class MTUExceededException(Exception):
    '''
    Exception raised if the supposed payload of an ethernet frame is larger
    than the MTU
    '''
    def __init__(self, err_msg):
        self.err_msg = err_msg
        super().__init__(err_msg)

    def __str__(self):
        return 'Frame payload larger than MTU: {}'.format(self.err_msg)


class MaxTCPHeaderSizeExceeded(Exception):
    '''
    Exception raised in case TCP header size is exceeded (mostly due to too
    many TCP options)
    '''
    def __init__(self, err_msg):
        self.err_msg = err_msg
        super().__init__(err_msg)

    def __str__(self):
        return 'TCP header too big: {}'.format(self.err_msg)


class SocketCreationException(Exception):
    '''
    Exception raised in case socket creation fails
    '''
    def __init__(self, err_msg):
        self.err_msg = err_msg
        super().__init__(err_msg)

    def __str__(self):
        return 'Could not create socket: {}'.format(self.err_msg)


class SocketBindException(Exception):
    '''
    Exception raised in case socket binding fails
    '''
    def __init__(self, err_msg):
        self.err_msg = err_msg
        super().__init__(err_msg)

    def __str__(self):
        return 'Could not bind socket: {}'.format(self.err_msg)


class InvalidMACAddrException(Exception):
    '''
    Exception raised when invalid MAC address is passed
    '''
    def __init__(self, mac):
        self.mac = mac
        super().__init__(mac)

    def __str__(self):
        return 'Invalid MAC address: {}'.format(self.mac)


class InvalidIPv4AddrException(Exception):
    '''
    Exception raised when invalid IPv4 address is passed
    '''
    def __init__(self, ip_addr):
        self.ip_addr = ip_addr
        super().__init__(ip_addr)

    def __str__(self):
        return 'Invalid IPv4 address: {}'.format(self.ip_addr)


class IncompleteIPv4HeaderException(Exception):
    '''
    Exception raised when no or incomplete IPv4 header is passed
    '''
    def __str__(self):
        return 'IPv4 header missing or incomplete!'


class IncompleteFrameHeaderException(Exception):
    '''
    Exception raised when no or an incomplete frame header is passed
    '''
    def __str__(self):
        return 'Frame header missing or incomplete!'
