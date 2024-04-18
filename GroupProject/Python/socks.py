from base64 import b64encode                     #Used to encode bytes-like objects into Base64-encoded ASCII strings
try:
    from collections.abc import Callable         #Represents a protocol for classes that can be called
except ImportError:
    from collections import Callable
from errno import EOPNOTSUPP, EINVAL, EAGAIN     #These are standard error numbers related to various system call failures, such as invalid argument, operation not supported, etc.
import functools                                 #Provides functions for higher-order programming, particularly operations that operate on or return other functions
from io import BytesIO                           #Provides a convenient way to work with in-memory binary data using file-like objects
import logging                                   #Provides a flexible logging system for python applications
import os                                        #Provides a portable way of using operating system-dependent functionality
from os import SEEK_CUR                          
import socket                                    #Provides access to the BSD socket interface, used for network communication
import struct                                    #Performs conversions between python values + C structs represented as python bytes objects
import sys                                       #Provides access to some variables used or maintained by the pyhton interpreter + to functions that interact with the interpreter

__version__ = "1.7.1"

######## Checks the os + pyhton version to ensure compatibility ########

if os.name == "nt" and sys.version_info < (3, 0):   #Checks if the os is Windows + if the python version is less then 3.0(Specific to handling compatability issues with older versions)
    try:
        import win_inet_pton                        #Converts an IPv4 or IPv6 address from its human readable form to a packed, binary format
    except ImportError:                             
        raise ImportError(
            "To run PySocks on Windows you must install win_inet_pton")

######## Defines constants related to proxy types + creates dictionaries for mapping ########

log = logging.getLogger(__name__)   #Retrieves a logger object from the python logging module, which can be used to output log messages to various destinations

PROXY_TYPE_SOCKS4 = SOCKS4 = 1      #Defines constants for the SOCKS4 proxy type, assigning both 'PROXY_TYPE_SOCKS4' + 'SOCKS4' to the value of '1'
PROXY_TYPE_SOCKS5 = SOCKS5 = 2
PROXY_TYPE_HTTP = HTTP = 3          #Defines constants for the HTTP proxy type 

PROXY_TYPES = {"SOCKS4": SOCKS4, "SOCKS5": SOCKS5, "HTTP": HTTP}             #This dictionary maps proxy type names to their corresponding numeric values
PRINTABLE_PROXY_TYPES = dict(zip(PROXY_TYPES.values(), PROXY_TYPES.keys()))  #This dictionary reverses the mapping, creating a dictionary where the keys are the numeric values +
                                                                              #the values are the proxy type names, useful for printing proxy type info in readable format
_orgsocket = _orig_socket = socket.socket   #This line backs up the original 'socket.socket' function by assigning it to both '_orgsocket' + '_orig_socket'. 
                                             #Can be useful if the socket module needs to be modified or replaced temporarily while still having the ability to access the original functionality

######## Ensures certain socket operations are performed in blocking mode ########

def set_self_blocking(function):               #Defines the decorator function which takes another function 'function' as its argument. Decorators modify other functions or methods

    @functools.wraps(function)                 #
    def wrapper(*args, **kwargs):              #A wrapper function that will replace the original function when the decorator is applied.
        self = args[0]                         #Extracts the instance('self') from the arguments 'args'. Assumes that the decorated function is a method of a class where the 
        try:                                    #first argument is always 'self'
            _is_blocking = self.gettimeout()   #Retrieves the current timeout value for the socket
            if _is_blocking == 0:              #If 'is_blocking' is '0'(non-blocking mode), it sets the socket to blocking mode
                self.setblocking(True)
            return function(*args, **kwargs)   #Calls the original function 
        except Exception as e:
            raise
        finally:
            if _is_blocking == 0:              #Sets the socket back to non-blocking mode
                self.setblocking(False)        #Ensures the socket's blocking state is restored even if an exception occurs during the execution of the original function
    return wrapper                             #Returns the wrapper function, which will replace the original function when the decorator is applied

######## Customizing error messages related to proxy operations ########

class ProxyError(IOError):                           #Inheriting from 'IOError', this class is meant to handle input/output errors
    def __init__(self, msg, socket_err=None):        #Serves as the constructor for this class. Initializes instances of this class with an error message
        self.msg = msg                               #Stores the error message passed to the constructor in the 'msg' attribute
        self.socket_err = socket_err                 #Stores the original socket error(if provided) in the 'socket_err' attribute

        if socket_err:                               #Checks if a 'socket_err' was provided. If yes, it adds the socket error message to the original error message
            self.msg += ": {}".format(socket_err)

    def __str__(self):                               #This method provides a string representation of the 'ProxyError' instance when it's converted to a string
        return self.msg                              #Returns the error message stored in the 'msg' attribute of the 'ProxyError' instance

class GeneralProxyError(ProxyError):      #Represents a general proxy error
    pass

class ProxyConnectionError(ProxyError):   #Represents an error related to establishing a proxy connection
    pass

class SOCKS5AuthError(ProxyError):        #Represents an error related to SOCKS5 authentication failure 
    pass

class SOCKS5Error(ProxyError):            #Represents a general SOCKS5 protocol error
    pass

class SOCKS4Error(ProxyError):            #Represents a general SOCKS4 protocol error
    pass

class HTTPError(ProxyError):              #Represents an error related to HTTP proxy connections
    pass

SOCKS4_ERRORS = {     #Initializes the 'SOCKS4_ERRORS' dictionary
    0x5B: "Request rejected or failed",     #Maps the error code '0x5B' to the error message 'Request ....'
    0x5C: ("Request rejected because SOCKS server cannot connect to identd on"
           " the client"),   
    0x5D: ("Request rejected because the client program and identd report"     #These error messages provide info about the reasons for SOCKS4 request rejections or failures
           " different user-ids")
}

SOCKS5_ERRORS = {
    0x01: "General SOCKS server failure",          #Same thing as above except for SOCKS5
    0x02: "Connection not allowed by ruleset",
    0x03: "Network unreachable",
    0x04: "Host unreachable",
    0x05: "Connection refused",
    0x06: "TTL expired",
    0x07: "Command not supported, or protocol error",
    0x08: "Address type not supported"
}

DEFAULT_PORTS = {SOCKS4: 1080, SOCKS5: 1080, HTTP: 8080}   #This dictionary provides default port number for different proxy types

######## Specify proxy type ########

def set_default_proxy(proxy_type=None, addr=None, port=None, rdns=True,     #Sets a default proxy config for all 'socksocket' objects created
                      username=None, password=None):                        #'rdns': A boolean indicating whether to perform reverse DNS lookups. 
                    #Stuff above is a tuple                                 #'username + password': The username + password for proxy authentication
    socksocket.default_proxy = (proxy_type, addr, port, rdns,               
                                username.encode() if username else None,    #If username is provided, it's encoded to bytes before being stored in the tuple
                                password.encode() if password else None)    #Same thing

def setdefaultproxy(*args, **kwargs):                    
    if "proxytype" in kwargs:                            #Checks if the keyword argument 'proxytype' is present in the 'kwargs' dictionary
        kwargs["proxy_type"] = kwargs.pop("proxytype")   #If 'proxytype' is found, it renames it to 'proxy_type'
    return set_default_proxy(*args, **kwargs)

def get_default_proxy():       #Returns the default proxy, set by set_default_proxy
    return socksocket.default_proxy

getdefaultproxy = get_default_proxy

def wrap_module(module):                    #Attempts to replace a module's socket library with a SOCKS socket
    if socksocket.default_proxy:            #Checks if a default proxy has been set
        module.socket.socket = socksocket   #If yes, it replaces the 'socket' attribute of the provided 'module' with the 'socksocket' class(Replacing the standard socket library with SOCKS socket functionality)
    else:                                   #If not, it raises a 'GeneralProxyError' indicating that no default proxy has been specified
        raise GeneralProxyError("No default proxy specified")

wrapmodule = wrap_module

######## Establish connections through a proxy ########

def create_connection(dest_pair,                           #'dest_pair': A tuple representing the destination address to connect to
                      timeout=None, source_address=None,   #'timeout': Socket timeout value in seconds. 'source_address': Specifies the source address for the socket to bind to before connecting(only for compatability)
                      proxy_type=None, proxy_addr=None,    #'proxy_addr': The address of the proxy server
                      proxy_port=None, proxy_rdns=True,    #'proxy_rdns': A boolean indicating whether to perform reverse DNS lookups for the proxy server
                      proxy_username=None, proxy_password=None, #Username + Password for proxy authentication
                      socket_options=None):                #Additional socket options

    remote_host, remote_port = dest_pair           #Extract destinations
    if remote_host.startswith("["):                #Remove IPv6 brackets
        remote_host = remote_host.strip("[]")      #Error initialization
    if proxy_addr and proxy_addr.startswith("["):
        proxy_addr = proxy_addr.strip("[]")

    err = None

#Function: It prepares the destination + proxy addresses, removing IPV6 brackets if present. It attempts to establish a connection to the destination address via the 
 #proxy server. If successful, it returns the socket object representing the connection. If not, it gives an error

    for r in socket.getaddrinfo(proxy_addr, proxy_port, 0, socket.SOCK_STREAM):   #Looping through address info
        family, socket_type, proto, canonname, sa = r                   
        sock = None
        try: 
            sock = socksocket(family, socket_type, proto)                         #Creating socket

            if socket_options:                                                    #Socket configuration
                for opt in socket_options:
                    sock.setsockopt(*opt)

            if isinstance(timeout, (int, float)):
                sock.settimeout(timeout)

            if proxy_type:
                sock.set_proxy(proxy_type, proxy_addr, proxy_port, proxy_rdns,
                               proxy_username, proxy_password)
            if source_address:
                sock.bind(source_address)

            sock.connect((remote_host, remote_port))                              #Connection Attempt
            return sock

        except (socket.error, ProxyError) as e:                                   #Exception handling
            err = e
            if sock:
                sock.close()
                sock = None

    if err:                                                                       #Error handling
        raise err

    raise socket.error("gai returned empty list.")


class _BaseSocket(socket.socket):                 #Inheriting from 'socket.socket', indicating that instances of '_BaseSocket' will have the same behaviour as regular
    def __init__(self, *pos, **kw):                #socket objects unless overridden
        _orig_socket.__init__(self, *pos, **kw)   

        self._savedmethods = dict()               #'_savedmethods': Empty dictionary that will store the original methods of the socket that are being overridden
        for name in self._savenames:
            self._savedmethods[name] = getattr(self, name)  #For each name, it retrieves the method from the instance
            delattr(self, name)                              #This allows for normal method overriding since overriden methods will no longer exist on the instance

    _savenames = list()   #'_savenames': Empty list, if specific methods need to be saved for later use


def _makemethod(name):
    return lambda self, *pos, **kw: self._savedmethods[name](*pos, **kw)  #Overrides specific socket methods to delegate their behaviour while preserving access to 
for name in ("sendto", "send", "recvfrom", "recv"):                        #the original methods
    method = getattr(_BaseSocket, name, None)

    if not isinstance(method, Callable):              #Ensures non-callable methods are replaced with lambda functions(functions that don't have a name)
        _BaseSocket._savenames.append(name)
        setattr(_BaseSocket, name, _makemethod(name))


class socksocket(_BaseSocket):
    default_proxy = None

    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM,  #Initializes a 'socksocket' object with specified parameters, checking if the socket type is 
                 proto=0, *args, **kwargs):                              #either stream or datagram. If not, it raises a 'ValueError'
        if type not in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            msg = "Socket type must be stream or datagram, not {!r}"
            raise ValueError(msg.format(type))

        super(socksocket, self).__init__(family, type, proto, *args, **kwargs)  #Calls the superclass initializer
        self._proxyconn = None  

        if self.default_proxy:    #Sets proxy attributes
            self.proxy = self.default_proxy
        else:
            self.proxy = (None, None, None, None, None, None)
        self.proxy_sockname = None
        self.proxy_peername = None

        self._timeout = None     #Initializes timeout

    def _readall(self, file, count):
        data = b""
        while len(data) < count:
            d = file.read(count - len(data))  #Reads exactly the specified number of bytes from a file object
            if not d:
                raise GeneralProxyError("Connection closed unexpectedly")
            data += d
        return data

    def settimeout(self, timeout):   #Sets a timeout for the socket connection + applies it if the socket is connected
        self._timeout = timeout
        try:
            peer = self.get_proxy_peername()
            super(socksocket, self).settimeout(self._timeout)
        except socket.error:
            pass

    def gettimeout(self):     #Returns the current timeout value
        return self._timeout

    def setblocking(self, v):   #Sets the socket to blocking or non-blocking mode accordingly
        if v:
            self.settimeout(None)
        else:
            self.settimeout(0.0)

    def set_proxy(self, proxy_type=None, addr=None, port=None, rdns=True,   #Sets the proxy config for the socket connecion with specified parameters like proxy type,
                  username=None, password=None):                             #address, port, etc.
        """ Sets the proxy to be used.

        proxy_type -  The type of the proxy to be used. Three types
                        are supported: PROXY_TYPE_SOCKS4 (including socks4a),
                        PROXY_TYPE_SOCKS5 and PROXY_TYPE_HTTP
        addr -        The address of the server (IP or DNS).
        port -        The port of the server. Defaults to 1080 for SOCKS
                        servers and 8080 for HTTP proxy servers.
        rdns -        Should DNS queries be performed on the remote side
                       (rather than the local side). The default is True.
                       Note: This has no effect with SOCKS4 servers.
        username -    Username to authenticate with to the server.
                       The default is no authentication.
        password -    Password to authenticate with to the server.
                       Only relevant when username is also provided."""
        self.proxy = (proxy_type, addr, port, rdns,
                      username.encode() if username else None,
                      password.encode() if password else None)

    def setproxy(self, *args, **kwargs):    #Updates the proxy config using the same parameters as 'set_proxy()'. It also allows using 'proxytype' instead of 'proxy_type'
        if "proxytype" in kwargs:
            kwargs["proxy_type"] = kwargs.pop("proxytype")
        return self.set_proxy(*args, **kwargs)

    def bind(self, *pos, **kw):    #Implements proxy connection for UDP sockets during the 'bind()' phase
        (proxy_type, proxy_addr, proxy_port, rdns, username,
         password) = self.proxy
        if not proxy_type or self.type != socket.SOCK_DGRAM:   #If no proxy is set or the socket type is not SOCK_DGRAM, it returns the original socket's bind method
            return _orig_socket.bind(self, *pos, **kw)

        if self._proxyconn:    #Raises an error if the socket is already bound
            raise socket.error(EINVAL, "Socket already bound to an address")
        if proxy_type != SOCKS5:    #If the proxy type is not SOCKS5, it raises a specific error
            msg = "UDP only supported by SOCKS5 proxy type"
            raise socket.error(EOPNOTSUPP, msg)
        super(socksocket, self).bind(*pos, **kw)   #Otherwise, it binds the socket + specifies the actual local port to avoid issues with some relays
        _, port = self.getsockname()
        dst = ("0", port)

        self._proxyconn = _orig_socket()  #Creates a proxy connection using the original socket
        proxy = self._proxy_addr()
        self._proxyconn.connect(proxy)  #Connects to the proxy address

        UDP_ASSOCIATE = b"\x03"   #Initiates a SOCKS5 UDP association request
        _, relay = self._SOCKS5_request(self._proxyconn, UDP_ASSOCIATE, dst)  #Establishes connection to relay address recieved from the proxy

        host, _ = proxy  #Sets timeout + proxy sockname
        _, port = relay
        super(socksocket, self).connect((host, port))
        super(socksocket, self).settimeout(self._timeout)
        self.proxy_sockname = ("0.0.0.0", 0) 

    def sendto(self, bytes, *args, **kwargs):  #Overrides 'sendto' method for UDP sockets
        if self.type != socket.SOCK_DGRAM:
            return super(socksocket, self).sendto(bytes, *args, **kwargs)
        if not self._proxyconn:
            self.bind(("", 0))  #If not bound, binds to a local address

        address = args[-1]  #Parses addresses + flags
        flags = args[:-1]

        header = BytesIO()   #Constructs a SOCKS5 header
        RSV = b"\x00\x00"    
        header.write(RSV)    #Writes it to a buffer
        STANDALONE = b"\x00"
        header.write(STANDALONE)
        self._write_SOCKS5_address(address, header)

        sent = super(socksocket, self).send(header.getvalue() + bytes, *flags,  #Sends the data with the header using the superclass method
                                            **kwargs)
        return sent - header.tell()

    def send(self, bytes, flags=0, **kwargs):   #For UDP sockets, it redirects the call to the 'sendto' method with the proxy peername as the dest address
        if self.type == socket.SOCK_DGRAM:
            return self.sendto(bytes, flags, self.proxy_peername, **kwargs)
        else:
            return super(socksocket, self).send(bytes, flags, **kwargs)  #For other socket types, it calls the superclass 'send' method

    def recvfrom(self, bufsize, flags=0):   #For UDP sockets, it binds the socket if it's not already bound
        if self.type != socket.SOCK_DGRAM:
            return super(socksocket, self).recvfrom(bufsize, flags)  #Redirects the call to the superclass' 'recvfrom' method
        if not self._proxyconn:
            self.bind(("", 0))

        buf = BytesIO(super(socksocket, self).recv(bufsize + 1024, flags))  #Receives the data from the socket
        buf.seek(2, SEEK_CUR)
        frag = buf.read(1)     #Reads the SOCKS5 header
        if ord(frag):
            raise NotImplementedError("Received UDP packet fragment")
        fromhost, fromport = self._read_SOCKS5_address(buf)  #Extracts the source address + port of the received UDP packet

        if self.proxy_peername:   #Checks if there's a proxy peer name set
            peerhost, peerport = self.proxy_peername  #If so, it verifies that the received packet's source host + port match the expected values
            if fromhost != peerhost or peerport not in (0, fromport):
                raise socket.error(EAGAIN, "Packet filtered")

        return (buf.read(bufsize), (fromhost, fromport))  #Returns the recieved data + the source address + port

    def recv(self, *pos, **kw):
        bytes, _ = self.recvfrom(*pos, **kw)  #Receives data using 'recvfrom'
        return bytes  #Returns only the bytes received

    def close(self):
        if self._proxyconn:
            self._proxyconn.close()  #Closes the proxy connection + then closes the socket
        return super(socksocket, self).close()

    def get_proxy_sockname(self):   #Returns the bound IP address + port number at the proxy
        return self.proxy_sockname

    getproxysockname = get_proxy_sockname  #Same name

    def get_proxy_peername(self):  #Returns the IP address + port number of the proxy
        return self.getpeername()

    getproxypeername = get_proxy_peername

    def get_peername(self):  #Returns the IP address + port nmuber of the destination machine
        return self.proxy_peername  #'get_proxy_peername': Returns the proxy's IP address + port number

    getpeername = get_peername

    def _negotiate_SOCKS5(self, *dest_addr):  #Negotiates a stream connection through a SOCKS5 server
        CONNECT = b"\x01" 
        self.proxy_peername, self.proxy_sockname = self._SOCKS5_request(  #Sends a CONNECT request to the SOCKS5 server with the destination address
            self, CONNECT, dest_addr)

    def _SOCKS5_request(self, conn, cmd, dst):  #Sends a SOCKS5 request with a given command(cmd) + address(dst) to the SOCKS5 server
        proxy_type, addr, port, rdns, username, password = self.proxy  #Returns the resolved destination address that was used

        writer = conn.makefile("wb")    #Opens a writer + a reader for the connection, allowing it to send data to + receive data from the SOCKS5 server
        reader = conn.makefile("rb", 0)  
        try:
            if username and password:  #Tries to send the supported authentication methods to the SOCKS5 server
                writer.write(b"\x05\x02\x00\x02")  #If a username + password were provided, it sends a request supporting Username/Password authentication
            else:                                  #Otherwise, it sends a request for no authentication
                writer.write(b"\x05\x01\x00")

            writer.flush()
            chosen_auth = self._readall(reader, 2)  #After sending the request, it reads the server's response to determine which authentication method was chosen

            if chosen_auth[0:1] != b"\x05":  #Checks if the 1st byte of the server's response is not equal to the SOCKS5 protocol version byte('b"\x05"')
                raise GeneralProxyError(     #If it's not, it raises an error indicating that the SOCKS5 proxy server sent invalid data
                    "SOCKS5 proxy server sent invalid data")

            if chosen_auth[1:2] == b"\x02":  #Checks if the second byte of the server's response is equal to ('b"\x02"'), indicating that the server requested basic user/pass authentication
                if not (username and password):  #If no user/pass supplied, it raises an error
                    raise SOCKS5AuthError("No username/password supplied. "
                                          "Server requested username/password"
                                          " authentication")

                writer.write(b"\x01" + chr(len(username)).encode()  #Sends the user + pass to SOCKS5 server for authentication
                             + username
                             + chr(len(password)).encode()
                             + password)
                writer.flush()
                auth_status = self._readall(reader, 2)  #Reads authentication status

                if auth_status[0:1] != b"\x01":
                    raise GeneralProxyError(
                        "SOCKS5 proxy server sent invalid data")  #Raises an error if the SOCKS5 proxy server sends invalid data

                if auth_status[1:2] != b"\x00":
                    raise SOCKS5AuthError("SOCKS5 authentication failed")  #Raises an error if SOCKS5 authentication fails

            elif chosen_auth[1:2] != b"\x00":
                if chosen_auth[1:2] == b"\xFF":  #Raises an error if all offered SOCKS5 authentication methods are rejected 
                    raise SOCKS5AuthError(
                        "All offered SOCKS5 authentication methods were"
                        " rejected")
                else:
                    raise GeneralProxyError(
                        "SOCKS5 proxy server sent invalid data")   #or if the SOCKS5 proxy server sends invalid data

            writer.write(b"\x05" + cmd + b"\x00")  #Writes SOCKS5 request header + address data
            resolved = self._write_SOCKS5_address(dst, writer) 
            writer.flush()  #Flushes the writer stream

            resp = self._readall(reader, 3)  #Reads + validates the response from the SOCKS5 proxy server
            if resp[0:1] != b"\x05":
                raise GeneralProxyError(
                    "SOCKS5 proxy server sent invalid data")

            status = ord(resp[1:2])  #Checks + raises errors if the connection fails
            if status != 0x00:
                error = SOCKS5_ERRORS.get(status, "Unknown error")
                raise SOCKS5Error("{:#04x}: {}".format(status, error))  #Provides detailed info about the error if available

            bnd = self._read_SOCKS5_address(reader)  #Reads the bound address from the SOCKS5 server response

            super(socksocket, self).settimeout(self._timeout)  #Sets the timeout
            return (resolved, bnd)  #Returns the resolved address + the bound address
        finally:
            reader.close()  #Closes the reader + writer
            writer.close()

    def _write_SOCKS5_address(self, addr, file):  #Writes the SOCKS5 address to the file object, packing the host + port for the SOCKS5 protocol
        host, port = addr
        proxy_type, _, _, rdns, username, password = self.proxy
        family_to_byte = {socket.AF_INET: b"\x01", socket.AF_INET6: b"\x04"}

        for family in (socket.AF_INET, socket.AF_INET6):  #Attempts to write the SOCKS5 addresses for both IPv4v + IPv6 families
            try:
                addr_bytes = socket.inet_pton(family, host)
                file.write(family_to_byte[family] + addr_bytes)
                host = socket.inet_ntop(family, addr_bytes)
                file.write(struct.pack(">H", port))
                return host, port  #If successful, returns the host + port
            except socket.error:
                continue

        if rdns:   #Writes the address with remote DNS resolution enabled
            host_bytes = host.encode("idna")  #Encodes the host name + writes its length before writing the actual host bytes
            file.write(b"\x03" + chr(len(host_bytes)).encode() + host_bytes)
        else:
            addresses = socket.getaddrinfo(host, port, socket.AF_UNSPEC,  #If remote DNS resolution is disabled, it resolves the host name locally + writes the address using
                                           socket.SOCK_STREAM,             #the 1st resolved IP address
                                           socket.IPPROTO_TCP,
                                           socket.AI_ADDRCONFIG)
            target_addr = addresses[0]
            family = target_addr[0]
            host = target_addr[4][0]

            addr_bytes = socket.inet_pton(family, host)     #It converts the host address to bytes + writes it to the file, along with the address family byte
            file.write(family_to_byte[family] + addr_bytes)
            host = socket.inet_ntop(family, addr_bytes)
        file.write(struct.pack(">H", port))   #Then it writes the port number to the file in network byte order + returns the host + port
        return host, port

    def _read_SOCKS5_address(self, file):   
        atyp = self._readall(file, 1)      #Reads the address type byte from the file
        if atyp == b"\x01":
            addr = socket.inet_ntoa(self._readall(file, 4))  #Depending on the address type, it reads the address + returns it
        elif atyp == b"\x03":
            length = self._readall(file, 1)
            addr = self._readall(file, ord(length))
        elif atyp == b"\x04":
            addr = socket.inet_ntop(socket.AF_INET6, self._readall(file, 16))
        else:
            raise GeneralProxyError("SOCKS5 proxy server sent invalid data")  #If the address type is not recognized, it raises an error

        port = struct.unpack(">H", self._readall(file, 2))[0]  #Reads the port from the file + returns it along with the address
        return addr, port

    def _negotiate_SOCKS4(self, dest_addr, dest_port):  #Negotiaties a connection through a SOCKS4 server by writing to + reading from the file
        proxy_type, addr, port, rdns, username, password = self.proxy

        writer = self.makefile("wb")
        reader = self.makefile("rb", 0)  
        try:
            remote_resolve = False  #Tries to determine if the destination address provided is an IP address
            try:
                addr_bytes = socket.inet_aton(dest_addr)  
            except socket.error:
                if rdns:
                    addr_bytes = b"\x00\x00\x00\x01"  #If not, it checks whether it should be resolved remotely or locally
                    remote_resolve = True
                else:
                    addr_bytes = socket.inet_aton(
                        socket.gethostbyname(dest_addr))

            writer.write(struct.pack(">BBH", 0x04, 0x01, dest_port))  #Writes the SOCKS4 protocol version, command code + destination port to the writer
            writer.write(addr_bytes)  #Then, it writes the destination IP address bytes

            if username:
                writer.write(username)  #It writes the username if available, followed by the null byte
            writer.write(b"\x00")

            if remote_resolve:  #It writes the destination address if it's resolved remotely, followed by the null byte
                writer.write(dest_addr.encode("idna") + b"\x00") 
            writer.flush()

            resp = self._readall(reader, 8)  #Reads the response from the SOCKS4 proxy server + checks if it's valid
            if resp[0:1] != b"\x00":
                raise GeneralProxyError(  #If not, it raises an error
                    "SOCKS4 proxy server sent invalid data")

            status = ord(resp[1:2])  #Checks the status of the response from the SOCKS4 proxy server
            if status != 0x5A:  #If the status indicates an error, it raises a SOCKS4Error with the message
                error = SOCKS4_ERRORS.get(status, "Unknown error")
                raise SOCKS4Error("{:#04x}: {}".format(status, error))

            self.proxy_sockname = (socket.inet_ntoa(resp[4:]),  #Sets the proxy socket name based on the response received from the SOCKS4 proxy server
                                   struct.unpack(">H", resp[2:4])[0])
            if remote_resolve:  #If remote resolution was performed, it sets the proxy peername accordingly
                self.proxy_peername = socket.inet_ntoa(addr_bytes), dest_port
            else:
                self.proxy_peername = dest_addr, dest_port
        finally:
            reader.close()  #Closes the reader + writer
            writer.close()

    def _negotiate_HTTP(self, dest_addr, dest_port):  #Negotiates a connection through an HTTP server using the HTTP Connect method
        proxy_type, addr, port, rdns, username, password = self.proxy

        addr = dest_addr if rdns else socket.gethostbyname(dest_addr) #If local resolution is needed, it resolves the dest add using 'socket.gethostbyname()'

        http_headers = [   #Prepares HTTP headers for the connect request, including the dest add + port in the 'Host' header
            (b"CONNECT " + addr.encode("idna") + b":"
             + str(dest_port).encode() + b" HTTP/1.1"),
            b"Host: " + dest_addr.encode("idna")  #Dest add is encoded using IDNA if needed
        ]

        if username and password:  #Adds basic authentication credentials to the HTTP headers if provided
            http_headers.append(b"Proxy-Authorization: basic "
                                + b64encode(username + b":" + password))

        http_headers.append(b"\r\n")  #Sends the headers to the proxy server

        self.sendall(b"\r\n".join(http_headers))

        fobj = self.makefile()  #Reads the response status line from the proxy server's HTTP response
        status_line = fobj.readline()
        fobj.close()

        if not status_line:  #Raises an error if the status line is empty, indicating an unexpected closure of the connection
            raise GeneralProxyError("Connection closed unexpectedly")

        try:  #Attempts to split the status line into 3 parts: protocol, status code + status msg
            proto, status_code, status_msg = status_line.split(" ", 2)
        except ValueError:  #If unsuccessful, it raises an error indicating an invalid response from the HTTP proxy server
            raise GeneralProxyError("HTTP proxy server sent invalid response")

        if not proto.startswith("HTTP/"):  #Checks if the protocol starts with 'HTTP/' 
            raise GeneralProxyError(  #If not, it raises an error
                "Proxy server does not appear to be an HTTP proxy")

        try:
            status_code = int(status_code)  #Attempts to convert the status code to an integer
        except ValueError:  #If it fails, it raises an error
            raise HTTPError(
                "HTTP proxy server did not return a valid HTTP status")

        if status_code != 200:  #Checks if the status code is not 200
            error = "{}: {}".format(status_code, status_msg)
            if status_code in (400, 403, 405):  #If the status code indicates a client error(400,403,405), it includes a note suggesting that the HTTP proxy server
                error += ("\n[*] Note: The HTTP proxy server may not be"  #may not support the CONNECT tunneling method
                          " supported by PySocks (must be a CONNECT tunnel"
                          " proxy)")
            raise HTTPError(error)

        self.proxy_sockname = (b"0.0.0.0", 0)  #Sets the proxy sockname to ((b"0.0.0.0", 0)) + the proxy peername to (addr, dest_port)
        self.proxy_peername = addr, dest_port

    _proxy_negotiators = {  #A dictionary mapping proxy types to their respective negotiation methods
                           SOCKS4: _negotiate_SOCKS4,
                           SOCKS5: _negotiate_SOCKS5,
                           HTTP: _negotiate_HTTP
                         }

    @set_self_blocking  
    def connect(self, dest_pair, catch_errors=None):  #Decorates the 'connect' method to handle blocking behaviour

        if len(dest_pair) != 2 or dest_pair[0].startswith("["):   #Raises an error if the destination pair isn't in the correct format or if it starts with an opening 
            raise socket.error("PySocks doesn't support IPv6: %s"  #square bracket, which likely indicates an IPv6 add, not supported by PySocks
                               % str(dest_pair))

        dest_addr, dest_port = dest_pair

        if self.type == socket.SOCK_DGRAM:  #Binds the socket if it's of type 'SOCK_DGRAM' + hasn't connected to the proxy yet
            if not self._proxyconn:
                self.bind(("", 0))
            dest_addr = socket.gethostbyname(dest_addr)  #Resolves the dest add if needed

            if dest_addr == "0.0.0.0" and not dest_port:
                self.proxy_peername = None  #Sets proxy_peername to none if the dest add is '0.0.0.0' + no port is provided
            else:
                self.proxy_peername = (dest_addr, dest_port)  #Otherwise, sets it to the dest add + port
            return

        (proxy_type, proxy_addr, proxy_port, rdns, username,
         password) = self.proxy

        if (not isinstance(dest_pair, (list, tuple))  #Raises an error if the dest pair is not a valid(host, port) tuple or list, or if either the host or port
                or len(dest_pair) != 2                 #is missing or not of the correct type
                or not dest_addr
                or not isinstance(dest_port, int)):
            raise GeneralProxyError(
                "Invalid destination-connection (host, port) pair")

        super(socksocket, self).settimeout(self._timeout)  #Sets the timeout value for the socket connection using the timeout value stored in '_timeout'

        if proxy_type is None:  #If 'proxy_type' is not specified, it behaves like a regular socket + connects directly to 'dest_pair'
            self.proxy_peername = dest_pair
            super(socksocket, self).settimeout(self._timeout)
            super(socksocket, self).connect((dest_addr, dest_port))
            return

        proxy_addr = self._proxy_addr()

        try:  #Attempts an initial connection to the proxy server 
            super(socksocket, self).connect(proxy_addr)

        except socket.error as error:  #Catches any socket error that occurs during the connection to the proxy server, closes the connection + raises the error
            self.close()                #again if 'catch_errors' is not specified
            if not catch_errors:
                proxy_addr, proxy_port = proxy_addr
                proxy_server = "{}:{}".format(proxy_addr, proxy_port)
                printable_type = PRINTABLE_PROXY_TYPES[proxy_type]

                msg = "Error connecting to {} proxy {}".format(printable_type,  #Generates an error message indicating the failure to connect to the specified proxy 
                                                                    proxy_server) #server + raises an error
                log.debug("%s due to: %s", msg, error)  #Logs the error for debugging purposes
                raise ProxyConnectionError(msg, error)
            else:
                raise error

        else:
            try:
                negotiate = self._proxy_negotiators[proxy_type]  #Initiates negotiation with the proxy server based on the specified proxy type
                negotiate(self, dest_addr, dest_port)

            except socket.error as error:  #Handles errors during negotiation with the proxy server, wrapping socket errors + protocol errors with appropriate exceptions
                if not catch_errors:
                    self.close()
                    raise GeneralProxyError("Socket error", error)
                else:
                    raise error
            except ProxyError:
                self.close()
                raise
                
    @set_self_blocking
    def connect_ex(self, dest_pair):  #Attempts to connect to a dest through a proxy
        try:
            self.connect(dest_pair, catch_errors=True) #If successful, it returns 0
            return 0
        except OSError as e:
            if e.errno:  #If an '0SError' occurs, it returns the error number if available
                return e.errno
            else:
                raise

    def _proxy_addr(self):  #Retreives the proxy address as a tuple object, including the proxy type, add + port
        (proxy_type, proxy_addr, proxy_port, rdns, username,
         password) = self.proxy
        proxy_port = proxy_port or DEFAULT_PORTS.get(proxy_type)
        if not proxy_port:  #If port is not specified, it uses a default port associated with the proxy type
            raise GeneralProxyError("Invalid proxy type")  #If no default port is available, it raises an error
        return proxy_addr, proxy_port