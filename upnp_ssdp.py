#!/usr/bin/env python
# -*- coding: us-ascii -*-
# vim:ts=4:sw=4:softtabstop=4:smarttab:expandtab
#
"""Simple UPnP ssdp library for clients and servers.

Almost certainly *not* 100% compliant :-)

Useful resources on this topic:

  * http://www.w3.org/TR/discovery-api/ - definitive!
  * http://www.upnp-hacks.org/upnp.html
  * http://buildingskb.schneider-electric.com/view.php?AID=15197

NOTE Many examples (some above) wrap MAN value in double quotes,
Official standards do not.

Routines for sending/receiving/processing:

    M-SEARCH * HTTP/1.1
    HOST: 239.255.255.250:1900
    MAN: ssdp:discover
    MX: 3
    ST: ssdp:all

"""


import os
import sys
import logging
import platform
import struct
import socket
import select
import threading
import time
import httplib
try:
    import cStringIO as StringIO
except ImportError:
    import StringIO


log = logging.getLogger('upnp_ssdp')
logging.basicConfig()
#log.setLevel(logging.DEBUG)

SSDP_MULTICAST_ADDR = '239.255.255.250'
SSDP_PORT = 1900
SSDP_PACKET_SIZE = 4096  # Way bigger than we need, could consider shrinking to 1024

# new format style.. moustache like
SSDP_QUERY_STRING = "\r\n".join([
    'M-SEARCH * HTTP/1.1',
    'HOST: {host_ip}:{host_port}',
    'MAN: ssdp:discover',
    'ST: {st}',
    'MX: {mx}',
    '',
    '',
    ])

# fragile but easy % style
SSDP_QUERY_STRING = "\r\n".join([
    'M-SEARCH * HTTP/1.1',
    'HOST: %(host_ip)s:%(host_port)d',
    'MAN: ssdp:discover',
    'ST: %(st)s',
    'MX: %(mx)d',
    '',
    '',
    ])
# TODO useragent should really be included


class Response(httplib.HTTPResponse):
    """
    NB if this is an response that does not start with 'HTTP/1.1 200 OK', stdlib httplib.HTTPResponse() will fail to find anything.
    """
    def __init__(self, response_text):
        self.fp = StringIO.StringIO(response_text)
        self.debuglevel = 0
        self.strict = 0
        self.msg = None
        self._method = None
        self.begin()


def process_ssdp_result_message(in_bytes):
    """Returns tuple of unique key and value(s)
    Assumes we can use Python httplib library to
    process HTTP Response.
    """
    response = Response(in_bytes)
    headers = response.getheaders()
    header_dict = dict(headers)
    # find something unique
    location = header_dict['location']
    return (location, header_dict)


def simple_http_headers_processor(in_bytes, unique_key='location'):
    """Returns tuple of unique key and value(s)
    pilight v5 does NOT return spaces after header colon and httplib freaks out.
    This simply using naive string spliting to process HTTP headers.
    This is not intended to be 100% compliant with http://www.w3.org/TR/discovery-api/
    """
    #print '-' * 65
    #print repr(in_bytes)
    #print '-' * 65
    header_dict = {}
    header_list = in_bytes.split('\r\n')
    #assert 'NOTIFY * HTTP/1.1' in header_list[0] or 'M-SEARCH * HTTP/1.1' in header_list[0], repr(header_list[0][:30])
    header_list.pop(0)
    for line in header_list:
        line = line.strip()
        if line:
            try:
                key, value = line.split(':', 1)
                key = key.lower()
                value = value.strip()
                header_dict[key] =  value
            except ValueError:
                # Probably did NOT split correctly, i.e. not a "name: value" pair
                pass
    if unique_key:
        location = header_dict['location']
        return (location, header_dict)
    else:
        return header_dict


def ssdp_discover(service_name='ssdp:all', timeout=3, host_ip=SSDP_MULTICAST_ADDR, host_port=SSDP_PORT, process_func=simple_http_headers_processor):
    """SSDP search client. Find all/specified ssdp services
    Sample service names:
        service_name='ssdp:all'  # find all, no filter
        service_name='upnp:rootdevice'  # find all, no filter
        service_name='uuid:...specific name....', filter to name
    
    host_ip can be multicast or a specific ip address for unicast
    
    Currently retries are not attempted
    """
    assert 1<= timeout <= 5
    ssdp_values = {
        'host_ip': host_ip,  # unicast (specific ip) or multicast
        'host_port': host_port,  # almost always 1900
        'st': service_name,
        'mx': timeout,
    }
    ssdp_query_string = SSDP_QUERY_STRING % ssdp_values
    log.debug('ssdp query: %r', ssdp_query_string)
    result = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    sock.sendto(ssdp_query_string, (host_ip, host_port))
    location = 0  # DEBUG
    while 1:
        # TODO handle timeout math
        rlist, wlist, elist = select.select([sock], [], [], timeout)
        if rlist:
            packet_bytes = sock.recv(SSDP_PACKET_SIZE)
            log.debug('ssdp response: %r', packet_bytes)
            location, header_dict = process_func(packet_bytes)
            result[location] = header_dict
        else:
            break

    return result

def show_devices():
    log.setLevel(logging.INFO)
    #log.setLevel(logging.DEBUG)  # DEBUG
    log.info('Looking for published SSDP services on network')
    services = ssdp_discover()
    for x in services:
        print '-' * 65
        print x
        print services[x]['server']
        print services[x]


def print_all(*args, **kwargs):
    """simply shows all ssdp discovery requests"""
    print '\t', args, kwargs


def demo_service(service_name, respond_to_wildcard=True, process_func=print_all, host_ip=SSDP_MULTICAST_ADDR, host_port=SSDP_PORT):
    """Not implemented yet, simply shows all ssdp discovery requests
    If respond_to_wildcard is True (default) respond to service name
    searches for; 'ssdp:all' and 'upnp:rootdevice'
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.bind(('', host_port))

    mreq = struct.pack('4sl', socket.inet_aton(host_ip), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    try:
        while True:
            data = sock.recvfrom(SSDP_PACKET_SIZE)
            raw_bytes, peer_info = data
            if raw_bytes.startswith('NOTIFY * HTTP/1.1\r\n'):
                # We have an SSDP Advertiser
                print 'SSDP Advertiser'
                peer_ip, peer_port = peer_info
                print '\t', peer_ip, peer_port
                print '\t', repr(raw_bytes)
                header_dict = simple_http_headers_processor(raw_bytes, unique_key=None)
                print '\t', header_dict
                from pprint import pprint
                pprint(header_dict)
            elif raw_bytes.startswith('M-SEARCH * HTTP/1.1\r\n'):
                print 'client searching for a service'
                print '\t', data
                # We have a client searching for a service
                peer_ip, peer_port = peer_info
                header_dict = simple_http_headers_processor(raw_bytes, unique_key=None)
                st = header_dict['st']
                service_name_match = False
                if respond_to_wildcard and (st == 'ssdp:all' or st == 'upnp:rootdevice'):
                    service_name_match = True
                print '\t', (service_name , st)
                if service_name == st:
                    print '\t', 'st'
                    service_name_match = True
                if service_name_match:
                    process_func(sock, peer_ip, peer_port, header_dict)
            else:
                print '????????????'
                print data
    finally:
        sock.close()


##################################



class StoppableThread(threading.Thread):
    """Thread class with a stop() method. The thread itself has to check
    regularly for the stopped() condition."""

    def __init__(self):
        super(StoppableThread, self).__init__()
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def stopped(self):
        return self._stop.isSet()


class MySsdpThreadServer(StoppableThread):
    def run(self):
        logger = logging.getLogger("ssdp_server")
        logger.setLevel(logging.INFO)
        #logger.setLevel(logging.DEBUG)  # DEBUG

        settings = self._settings
        process_func = settings['process_func']

        host_ip = SSDP_MULTICAST_ADDR
        host_port = SSDP_PORT

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.bind(('', host_port))

        mreq = struct.pack('4sl', socket.inet_aton(host_ip), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        logger.debug('ssdp MySsdpThreadServer about to listen')
        try:
            timeout = 1
            while not self.stopped():
                logger.debug('ssdp MySsdpThreadServer about to select')
                rlist, wlist, elist = select.select([sock], [], [], timeout)
                if rlist:
                    data = sock.recvfrom(SSDP_PACKET_SIZE)
                    logger.debug('ssdp server recieved: %r', data)
                    raw_bytes, peer_info = data
                    process_http = True
                    if raw_bytes.startswith('NOTIFY * HTTP/1.1\r\n'):
                        # We have an SSDP Advertiser
                        logger.debug('ssdp server recieved: NOTIFY - an SSDP Advertiser broadcast')
                    elif raw_bytes.startswith('M-SEARCH * HTTP/1.1\r\n'):
                        # We have a client searching for a service
                        logger.debug('ssdp server recieved: M-SEARCH - client searching for a service')
                    else:
                        logger.error('Peer %r sent unhandled %r', peer_info, raw_bytes)
                        process_http = False
                    if process_http:
                        header_dict = simple_http_headers_processor(raw_bytes, unique_key=None)
                        process_func(sock, peer_info, header_dict, settings)
                else:
                    time.sleep(timeout)
        finally:
            sock.close()


def determine_local_ipaddr():
    local_address = None

    # Most portable (for modern versions of Python)
    if hasattr(socket, 'gethostbyname_ex'):
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if not ip.startswith('127.'):
                local_address = ip
                break
    # may be none still (nokia) http://www.skweezer.com/s.aspx/-/pypi~python~org/pypi/netifaces/0~4 http://www.skweezer.com/s.aspx?q=http://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib has alonger one

    if sys.platform.startswith('linux'):
        import fcntl

        def get_ip_address(ifname):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', ifname[:15])
            )[20:24])

        if not local_address:
            for devname in ["eth0", "eth1", "eth2", "wlan0", "wlan1", "wifi0", "ath0", "ath1", "ppp0"]:
                try:
                    ip = get_ip_address(devname)
                    if not ip.startswith('127.'):
                        local_address = ip
                        break
                except IOError:
                    pass

    # Jython / Java approach
    if not local_address and InetAddress:
        addr = InetAddress.getLocalHost()
        hostname = addr.getHostName()
        for ip_addr in InetAddress.getAllByName(hostname):
            if not ip_addr.isLoopbackAddress():
                local_address = ip_addr.getHostAddress()
                break

    return local_address


def ssdp_server_processor_sample(sock, client_addr, header_dict, settings):
    """If respond_to_wildcard is True (default) respond to service name
    searches for; 'ssdp:all' and 'upnp:rootdevice'"""

    respond_to_wildcard = settings.get('respond_to_wildcard', True)
    logger = logging.getLogger("ssdp_server")
    service_name = settings['service_name']
    st = header_dict.get('st')  # seen an Android device NOT provide ST field
    if st is None:
        log.debug('header mising ST field: %r', header_dict)
    service_name_match = False
    if respond_to_wildcard and (st == 'ssdp:all' or st == 'upnp:rootdevice'):
        service_name_match = True
    elif service_name == st:
        service_name_match = True
    if service_name_match:
        ssdp_values = {}
        for x in ('host_ip', 'host_port', 'uuid', 'hostname', 'server_type', 'service_name'):
            ssdp_values[x] = settings[x]
        msg = settings['SSDP_RESPONSE_STRING'] % ssdp_values
        logger.info("SSDP response to %r, send: %r", client_addr, msg)
        sock.sendto(msg, client_addr)

def demo_service_threaded():
    settings = {}
    settings = {
        'SSDP_RESPONSE_STRING': "\r\n".join([  # fragile but easy % style
            'HTTP/1.1 200 OK',
            'Cache-Control:max-age=900',
            'Host:239.255.255.250:1900',  # this may be incorrect on a unicast discover request
            'Location:%(host_ip)s:%(host_port)d',
            'ST:%(service_name)s',
            'NT:upnp:rootdevice',
            'USN:uuid:%(uuid)s::upnp:rootdevice',
            'NTS:ssdp:alive',
            'SERVER:%(server_type)s UPnP/1.1 sample_ssdp_service (%(hostname)s)/5.0',  # limit server_type to 31 bytes

            '',
            '',
        ]),
        'process_func': ssdp_server_processor_sample,  # or print_all()

        # template values
        'service_name': 'urn:schemas-upnp-org:service:pilight:1',
        'host_ip': determine_local_ipaddr(),
        'host_port': 1234,
        'uuid': '00000000-0000-0000-0000-000000000000',  # uuid.uuid4()
        'hostname': platform.node(),
        'server_type': platform.platform(),
    }
    ssdp_server = MySsdpThreadServer()
    ssdp_server._settings = settings
    ssdp_server.start()

    try:
        time.sleep(5)
    finally:
        ssdp_server.stop()
        ssdp_server.join()  # wait for it to stop


##################################

def main(argv=None):
    if argv is None:
        argv = sys.argv

    if 'server' in argv:
        #demo_service('ssdp:all')
        #demo_service('urn:schemas-upnp-org:service:pilight:1')
        demo_service_threaded()
    else:
        show_devices()

    return 0


if __name__ == "__main__":
    sys.exit(main())
