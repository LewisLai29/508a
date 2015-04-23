import argparse, random, socket, sys
from uuid import getnode as get_mac

BUF_SIZE = 65535

def getMacAddr():
    return get_mac()


def setClientSocket():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client_socket.bind(("0.0.0.0", 68))
    return client_socket


def setServerSocket():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", 67))
    return server_socket


def DHCPDISCOVER():
    packet = b''
    packet += b'\x01'   #Message type: Boot Request (1)
    packet += b'\x01'   #Hardware type: Ethernet
    packet += b'\x06'   #Hardware address length: 6
    packet += b'\x00'   #Hops: 0 
    packet += b"\x39\x03\xf3\x26"       #Transaction ID
    packet += b'\x00\x00'    #Seconds elapsed: 0
    packet += b'\x00\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
    packet += b'\x10\xbf\x48\x4F\x38\x38'   #Client MAC address: 10:bf:48:4f:38:38
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
    packet += b'\x00' * 64  #Server host name not given
    packet += b'\x00' * 128 #Boot file name not given
    packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
    packet += b'\x35\x01\x01'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
    packet += b'\x3d\x07\x01\x10\xbf\x48\x4F\x38\x38'
    packet += b'\x32\x04\x00\x00\x00\x00'   #Option: (t=55,l=3) Parameter Request List
    packet += b'\x37\x04\x00\x00\x00\x00'
    packet += b'\xff'   #End Option
    packet += b'\x00' * 7
    return packet


def DHCPOFFER():
    packet = b''
    packet += b'\x02'   #Message type: Boot Request (1)
    packet += b'\x01'   #Hardware type: Ethernet
    packet += b'\x06'   #Hardware address length: 6
    packet += b'\x00'   #Hops: 0 
    packet += b"\x39\x03\xf3\x26"       #Transaction ID
    packet += b'\x00\x00'    #Seconds elapsed: 0
    packet += b'\x00\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
    packet += b'\xc0\xa8\x01\x64'   #Your (client) IP address: 0.0.0.0
    packet += b'\xc0\x00\x00\x00'   #Next server IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
    packet += b'\x10\xbf\x48\x4F\x38\x38'   #Client MAC address: 10:bf:48:4f:38:38
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
    packet += b'\x00' * 64  #Server host name not given
    packet += b'\x00' * 128 #Boot file name not given
    packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
    packet += b'\x35\x01\x02'   #DHCP Message Type = DHCP Discover
    packet += b'\x01\x04\xff\xff\xff\x00'
    packet += b'\x3a\x04\x00\x00\x07\x08'
    packet += b'\x3b\x04\x00\x00\x0c\x4e'
    packet += b'\x33\x04\x00\x00\x0e\x10'
    packet += b'\x36\x04\x7f\x00\x00\x01'
    packet += b'\xff'
    packet += b'\x00' * 26 #end padding
    return packet


def DHCPREQUEST():
    packet = b''
    packet += b'\x01'   #Message type: Boot Request (1)
    packet += b'\x01'   #Hardware type: Ethernet
    packet += b'\x06'   #Hardware address length: 6
    packet += b'\x00'   #Hops: 0 
    packet += b"\x39\x03\xf3\x26"       #Transaction ID
    packet += b'\x00\x00'    #Seconds elapsed: 0
    packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
    packet += b'\x10\xbf\x48\x4F\x38\x38'   #Client MAC address: 10:bf:48:4f:38:38
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
    packet += b'\x00' * 64  #Server host name not given
    packet += b'\x00' * 128 #Boot file name not given
    packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
    packet += b'\x35\x01\x03'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
    packet += b'\x3d\x07\x01\x00\x26\x9e\x04\x1e\x9b'
    packet += b'\x32\x04\xc0\xa8\x00\x0a'   #Option: (t=55,l=3) Parameter Request List
    packet += b'\x36\x04\xc0\xa8\x00\x01'
    packet += b'\x37\x04\x01\x03\x06\x2a'
    packet += b'\xff'   #End Option
    packet += b'\x00'
    return packet


def DHCPACK():
    packet = b''
    packet += b'\x02'   #Message type: Boot Request (1)
    packet += b'\x01'   #Hardware type: Ethernet
    packet += b'\x06'   #Hardware address length: 6
    packet += b'\x00'   #Hops: 0 
    packet += b"\x39\x03\xf3\x26"       #Transaction ID
    packet += b'\x00\x00'    #Seconds elapsed: 0
    packet += b'\x00\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
    packet += b'\xc0\xa8\x01\x64'   #Your (client) IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
    packet += b'\x10\xbf\x48\x4F\x38\x38'   #Client MAC address: 10:bf:48:4f:38:38
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
    packet += b'\x00' * 64  #Server host name not given
    packet += b'\x00' * 128 #Boot file name not given
    packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
    packet += b'\x35\x01\x05'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
    packet += b'\x3a\x04\x00\x00\x07\x08'
    packet += b'\x3b\x04\x00\x00\x0c\x4e'
    packet += b'\x33\x04\x00\x00\x0e\x10'
    packet += b'\x36\x04\x7f\x00\x00\x01'
    packet += b'\x01\x04\xff\xff\xff\x00'
    packet += b'\xff'
    packet += b'\x00' * 26   #End Option
    return packet


def server():
    server_socket = setServerSocket()
    print("Waiting...")
    try:
        data = server_socket.recvfrom(BUF_SIZE)
        print("DHCPDISCOVER : {}".format(data))
    except Exception as e:
        print("DHCPDISCOVER not recieved")

    server_socket.sendto(DHCPOFFER(), ("255.255.255.255", 68))

    try:
        data = server_socket.recvfrom(BUF_SIZE)
        print("DHCPREQUEST : {}".format(data))
    except Exception as e:
        print("DHCPREQUEST not recieved")

    server_socket.sendto(DHCPACK(), ("255.255.255.255", 68))
    server_socket.close()


def client():
    client_socket = setClientSocket()
    client_socket.sendto(DHCPDISCOVER(), ("255.255.255.255", 67))
    try:
        data = client_socket.recvfrom(BUF_SIZE)
        print("DHCPOFFER : {}".format(data))
    except Exception as e:
        print("DHCPOFFER not recieved")

    client_socket.sendto(DHCPREQUEST(), ("255.255.255.255", 67))

    try:
        data = client_socket.recvfrom(BUF_SIZE)
        print("DHCPACK : {}".format(data))
    except Exception as e:
        print("DHCPACK not recieved")

    client_socket.close()


if __name__ == '__main__':
    choices = {'client': client, 'server': server}
    parser = argparse.ArgumentParser(description = 'DHCP Simulation')
    parser.add_argument('role', choices = choices, help = 'which role to take' )
    args = parser.parse_args()
    function = choices[args.role]
    function()
