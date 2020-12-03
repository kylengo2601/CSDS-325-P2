import struct
import time
import socket
import select
import sys


source_ip = '18.232.157.167'
max_hop = 32
msg = 'Measurement for class project. Questions to student ktn27@case.edu or professor mxr136@case.edu'
payload = bytes(msg, 'ascii')
dest_port = 33434
VERBOSE = True


def create_socket(ttl):
    # creating receive and send sockets
    try:
        rcv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except socket.error as exc:
        print('Receive socket could not be created. Error : ' + str(exc))
        sys.exit()

    try:
        snd_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except socket.error as exc:
        print('Send socket could not be created. Error : ' + str(exc))
        sys.exit()
    
    rcv_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    snd_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    time_out = struct.pack("ll", 5, 0)
    rcv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, time_out)

    return rcv_socket, snd_socket


def get_hop_count_and_rtt_of(dest_addr, src_port):
    ttl = max_hop
    rtt = time.time()

    while True:

        dest_ip = socket.gethostbyname(dest_addr)
        rcv_socket, snd_socket = create_socket(ttl)
        rcv_socket.bind(("", dest_port))
        snd_socket.bind(("", src_port))

        select_status = select.select([rcv_socket], [], [], 2)

        node_addr = None
        node_name = None
        tries = 3
        reachable = False

        snd_socket.sendto(payload, (dest_ip, dest_port))

        while not reachable and tries > 0 and select_status:
            try:
                # get the address from receiving socket
                icmp_packet, node_addr = rcv_socket.recvfrom(512)
                reachable = True
                node_addr = node_addr[0]

                try:
                    # reverse DNS lookup
                    node_name = socket.gethostbyaddr(node_addr)[0]
                except socket.error:
                    # substitute it with the address in case failing
                    node_name = node_addr

            except socket.error:
                print("Receive from socket failed.")
                tries -= 1

        if not reachable:
            print(dest_addr + " is unreachable after 3 trials.")
            return "Unreachable", "Unreachable"

        # unpack ip header to get ttl
        ip_header_packed = icmp_packet[28:48]
        ip_header = struct.unpack('!BBHHHBBH4s4s', ip_header_packed)
        node_ttl = ip_header[5]
        ttl = node_ttl

        # extract ICMP response source IP address
        src_IP_addr_byte = ip_header[9]
        src_IP_addr = str(src_IP_addr_byte[0]) + '.' + str(src_IP_addr_byte[1]) + '.' + str(src_IP_addr_byte[2]) + '.' + str(src_IP_addr_byte[3])
        matched_IP_addr = True if src_IP_addr == dest_addr else False

        # extract ICMP packet ID
        packet_IP_ID = ip_header[3]

        # extract ICMP packet's src port from udp header
        udp_header_packed = icmp_packet[48:50]
        udp_header = struct.unpack('!H', udp_header_packed)
        port_from_packet = udp_header[0]
        matched_port_number = True if port_from_packet == src_port else False


        # close all sockets
        snd_socket.close()
        rcv_socket.close()

        # create a new unique source port number
        src_port += 1

        # exit the loop when reached dest or exceeded max # of hops
        if node_addr == dest_ip or node_ttl <= 0:
            hop_count = max_hop - node_ttl

            original_msg = []

            if icmp_packet[56:] in payload:
                # this is the original message contained in the icmp
                original_msg = icmp_packet[56:]

            rtt = int((time.time() - rtt)*1000)
            print('Site: %s, IP: %s HOP_COUNT: %s, RTT: %d ms, bytes of initial message in ICMP: %d ' % (
                dest_ip, dest_addr, hop_count, rtt, len(original_msg)))
            return hop_count, rtt, len(original_msg)


def main(targets, results):

    targets_list = open(targets).read().splitlines()
    result = open(results, 'w')
    src_port = 60000

    for target in targets_list:
        hop_count, rtt, size_of_initial_msg = get_hop_count_and_rtt_of(target, src_port)
        result.write('%s, %s, %s, %s\n' % (target, hop_count, rtt, size_of_initial_msg))
        src_port += 1

    print('Probing finished.')
    result.close()


if __name__ == "__main__":
    main("targets.txt", "trace_results.csv")
