import struct
import time
import socket
import select
import sys


# some value initialization
source_ip = '18.232.157.167'
max_hop = 32
msg = 'Measurement for class project. Questions to student ktn27@case.edu or professor mxr136@case.edu'
payload = bytes(msg + 'a' * (1472 - len(msg)), 'ascii')
dest_port = 33434
VERBOSE = True


def create_socket(ttl):
    # creating receive and send sockets
    try:
        receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except socket.error as exc:
        print('Receive socket could not be created. Error : ' + str(exc))
        sys.exit()

    try:
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except socket.error as exc:
        print('Send socket could not be created. Error : ' + str(exc))
        sys.exit()
    
    # setting up socket options
    receiver.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    sender.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    time_out = struct.pack("ll", 5, 0)
    receiver.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, time_out)

    return receiver, sender


def get_rtt_hop_count_measurement_from(dest_addr, src_port):
    ttl = max_hop
    rtt = time.time()

    while True:
        # getting ip address of dest and create sockets
        dest_ip = socket.gethostbyname(dest_addr)
        receiver, sender = create_socket(ttl)

        # socket port binding
        receiver.bind(("", dest_port))
        sender.bind(("", src_port))

        select_status = select.select([receiver], [], [], 2)

        # initialize address info
        node_addr = None
        node_name = None

        # initialize trace trials info
        tries = 3
        reachable = False

        # sending the packet
        sender.sendto(payload, (dest_ip, dest_port))

        # try receiving response
        while not reachable and tries > 0 and select_status:
            try:
                # get the address from receiving socket
                icmp_packet, node_addr = receiver.recvfrom(512)
                reachable = True
                node_addr = node_addr[0]

                try:
                    # reverse DNS lookup
                    node_name = socket.gethostbyaddr(node_addr)[0]
                except socket.error:
                    # in case of failure, substituting with the address
                    node_name = node_addr

            except socket.error:
                print("Receive from socket failed.")
                tries -= 1

        # handle failure with getting response
        if not reachable:
            print(dest_addr + " is unreachable after 3 trials.")
            return "Unreachable", "Unreachable"

        # in case of success in getting resonse
        # unpack ip header
        ip_header_packed = icmp_packet[28:48]
        ip_header = struct.unpack('!BBHHHBBH4s4s', ip_header_packed)

        # extract time to live
        node_ttl = ip_header[5]
        ttl = node_ttl

        # extract ICMP response source IP address
        # and src IP address vs. dest IP address
        src_IP_addr_byte = ip_header[9]
        src_IP_addr = str(src_IP_addr_byte[0]) + '.' + str(src_IP_addr_byte[1]) + '.' + str(src_IP_addr_byte[2]) + '.' + str(src_IP_addr_byte[3])
        matched_IP_addr = True if src_IP_addr == dest_addr else False

        # extract ICMP packet's src port from udp header
        # and port from packet vs. initially binded port
        udp_header_packed = icmp_packet[48:50]
        udp_header = struct.unpack('!H', udp_header_packed)
        port_from_packet = udp_header[0]
        matched_port_number = True if port_from_packet == src_port else False

        # declare match, no match
        matched_src = matched_IP_addr or matched_port_number

        # close all sockets
        sender.close()
        receiver.close()


        # when reached destination or exceeded max number of hops
        # stop the process
        if node_addr == dest_ip or node_ttl <= 0:
            hop_count = max_hop - node_ttl

            original_msg = []

            if icmp_packet[56:] in payload:
                # get original message from the ICMP packet
                original_msg = icmp_packet[56:]

            rtt = int((time.time() - rtt)*1000)
            # output info
            print('Site: %s, IP: %s HOP_COUNT: %s, RTT: %d ms, Matched sent packet\'s data: %r, bytes of initial message in ICMP: %d ' % (
                dest_ip, dest_addr, hop_count, rtt, matched_src, len(original_msg)))
            print('IP address un-modified in transit: %r' % (matched_IP_addr))
            print('Packet source port un-modified: %r' % (matched_port_number))

            # write measure data
            return hop_count, rtt, len(original_msg)


def main(targets, results):
    # reading target file
    targets_list = open(targets).read().splitlines()
    result = open(results, 'w')

    # initialize port number for send socket
    src_port = 60000

    for target in targets_list:
        # start measurement
        hop_count, rtt, size_of_initial_msg = get_rtt_hop_count_measurement_from(target, src_port)

        # writing the measurement data
        result.write('%s, %s, %s, %s\n' % (target, hop_count, rtt, size_of_initial_msg))

        # change to new unique port for sender
        src_port += 1

    # Done
    print('Probing finished.')
    result.close()


if __name__ == "__main__":
    main("targets.txt", "trace_results.csv")
