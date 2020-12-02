import struct
import time
import socket
import select
import sys


source_ip = '18.232.157.167'
max_hop = 32
msg = 'Measurement for class project. Questions to student ktn27@case.edu or professor mxr136@case.edu'
payload = bytes(msg, 'ascii')
port = 33434
VERBOSE = True


def set_socket(ttl):
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

def create_header(dest_ip):


    # ip header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0	# kernel will fill the correct total length
    ip_id = 54321	# ID of this packet
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0	# kernel will fill the correct checksum
    ip_saddr = socket.inet_aton ( source_ip )
    ip_daddr = socket.inet_aton ( dest_ip )

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # the ! in the pack format string means network order
    ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    
    
    # tcp header fields
    tcp_source = port	# source port
    tcp_dest = 80	# destination port
    tcp_seq = 454
    tcp_ack_seq = 0
    tcp_doff = 5	#4 bit field, size of tcp header, 5 * 4 = 20 bytes
    #tcp flags
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons (5840)	#	maximum allowed window size
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

    # the ! in the pack format string means network order
    tcp_header = struct.pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)




    return ip_id, payload

def get_hop_count_and_rtt_of(dest_addr):
    ttl = max_hop
    rtt = time.time()

    while True:

        dest_ip = socket.gethostbyname(dest_addr)
        rcv_socket, snd_socket = set_socket(ttl)
        rcv_socket.bind(("", port))

        select_status = select.select([rcv_socket], [], [], 2)

        node_addr = None
        node_name = None
        tries = 3
        reachable = False

        snd_socket.sendto(payload, (dest_ip, port))

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
        for part in ip_header:
            print(part)
        
        # close all sockets
        snd_socket.close()
        rcv_socket.close()

        # exit the loop when reached dest or exceeded max # of hops
        if node_addr == dest_addr or node_ttl <= 0:
            hop_count = max_hop - node_ttl

            original_msg = []

            if icmp_packet[56:] in payload:
                # this is the original message contained in the icmp
                original_msg = icmp_packet[56:]

            rtt = int((time.time() - rtt)*1000)
            print('<Sys>: Site: %s, IP: %s HOP_COUNT: %s, RTT: %d ms, bytes of initial message in ICMP: %d ' % (
                dest_ip, dest_addr, hop_count, rtt, len(original_msg)))
            return hop_count, rtt, len(original_msg)


def main(targets, results):

    targets_list = open(targets).read().splitlines()
    result = open(results, 'w')

    for target in targets_list:
        hop_count, rtt, size_of_initial_msg = get_hop_count_and_rtt_of(target)
        result.write('%s, %s, %s, %s\n' % (target, hop_count, rtt, size_of_initial_msg))

    print('Probing finished.')
    result.close()


if __name__ == "__main__":
    main("targets.txt", "trace_results.csv")
