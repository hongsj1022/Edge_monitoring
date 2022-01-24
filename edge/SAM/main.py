import socket
import struct
import textwrap
import iptc
import subprocess
import re
import minio
import json

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

REG_API = '(GET.*|POST.*|PUT.*|DELETE.*) HTTP'
REG_DIR = '/var/lib/docker/overlay2/(.*)/diff'

#Reference
#https://python-iptables.readthedocs.io/en/latest/examples.html
#http://blog.naver.com/PostView.nhn?blogId=alice_k106&logNo=221305928714&parentCategoryNo=&categoryNo=22&viewDate=&isShowPopularPosts=false&from=postView
def main():
    # Get Configuration

    # data = getCallResult("cat ServiceTable.txt")
    # with open("STable.txt", "w") as text_file:
    #     text_file.write(data)
    print("=====================================================")
    print("========== Service Aware Module is running ==========")
    print("=====================================================")
    minio_conn = connect_minio()
    print("================= Get Service Tables ================")
    core_ip_list, core_port_list, core_address_list = get_service_table()
    print("================== Get Edge Tables ==================")
    edge_ip, edge_port, edge_address = get_edge_table()
    print("================== Add DNAT Rules ===================")
    add_dnat_rules(edge_address, core_ip_list, core_port_list)
    print("=============== Start Packet Sniffing ===============")
    #packet_sniffing(minio_conn, edge_ip, core_ip_list)


def packet_sniffing(minio_conn, edge_ip, core_ip_list):
    #   Packet Sniffing
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        #        print('\n Ethernet Frame: ')
        #        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_Packet(data)
            #            print(TAB_1 + "IPV4 Packet:")
            #            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            #            print(TAB_3 + 'protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
            #                print(TAB_1 + 'ICMP Packet:')
            #                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
            #                print(TAB_2 + 'ICMP Data:')
            #                print(format_output_line(DATA_TAB_3, data))

            # TCP
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = struct.unpack(
                    '! H H L L H H H H H H', raw_data[:24])
                # HTTP
                # if src_port == 80 or dest_port == 80:
                #    print(TAB_2 + 'HTTP Data:')
                #    try:
                #        http = HTTP(data)
                #        http_info = str(http.data).split('\n')
                #        for line in http_info:
                #            print(DATA_TAB_3 + str(line))
                #    except:
                #        print(format_output_line(DATA_TAB_3, data))
                # else:
                #    print(TAB_2 + 'TCP Data:')
                #    print(format_output_line(DATA_TAB_3, data))

                print_eth_frame(dest_mac, src_mac, eth_proto, version, header_length, ttl, proto, src, target)
                print_tcp_segment(src_port, dest_port, sequence, acknowledgment)
                print_flag(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin)
                print_data(data)
                if target is edge_ip:
                    print('packet sent to edge!!! done')
                    # HTTP parsing
                    #api = re.match(REG_API, data)
                    #if api is not None:
                    #    # Get Docker Container List
                    #    script = get_call_result("sudo docker ps -a | grep Existed")
                    #    container_list = get_container_list(script)
                    #    # Select Docker Container
                    #    selected_container = container_list[0]
                    #    # Get Docker Layer
                    #    selected_container_layer = get_container_layer(selected_container)
                    #    # Copy Minio to Container File System
                    #    change_container_src(minio_conn, selected_container_layer, api)
                    #    # Restart Docker
                    #    get_call_result("sudo time docker restart " + selected_container)
                    #    # Return Packet
                if target in core_ip_list:
                    print('packet sent to core!!! check')

            # UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_seg(data)
            #                print(TAB_1 + 'UDP Segment:')
            #                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

            # Other IPv4
#            else:
#                print(TAB_1 + 'Other IPv4 Data:')
#                print(format_output_line(DATA_TAB_2, data))

#        else:
#            print('Ethernet Data:')
#            print(format_output_line(DATA_TAB_1, data))


def get_container_layer(selected_container):
    inspect = get_call_result("sudo docker inspect " + selected_container + "|grep Upper")
    return re.match(REG_DIR, str(inspect))


def get_object_data(minio_conn, api):
    response = minio_conn.get_object('src', api)
    data = response.data
    response.close()
    response.release_conn()
    return data


def change_container_src(minio_conn, selected_container_layer, api):
    src = 'var/lib/docker/overlay2/' + selected_container_layer + '/diff/usr/src/app/hello.py'
    data = get_object_data(minio_conn, api)
    f = open(src)
    f.write(data)
    f.close()


def add_dnat_rules(edge_address, core_ip_list, core_port_list):
    match_field = get_all_dnat_rules()
    for core_ip in core_ip_list:
        if core_ip not in match_field:
            # DNAT Function
            chain = iptc.Chain(iptc.Table('nat'), 'PREROUTING')
            # print(chain)

            rule = iptc.Rule()
            rule.protocol = 'tcp'
            # print("rule.dst: %s" % rule.dst)
            # print("Core IP: %s" % core_ip)
            # rule.in_interface = 'eth1'
            rule.dst = core_ip
            # print("rule.dst: %s" % rule.dst)

            match = rule.create_match('tcp')
            #match.dport = core_port_list[core_ip.index()]
            # print("Core port: %s" % core_port)

            target = rule.create_target('DNAT')
            target.to_destination = edge_address
            # print("ec_service_ip: %s" % ec_service_ip_and_port)

            result = chain.insert_rule(rule)
            print("== Routing rule is updated(Core->Edge)")
            print("== The rule: %s" % str(iptc.easy.decode_iptc_rule(rule)))

            prerouting_rules = get_call_result("iptables -nL PREROUTING -t nat")
            print("== All dnat rules")
            print(prerouting_rules.decode('utf-8'))


# def add_snat_rules(ec_service_ip_and_port):
#     match_field = get_all_snat_rules()
#     for edge_service in ec_service_ip_and_port:
#         if edge_service not in match_field:
#             # DNAT Function
#             chain = iptc.Chain(iptc.Table('nat'), 'POSTROUTING')
#             # print(chain)
# 
#             rule = iptc.Rule()
#             rule.protocol = 'tcp'
#             # print("rule.dst: %s" % rule.dst)
#             # print("Core IP: %s" % core_ip)
#             # rule.in_interface = 'eth1'
#             rule.out_interface = 'docker0'
#             target = iptc.Target(rule, "MASQUERADE")
#             # print("rule.dst: %s" % rule.dst)
#             #target.to_ports ="1234"
#             rule.target = target
#             result = chain.insert_rule(rule)
#             print("== Routing rule is updated(Edge->User)")
#             print("== The rule: %s" % str(iptc.easy.decode_iptc_rule(rule)))
# 
#             postrouting_rules = get_call_result("iptables -nL POSTROUTING -t nat")
#             print("== All snat rules")
#             print(postrouting_rules.decode('utf-8'))


def get_container_list(script):
    container_list = []
    containers = script.split("\n")[1:]
    # print("service Table: %s" % st)
    for i in containers:
        if len(i.strip()) > 0:
            x = i.split()
            container_list.append(x[0])
            print("== Container: %s" % x[0])
    return container_list


def get_service_table():
    core_ip = []
    core_port = []
    core_address = []
    f = open("STable.txt")
    service_table = f.read()
    f.close()
    st = service_table.split("\n")[1:]
    # print("service Table: %s" % st)
    for i in st:
        if len(i.strip()) > 0:
            x = i.split()
            core_ip.append(x[1])
            core_port.append(x[3])
            core_address.append(x[1] + ':' + x[3])
            print("== Core IP: %s" % x[1])
            print("== Core port: %s" % x[3])
    return core_ip, core_port, core_address


def get_edge_table():
    # Parsing the Edge service
    f = open("EdgeInfo.txt")
    edge_table = f.read()
    f.close()
    et = edge_table.split("\n")[1:]
    # print("service Table: %s" % st)
    for i in et:
        if len(i.strip()) > 0:
            x = i.split()
            edge_ip = x[1]
            edge_port = x[2]
            edge_adress = x[1]+':'+x[2]
            print("== Edge IP: %s" % x[1])
            print("== Edge port: %s" % x[2])
    return edge_ip, edge_port, edge_adress


def get_all_dnat_rules():
    # DNAT rule Check
    # all_dnat_rules = get_call_result("iptables -L PREROUTING -t nat")
    all_dnat_rules = get_call_result("iptables -nL PREROUTING -t nat")
    # print(type(all_dnat_rules))
    # print(all_dnat_rules)
    parsed_dnat_rules = all_dnat_rules.split(b'\n')[2:]
    print(str(parsed_dnat_rules))
    return str(parsed_dnat_rules)


def get_all_snat_rules():
    # DNAT rule Check
    # all_dnat_rules = get_call_result("iptables -L PREROUTING -t nat")
    all_snat_rules = get_call_result("iptables -nL POSTROUTING -t nat")
    # print(type(all_dnat_rules))
    # print(all_dnat_rules)
    parsed_snat_rules = all_snat_rules.split(b'\n')[2:]
    print(str(parsed_snat_rules))
    return str(parsed_snat_rules)


def get_call_result(args):
    fd_popen = subprocess.Popen(args.split(), stdout=subprocess.PIPE).stdout
    data = fd_popen.read().strip()
    fd_popen.close()
    return data


# Unpack Ethernet Frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

    # Format MAC Address


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr


# Unpack IPv4 Packets Recieved
def ipv4_Packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]


# Returns Formatted IP Address
def ipv4(addr):
    return '.'.join(map(str, addr))


# Unpacks for any ICMP Packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# Unpacks for any TCP Packet
def tcp_seg(data):
    (src_port, destination_port, sequence, acknowledgenment, offset_reserved_flag) = struct.unpack('! H H L L H',
                                                                                                   data[:14])
    offset = (offset_reserved_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 32) >> 4
    flag_psh = (offset_reserved_flag & 32) >> 3
    flag_rst = (offset_reserved_flag & 32) >> 2
    flag_syn = (offset_reserved_flag & 32) >> 1
    flag_fin = (offset_reserved_flag & 32) >> 1

    return src_port, destination_port, sequence, acknowledgenment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# Unpacks for any UDP Packet
def udp_seg(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# Formats the output line
def format_output_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        # string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        string = ''.join('{:02x}'.format(byte) for byte in string)
        string = string.encode('utf-8')
        if size % 2:
            size -= 1
            return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def connect_minio():
    f = open("minio.json")
    dump = json.load(f)
    f.close()
    host = dump['host']
    access_key = dump['access_key']
    secret_key = dump['secret_key']
    secure = dump['secure']

    return minio.Minio(host, access_key=access_key, secret_key=secret_key, secure=secure)


def print_eth_frame(dest_mac, src_mac, eth_proto, version, header_length, ttl, proto, src, target):
    print('\n Ethernet Frame: ')
    print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
    print(TAB_1 + "IPV4 Packet:")
    print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
    print(TAB_3 + 'protocol: {}, Source: {}, Target: {}'.format(proto, src, target))


def print_tcp_segment(src_port, dest_port, sequence, acknowledgment):
    print(TAB_1 + 'TCP Segment:')
    print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
    print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))


def print_flag(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin):
    print(TAB_2 + 'Flags:')
    print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
    print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))


def print_data(data):
    print(TAB_2 + 'Data:')
    print(TAB_3 + str(len(data)))
    print(TAB_3 + str(data))


main()

