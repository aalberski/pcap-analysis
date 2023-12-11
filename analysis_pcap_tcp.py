# Name: Adam Alberski
# ID: 112890087
# Date: 3/2/2022

import socket
import dpkt
import datetime

from dpkt.compat import compat_ord


def main():
    # Manual user input to decide what pcap file (in the same directory) shall be inspected by the program
    # If not a valid file, returns an error and tries again
    while True:
        try:
            file_name = input('Enter file name: ')
            file = open(file_name, 'rb')
            break
        except FileNotFoundError:
            print('File not found, please try again')
        else:
            print('Error, please try again')
    pcap = dpkt.pcap.Reader(file)

    # Hierarchy of lists in ascending order to hold objects of packets, transactions, and flow
    packets = []
    transactions = []
    flows = []

    # ---------------------------------------------------Part A---------------------------------------------------#

    # Iterates through pcap file and inducts packets to a list
    for num, (ts, buff) in enumerate(pcap):
        eth = dpkt.ethernet.Ethernet(buff)
        # Skip if not an IP
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        # Skip if not a TCP transaction
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue
        tcp = ip.data
        # Obtains a list of associated flags
        flags = check_flags(tcp)
        # Creates a packet object for the current instance
        packets.append(Packet(num, eth, ts, flags))
    file.close()

    # Iterates through packets to create transactions between matching SYN or FIN packets
    for x in packets:
        # If SYN packet, append with SYN flag
        if 'SYN' in x.flags and 'ACK' not in x.flags:
            for y in packets:
                if 'SYN' in y.flags:
                    if x.check(y) and y.check(x):
                        transactions.append(Transaction(x, y, 'SYN'))
        # If FIN packet, append with FIN flag
        if 'FIN' in x.flags and 'PUSH' in x.flags:
            for y in packets:
                if 'FIN' in y.flags:
                    if x.check(y) and y.check(x):
                        transactions.append(Transaction(x, y, 'FIN'))

    count = 0
    # Finds transactions that match between SYN and FYN values and adds them to a flow
    for x in transactions:
        if x.flag == 'SYN':
            for y in transactions:
                # If source/destination port and addresses match up respectively
                if x.check(y) and x.flag != y.flag:
                    count += 1
                    flows.append(Flow(x, y, count))

    # Part A.b
    # For each flow, this loop iterates through the list of packets to find the first two transactions based on if
    # the packet's source port matches the destination port of the response SYN packet in the flow, and then calculates
    # the throughput between the starting and finishing packets
    for flow in flows:
        # Handles first two transactions
        for x in packets:
            # X is used to receive the first, if ports match up and the packet appears later chronologically
            if x.sport() == flow.start.response.dport() and x.num > flow.start.response.num:
                break
        for y in packets:
            if x.check(y) and 'SYN' not in y.flags and 'PUSH' not in y.flags:
                flow.first_two.append(Transaction(x, y, 'ACK'))
                break
        for z in packets:
            # Z is used to receive the second, making sure it succeeds the first transaction by starting from x's index
            if z.sport() == flow.start.response.dport() and z.num > x.num and 'PUSH' not in z.flags:
                for y in packets:
                    if x.check(y) and 'SYN' not in y.flags and 'PUSH' not in y.flags:
                        flow.first_two.append(Transaction(z, y, 'ACK'))
                        break
                break

        # Part A.c
        # Handles measuring throughput and related elements
        for a in packets:
            # If source/destination port of current packet match with the starting packet of the flow
            if a.sport() == flow.start.send.sport() or a.dport() == flow.start.send.sport():
                flow.packet_count += 1
                if a.flags and all(elem == 'ACK' for elem in a.flags):
                    flow.total_length += len(a.tcp)

        # Calculate difference between time of beginning and ending packet to get total time taken
        flow.total_time = flow.end.response.ts - flow.start.send.ts

        # ---------------------------------------------------Part B---------------------------------------------------#

        # Part B.1
        # RTT is calculated from the time it takes between sending a packet and receiving a response
        RTT = flow.start.response.ts - flow.start.send.ts
        start = flow.start.response.num
        i = flow.start.response.num + 1
        # While there is enough room in the congestion list (max of 3)
        # and the index of the packet doesn't go out of bounds of the flow
        while len(flow.congestion) <= 2 and i < flow.end.response.num:
            count = 0
            while packets[i].ts - packets[start].ts < RTT:
                # Only add count to congestion window if ports match up
                if packets[i].sport() == flow.start.send.sport():
                    count += 1
                i += 1
            flow.congestion.append(count)
            start = i

        # Part B.2
        # for x in packets[flow.start.response.num: flow.end.send.num]:
        #     for y in packets[flow.start.response.num: flow.end.send.num]:
        #         if False:
        #             flow.dupes += 1
        #             print(flow.dupes)

    # Prints all necessary output
    for flow in flows:
        flow.print()


# Object to hold packet information
class Packet:
    def __init__(self, num, eth, ts, flags):
        self.num = num
        self.eth = eth
        self.ts = ts
        self.time = str(datetime.datetime.utcfromtimestamp(ts))
        self.flags = flags
        self.ip = eth.data
        self.tcp = self.ip.data
        self.connected = None

    # Returns source port
    def sport(self):
        return self.tcp.sport

    # Returns destination port
    def dport(self):
        return self.tcp.dport

    # Returns source address
    def src(self):
        return socket.inet_ntoa(self.ip.src)

    # Returns destination address
    def dst(self):
        return socket.inet_ntoa(self.ip.dst)

    # Checks to see if this and another packet have matching ports and addresses
    def check(self, other):
        if self.src() == other.dst() and self.dst() == other.src() and self.sport() == other.dport() and self.dport() == other.sport():
            self.connected = other
            return True
        else:
            return False

    # Prints out source/destination ports and addresses for use in part a.a
    def print(self):
        print('%0s %16s %12s %16s %12s %8s %4s %8s %4s' % (
            '|', 'SRC IP', '|', 'DST IP', '|', 'sport', '|', 'dport', '|'))
        print('+', ''.ljust(85, '-'), '+')
        print('%0s %20s %8s %20s %8s %8s %4s %8s %4s' % (
            '|', self.src(), '|', self.dst(), '|', self.sport(), '|', self.dport(), '|'))


# Object to hold transaction information
class Transaction:
    def __init__(self, send, response, flag):
        self.send = send
        self.response = response
        self.flag = flag
        self.connected = None

    # Checks to see if this and another transaction are part of the same flow as the respective starts and ends
    def check(self, other):
        if self.send.sport() == other.send.sport():
            self.connected = other
            return True
        else:
            return False

    # Prints out source and destination addresses, sequence and ack numbers, as well as window size and timestamp
    # for each pack in the transaction
    def print(self):
        print('%0s %16s %4s %16s %4s %14s %4s %17s %8s %11s %11s %29s %4s' %
              ('|', self.send.src(), '|', self.send.dst(), '|', self.send.tcp.seq, '|', self.send.tcp.ack, '|',
               self.send.tcp.win, '|', self.send.time, '|'))
        print('%0s %16s %4s %16s %4s %14s %4s %17s %8s %11s %11s %29s %4s' %
              ('|', self.response.src(), '|', self.response.dst(), '|', self.response.tcp.seq, '|',
               self.response.tcp.ack, '|', self.response.tcp.win, '|', self.response.time, '|'))


# Object to hold flow information
class Flow:
    def __init__(self, start, end, num):
        self.start = start
        self.end = end
        self.num = num
        self.first_two = []
        self.packet_count = 0
        self.total_length = 0
        self.total_time = None
        self.congestion = []
        self.dupes = 0
        self.timeouts = 0

    # Prints out all information formatted for questions in Part A and Part B
    def print(self):
        # Part A.a
        print('\nFlow', self.num, 'General Statistics')
        print('+', ''.ljust(85, '-'), '+')
        self.start.send.print()
        print('+', ''.ljust(85, '-'), '+')
        # Part A.b
        print('First Two Transactions After The TCP Connection ')
        print('+', ''.ljust(147, '-'), '+')
        print('%0s %12s %8s %12s %8s %16s %2s %23s %2s %20s %2s %16s %17s' % (
            '|', 'Src IP', '|', 'Dst IP', '|', 'Sequence Number', '|', 'Acknowledgement Number', '|',
            'Receive Window Size', '|', 'Time', '|'))
        print('+', ''.ljust(147, '-'), '+')
        for x in self.first_two:
            x.print()
            print('+', ''.ljust(147, '-'), '+')
        # Part A.c
        print('Sender Throughput')
        print('+', ''.ljust(92, '-'), '+')
        print('%0s %14s %2s %16s %2s %18s %8s %21s %6s' % (
            '|', 'Total Packets', '|', 'Total Data Sent', '|', 'Time Period', '|', 'Bytes Per Second', '|'))
        print('+', ''.ljust(92, '-'), '+')
        print('%0s %10s %6s %12s %6s %21s %5s %22s %5s' % (
            '|', self.packet_count, '|', self.total_length, '|', self.total_time, '|',
            (self.total_length / self.total_time), '|'))
        print('+', ''.ljust(92, '-'), '+')
        # Part B.1
        print('First Three Congestion Window Sizes')
        print('+', ''.ljust(42, '-'), '+')
        temp = '|'
        for i in self.congestion:
            temp += ('%8s %6s' % (str(i), '|'))
        print(temp)
        print('+', ''.ljust(42, '-'), '+')
        # Part B.2
        print('Number Of Times Retransmission Occurred')
        print('+', ''.ljust(42, '-'), '+')
        print('%0s %15s %5s %14s %7s' % ('|', 'Duplicates', '|', 'Timeouts', '|'))
        print('+', ''.ljust(42, '-'), '+')
        print('%0s %10s %10s %11s %10s' % ('|', self.dupes, '|', self.timeouts, '|'))
        print('+', ''.ljust(42, '-'), '+')


# Checks for any associated flags and returns them as a list
def check_flags(tcp):
    flags = []
    if tcp.flags & dpkt.tcp.TH_FIN:
        flags.append('FIN')
    if tcp.flags & dpkt.tcp.TH_SYN:
        flags.append('SYN')
    if tcp.flags & dpkt.tcp.TH_RST:
        flags.append('RST')
    if tcp.flags & dpkt.tcp.TH_PUSH:
        flags.append('PUSH')
    if tcp.flags & dpkt.tcp.TH_ACK:
        flags.append('ACK')
    if tcp.flags & dpkt.tcp.TH_URG:
        flags.append('URG')
    if tcp.flags & dpkt.tcp.TH_ECE:
        flags.append('ECE')
    if tcp.flags & dpkt.tcp.TH_CWR:
        flags.append('CWR')
    if tcp.flags & dpkt.tcp.TH_NS:
        flags.append('NS')
    return flags


if __name__ == '__main__':
    main()
