#!/usr/bin/env python3

import argparse

from scapy.all import *
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSClientHello

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-i', '--interface', type=str, dest='interface', default='eth0',
                    help='interface to use')
parser.add_argument('-c', '--count', type=int, dest='count', default=1000,
                    help='number of packets to send, 0 means send forever')
parser.add_argument('-f', '--filename', type=str, dest='filename', default=f'{sys.argv[0]}.pcap',
                    help='filename to save pcap')

parser.description = """\
This is a Python program to sniff TLS client hello messages for passive os fingerprinting.
"""
args = parser.parse_args()


def write_pcap():
    try:
        print(f'Starting sniffer for {args.count} packets')

        packets = sniff(iface=args.interface,
                        count=args.count,
                        prn=lambda x: x.summary(),
                        # just 'client hello'
                        lfilter=lambda x: scapy.layers.tls.handshake.TLSClientHello in x)
                        # TLS only, but _all_ tls
                        # lfilter=lambda x: TLS in x)

        # write out a pcap
        wrpcap(args.filename, packets)

    except KeyboardInterrupt:
        sys.exit(0)


def read_pcap():
    # this will be all:
    # scapy.layers.tls.handshake.TLSClientHello
    # mostly this should extract fields we care about and turn the data from each packet into a 'fingerprint'
    pass


def main():
    write_pcap()
    read_pcap()


if __name__ == '__main__':
    main()
