#!/usr/bin/env python3

import argparse
import json
import shlex

from scapy.all import *
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-i', '--interface', type=str, dest='interface', default='eth0',
                    help='interface to use')
parser.add_argument('-c', '--count', type=int, dest='count', default=1000,
                    help='number of packets to send, 0 means send forever')
parser.add_argument('-f', '--filename', type=str, dest='filename', default=f'{sys.argv[0]}.pcap',
                    help='filename to save pcap')
parser.add_argument('-d', '--dir', type=str, dest='dir', default='.',
                    help='dir to save ja3 json files')

parser.description = """\
This is a Python program to sniff TLS traffic and parse ja3 signatures from that traffic. Writes ja3 as json files, 
can easily be picked up from a queue dir or shipped to an api endpoint instead.
"""
args = parser.parse_args()


def write_pcap():
    try:
        print(f'Starting sniffer for {args.count} packets')

        packets = sniff(iface=args.interface,
                        count=args.count,
                        prn=lambda x: x.summary(),
                        # just 'client hello'
                        # lfilter=lambda x: scapy.layers.tls.handshake.TLSClientHello in x)
                        # just 'server hello'
                        # lfilter=lambda x: scapy.layers.tls.handshake.TLSServerHello in x)
                        # both hellos
                        # lfilter=lambda x: (TLSClientHello or TLSServerHello) in x)
                        # TLS only, but _all_ tls
                        lfilter=lambda x: TLS in x)

        # write out a pcap
        wrpcap(args.filename, packets)

    except KeyboardInterrupt:
        sys.exit(0)


def get_ja3(ja3s=False):
    '''
    what kind of ja3 do you want?
    :param ja3s:
    :return:
    '''
    cmd = ''
    res = []
    if ja3s:
        cmd = f'./ja3/python/ja3s.py --json {args.filename}'
    else:
        cmd = f'./ja3/python/ja3.py --json {args.filename}'
    res = subprocess.run(shlex.split(cmd), check=True, stdout=subprocess.PIPE)
    if res.returncode == 0:
        return(res.stdout)
    else:
        print(f'could not dump ja3 json!')
        sys.exit(res.returncode)


def main():
    write_pcap()
    # get client hello ja3
    ja3_list = json.loads(get_ja3())
    # get server hello ja3s
    ja3_list.extend(json.loads(get_ja3(ja3s=True)))
    for ja3 in ja3_list:
        # print(f'{type(ja3)} - {ja3}')
        # print(f'{ja3["timestamp"]} - {ja3["source_ip"]}')
        print(ja3)
        # # write to queue or dir or endpoint for more processing

        # build a unique filename
        jsonfname = f'{ja3["source_ip"]}:{ja3["source_port"]}'
        jsonfname += f'-{ja3["destination_ip"]}:{ja3["destination_port"]}'
        jsonfname += f'-{ja3["timestamp"]}-{ja3["ja3_digest"]}.json'
        with open(f'{args.dir}/{jsonfname}', 'w') as outfile:
             outfile.write(json.dumps(ja3, indent=4))


if __name__ == '__main__':
    main()
