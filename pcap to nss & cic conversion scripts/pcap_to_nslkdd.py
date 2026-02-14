#!/usr/bin/env python3
"""
PCAP to NSL-KDD Format Converter
Converts Wireshark PCAP files to NSL-KDD format CSV
"""

import sys
import csv
from collections import defaultdict
import argparse

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
except ImportError:
    print("Error: scapy is required. Install with: pip install scapy")
    sys.exit(1)


# Service port mappings
SERVICE_PORTS = {
    20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
    53: 'domain_u', 79: 'finger', 80: 'http', 110: 'pop_3', 111: 'sunrpc',
    113: 'auth', 119: 'nntp', 123: 'ntp_u', 139: 'netbios_ssn',
    143: 'imap4', 443: 'http', 512: 'exec', 513: 'login', 514: 'shell',
    515: 'printer', 3306: 'sql_net', 5432: 'postgres', 8080: 'http_8001'
}

# TCP flags to NSL-KDD flag mapping
def get_connection_flag(packets):
    """Determine connection flag based on TCP flags"""
    if not packets:
        return 'OTH'
    
    has_syn = False
    has_fin = False
    has_rst = False
    has_ack = False
    
    for pkt in packets:
        if TCP in pkt:
            flags = str(pkt[TCP].flags)
            if 'S' in flags:
                has_syn = True
            if 'F' in flags:
                has_fin = True
            if 'R' in flags:
                has_rst = True
            if 'A' in flags:
                has_ack = True
    
    # Determine flag
    if has_rst:
        return 'RSTO'
    elif has_syn and has_fin and has_ack:
        return 'SF'
    elif has_syn and not has_fin:
        return 'S0'
    elif has_syn and has_fin:
        return 'S1'
    elif has_fin:
        return 'FIN'
    else:
        return 'OTH'


class NSLKDDConnection:
    """Represents a connection in NSL-KDD format"""
    
    def __init__(self, src_ip, dst_ip, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.packets = []
        self.start_time = None
        self.end_time = None
        self.src_bytes = 0
        self.dst_bytes = 0
        self.src_packets = 0
        self.dst_packets = 0
        self.service = 'other'
        self.flag = 'OTH'
        
    def add_packet(self, pkt, timestamp):
        """Add packet to connection"""
        if self.start_time is None:
            self.start_time = timestamp
        self.end_time = timestamp
        
        self.packets.append(pkt)
        
        # Determine direction and count bytes
        if IP in pkt:
            packet_size = len(pkt)
            if pkt[IP].src == self.src_ip:
                self.src_bytes += packet_size
                self.src_packets += 1
            else:
                self.dst_bytes += packet_size
                self.dst_packets += 1
        
        # Determine service from destination port
        if TCP in pkt:
            dport = pkt[TCP].dport
            if dport in SERVICE_PORTS:
                self.service = SERVICE_PORTS[dport]
        elif UDP in pkt:
            dport = pkt[UDP].dport
            if dport in SERVICE_PORTS:
                self.service = SERVICE_PORTS[dport]
    
    def get_features(self):
        """Generate NSL-KDD features"""
        features = {}
        
        # Duration
        duration = int((self.end_time - self.start_time)) if self.end_time > self.start_time else 0
        features['duration'] = duration
        
        # Protocol type
        if self.protocol == 6:
            features['protocol_type'] = 'tcp'
        elif self.protocol == 17:
            features['protocol_type'] = 'udp'
        elif self.protocol == 1:
            features['protocol_type'] = 'icmp'
        else:
            features['protocol_type'] = 'other'
        
        # Service
        features['service'] = self.service
        
        # Flag
        features['flag'] = get_connection_flag(self.packets)
        
        # Bytes
        features['src_bytes'] = self.src_bytes
        features['dst_bytes'] = self.dst_bytes
        
        # Land (connection from/to same host/port)
        features['land'] = 0
        
        # Wrong fragment
        features['wrong_fragment'] = 0
        
        # Urgent
        features['urgent'] = 0
        
        # Hot indicators
        features['hot'] = 0
        
        # Failed logins
        features['num_failed_logins'] = 0
        
        # Logged in
        features['logged_in'] = 1 if self.service in ['ftp', 'ssh', 'telnet'] else 0
        
        # Compromised conditions
        features['num_compromised'] = 0
        features['root_shell'] = 0
        features['su_attempted'] = 0
        
        # File operations
        features['num_root'] = 0
        features['num_file_creations'] = 0
        features['num_shells'] = 0
        features['num_access_files'] = 0
        features['num_outbound_cmds'] = 0
        
        # Is host login / Is guest login
        features['is_host_login'] = 0
        features['is_guest_login'] = 0
        
        # Count
        features['count'] = len(self.packets)
        
        # Srv count (connections to same service)
        features['srv_count'] = len(self.packets)
        
        # Error rates (simplified)
        features['serror_rate'] = 0.0
        features['srv_serror_rate'] = 0.0
        features['rerror_rate'] = 0.0
        features['srv_rerror_rate'] = 0.0
        
        # Same srv rate
        features['same_srv_rate'] = 1.0
        features['diff_srv_rate'] = 0.0
        features['srv_diff_host_rate'] = 0.0
        
        # Host-based features (simplified)
        features['dst_host_count'] = 1
        features['dst_host_srv_count'] = 1
        features['dst_host_same_srv_rate'] = 1.0
        features['dst_host_diff_srv_rate'] = 0.0
        features['dst_host_same_src_port_rate'] = 1.0
        features['dst_host_srv_diff_host_rate'] = 0.0
        features['dst_host_serror_rate'] = 0.0
        features['dst_host_srv_serror_rate'] = 0.0
        features['dst_host_rerror_rate'] = 0.0
        features['dst_host_srv_rerror_rate'] = 0.0
        
        # Label (default to normal)
        features['class'] = 'normal'
        
        return features


def parse_pcap(pcap_file):
    """Parse PCAP and extract NSL-KDD format connections"""
    print(f"Reading PCAP file: {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"Total packets read: {len(packets)}")
    
    connections = {}
    
    for pkt in packets:
        if IP not in pkt:
            continue
        
        ip_layer = pkt[IP]
        timestamp = float(pkt.time)
        
        # Determine protocol
        if TCP in pkt:
            protocol = 6
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            protocol = 17
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        elif ICMP in pkt:
            protocol = 1
            sport = 0
            dport = 0
        else:
            continue
        
        # Create connection ID
        conn_id = f"{ip_layer.src}-{ip_layer.dst}-{protocol}"
        
        if conn_id not in connections:
            connections[conn_id] = NSLKDDConnection(ip_layer.src, ip_layer.dst, protocol)
        
        connections[conn_id].add_packet(pkt, timestamp)
    
    print(f"Total connections identified: {len(connections)}")
    return connections


def export_to_csv(connections, output_file):
    """Export connections to NSL-KDD format CSV"""
    print(f"Exporting to CSV: {output_file}")
    
    if not connections:
        print("No connections to export!")
        return
    
    # Generate features for all connections
    records = []
    for conn in connections.values():
        features = conn.get_features()
        records.append(features)
    
    if not records:
        print("No features generated!")
        return
    
    # Define NSL-KDD column order
    columns = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
        'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'class'
    ]
    
    # Write to CSV
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=columns)
        writer.writeheader()
        writer.writerows(records)
    
    print(f"Successfully exported {len(records)} connections to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Convert PCAP file to NSL-KDD format CSV',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pcap_to_nslkdd.py input.pcap output.csv
  python pcap_to_nslkdd.py capture.pcap -o flows.csv
        """
    )
    
    parser.add_argument('input', help='Input PCAP file')
    parser.add_argument('output', nargs='?', default=None, help='Output CSV file')
    parser.add_argument('-o', '--output-file', dest='output', help='Output CSV file')
    
    args = parser.parse_args()
    
    # Determine output filename
    if args.output is None:
        if args.input.endswith('.pcap'):
            output_file = args.input[:-5] + '_nslkdd.csv'
        else:
            output_file = args.input + '_nslkdd.csv'
    else:
        output_file = args.output
    
    try:
        # Parse PCAP
        connections = parse_pcap(args.input)
        
        # Export to CSV
        export_to_csv(connections, output_file)
        
        print("\nConversion complete!")
        print(f"Input:  {args.input}")
        print(f"Output: {output_file}")
        
    except FileNotFoundError:
        print(f"Error: File '{args.input}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
