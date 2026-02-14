#!/usr/bin/env python3
"""
PCAP to CIC Format CSV Converter
Converts Wireshark-generated PCAP files to CIC (Canadian Institute for Cybersecurity) format CSV
"""

import sys
import csv
from collections import defaultdict
from datetime import datetime
import argparse

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
    from scapy.layers.inet import TCP, UDP
except ImportError:
    print("Error: scapy is required. Install with: pip install scapy")
    sys.exit(1)

import statistics


class FlowFeatures:
    """Calculate CIC-style flow features"""
    
    def __init__(self, flow_id):
        self.flow_id = flow_id
        self.packets = []
        self.fwd_packets = []
        self.bwd_packets = []
        self.start_time = None
        self.end_time = None
        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        self.fwd_urg_flags = 0
        self.bwd_urg_flags = 0
        self.fin_flags = 0
        self.syn_flags = 0
        self.rst_flags = 0
        self.psh_flags = 0
        self.ack_flags = 0
        self.urg_flags = 0
        self.ece_flags = 0
        self.cwr_flags = 0
        self.fwd_header_length = 0
        self.bwd_header_length = 0
        self.fwd_bulk_bytes = []
        self.bwd_bulk_bytes = []
        self.fwd_bulk_packets = []
        self.bwd_bulk_packets = []
        self.fwd_bulk_duration = []
        self.bwd_bulk_duration = []
        
    def add_packet(self, packet, timestamp, direction):
        """Add packet to flow (direction: 'fwd' or 'bwd')"""
        if self.start_time is None:
            self.start_time = timestamp
        self.end_time = timestamp
        
        # Calculate header length
        header_length = 0
        if IP in packet:
            header_length += packet[IP].ihl * 4  # IP header length in bytes
        if TCP in packet:
            header_length += packet[TCP].dataofs * 4  # TCP header length in bytes
        elif UDP in packet:
            header_length += 8  # UDP header is always 8 bytes
        
        packet_info = {
            'timestamp': timestamp,
            'length': len(packet),
            'header_length': header_length,
            'direction': direction
        }
        
        self.packets.append(packet_info)
        
        if direction == 'fwd':
            self.fwd_packets.append(packet_info)
            self.fwd_header_length += header_length
        else:
            self.bwd_packets.append(packet_info)
            self.bwd_header_length += header_length
        
        # Extract TCP flags if present
        if TCP in packet:
            tcp_layer = packet[TCP]
            flags = tcp_layer.flags
            
            if 'F' in str(flags):
                self.fin_flags += 1
            if 'S' in str(flags):
                self.syn_flags += 1
            if 'R' in str(flags):
                self.rst_flags += 1
            if 'P' in str(flags):
                self.psh_flags += 1
                if direction == 'fwd':
                    self.fwd_psh_flags += 1
                else:
                    self.bwd_psh_flags += 1
            if 'A' in str(flags):
                self.ack_flags += 1
            if 'U' in str(flags):
                self.urg_flags += 1
                if direction == 'fwd':
                    self.fwd_urg_flags += 1
                else:
                    self.bwd_urg_flags += 1
            if 'E' in str(flags):
                self.ece_flags += 1
            if 'C' in str(flags):
                self.cwr_flags += 1
    
    def calculate_features(self):
        """Calculate all CIC flow features"""
        features = {}
        
        # Basic flow identifiers
        parts = self.flow_id.split('-')
        features['Flow ID'] = self.flow_id
        features['Source IP'] = parts[0]
        features['Source Port'] = int(parts[1])
        features['Destination IP'] = parts[2]
        features['Destination Port'] = int(parts[3])
        features['Protocol'] = int(parts[4])
        
        # Timestamp
        features['Timestamp'] = datetime.fromtimestamp(self.start_time).strftime('%d/%m/%Y %H:%M:%S')
        
        # Flow duration
        duration = (self.end_time - self.start_time) * 1000000  # microseconds
        features['Flow Duration'] = int(duration)
        
        # Total packets and bytes
        features['Total Fwd Packets'] = len(self.fwd_packets)
        features['Total Backward Packets'] = len(self.bwd_packets)
        
        fwd_lengths = [p['length'] for p in self.fwd_packets]
        bwd_lengths = [p['length'] for p in self.bwd_packets]
        all_lengths = [p['length'] for p in self.packets]
        
        features['Total Length of Fwd Packets'] = sum(fwd_lengths) if fwd_lengths else 0
        features['Total Length of Bwd Packets'] = sum(bwd_lengths) if bwd_lengths else 0
        
        # Packet length statistics - Forward
        if fwd_lengths:
            features['Fwd Packet Length Max'] = max(fwd_lengths)
            features['Fwd Packet Length Min'] = min(fwd_lengths)
            features['Fwd Packet Length Mean'] = statistics.mean(fwd_lengths)
            features['Fwd Packet Length Std'] = statistics.stdev(fwd_lengths) if len(fwd_lengths) > 1 else 0
        else:
            features['Fwd Packet Length Max'] = 0
            features['Fwd Packet Length Min'] = 0
            features['Fwd Packet Length Mean'] = 0
            features['Fwd Packet Length Std'] = 0
        
        # Packet length statistics - Backward
        if bwd_lengths:
            features['Bwd Packet Length Max'] = max(bwd_lengths)
            features['Bwd Packet Length Min'] = min(bwd_lengths)
            features['Bwd Packet Length Mean'] = statistics.mean(bwd_lengths)
            features['Bwd Packet Length Std'] = statistics.stdev(bwd_lengths) if len(bwd_lengths) > 1 else 0
        else:
            features['Bwd Packet Length Max'] = 0
            features['Bwd Packet Length Min'] = 0
            features['Bwd Packet Length Mean'] = 0
            features['Bwd Packet Length Std'] = 0
        
        # Flow bytes/s and packets/s
        duration_sec = (self.end_time - self.start_time) if self.end_time > self.start_time else 1
        features['Flow Bytes/s'] = (features['Total Length of Fwd Packets'] + features['Total Length of Bwd Packets']) / duration_sec
        features['Flow Packets/s'] = len(self.packets) / duration_sec
        
        # Flow IAT statistics
        flow_iat = []
        for i in range(1, len(self.packets)):
            iat = (self.packets[i]['timestamp'] - self.packets[i-1]['timestamp']) * 1000000
            flow_iat.append(iat)
        
        if flow_iat:
            features['Flow IAT Mean'] = statistics.mean(flow_iat)
            features['Flow IAT Std'] = statistics.stdev(flow_iat) if len(flow_iat) > 1 else 0
            features['Flow IAT Max'] = max(flow_iat)
            features['Flow IAT Min'] = min(flow_iat)
        else:
            features['Flow IAT Mean'] = 0
            features['Flow IAT Std'] = 0
            features['Flow IAT Max'] = 0
            features['Flow IAT Min'] = 0
        
        # Inter-arrival time statistics - Forward
        fwd_iat = []
        for i in range(1, len(self.fwd_packets)):
            iat = (self.fwd_packets[i]['timestamp'] - self.fwd_packets[i-1]['timestamp']) * 1000000
            fwd_iat.append(iat)
        
        if fwd_iat:
            features['Fwd IAT Total'] = sum(fwd_iat)
            features['Fwd IAT Mean'] = statistics.mean(fwd_iat)
            features['Fwd IAT Std'] = statistics.stdev(fwd_iat) if len(fwd_iat) > 1 else 0
            features['Fwd IAT Max'] = max(fwd_iat)
            features['Fwd IAT Min'] = min(fwd_iat)
        else:
            features['Fwd IAT Total'] = 0
            features['Fwd IAT Mean'] = 0
            features['Fwd IAT Std'] = 0
            features['Fwd IAT Max'] = 0
            features['Fwd IAT Min'] = 0
        
        # Inter-arrival time statistics - Backward
        bwd_iat = []
        for i in range(1, len(self.bwd_packets)):
            iat = (self.bwd_packets[i]['timestamp'] - self.bwd_packets[i-1]['timestamp']) * 1000000
            bwd_iat.append(iat)
        
        if bwd_iat:
            features['Bwd IAT Total'] = sum(bwd_iat)
            features['Bwd IAT Mean'] = statistics.mean(bwd_iat)
            features['Bwd IAT Std'] = statistics.stdev(bwd_iat) if len(bwd_iat) > 1 else 0
            features['Bwd IAT Max'] = max(bwd_iat)
            features['Bwd IAT Min'] = min(bwd_iat)
        else:
            features['Bwd IAT Total'] = 0
            features['Bwd IAT Mean'] = 0
            features['Bwd IAT Std'] = 0
            features['Bwd IAT Max'] = 0
            features['Bwd IAT Min'] = 0
        
        # PSH and URG flag counts
        features['Fwd PSH Flags'] = self.fwd_psh_flags
        features['Bwd PSH Flags'] = self.bwd_psh_flags
        features['Fwd URG Flags'] = self.fwd_urg_flags
        features['Bwd URG Flags'] = self.bwd_urg_flags
        
        # Header lengths
        features['Fwd Header Length'] = self.fwd_header_length
        features['Bwd Header Length'] = self.bwd_header_length
        
        # Packets per second
        features['Fwd Packets/s'] = len(self.fwd_packets) / duration_sec if duration_sec > 0 else 0
        features['Bwd Packets/s'] = len(self.bwd_packets) / duration_sec if duration_sec > 0 else 0
        
        # Packet length statistics - Overall
        if all_lengths:
            features['Min Packet Length'] = min(all_lengths)
            features['Max Packet Length'] = max(all_lengths)
            features['Packet Length Mean'] = statistics.mean(all_lengths)
            features['Packet Length Std'] = statistics.stdev(all_lengths) if len(all_lengths) > 1 else 0
            features['Packet Length Variance'] = statistics.variance(all_lengths) if len(all_lengths) > 1 else 0
        else:
            features['Min Packet Length'] = 0
            features['Max Packet Length'] = 0
            features['Packet Length Mean'] = 0
            features['Packet Length Std'] = 0
            features['Packet Length Variance'] = 0
        
        # Flag counts
        features['FIN Flag Count'] = self.fin_flags
        features['SYN Flag Count'] = self.syn_flags
        features['RST Flag Count'] = self.rst_flags
        features['PSH Flag Count'] = self.psh_flags
        features['ACK Flag Count'] = self.ack_flags
        features['URG Flag Count'] = self.urg_flags
        features['CWE Flag Count'] = self.cwr_flags  # Note: CWE in CIC, CWR in TCP
        features['ECE Flag Count'] = self.ece_flags
        
        # Down/Up Ratio
        if features['Total Fwd Packets'] > 0:
            features['Down/Up Ratio'] = features['Total Backward Packets'] / features['Total Fwd Packets']
        else:
            features['Down/Up Ratio'] = 0
        
        # Average packet size
        total_packets = len(self.packets)
        if total_packets > 0:
            features['Average Packet Size'] = (features['Total Length of Fwd Packets'] + features['Total Length of Bwd Packets']) / total_packets
        else:
            features['Average Packet Size'] = 0
        
        # Forward and backward averages
        if features['Total Fwd Packets'] > 0:
            features['Avg Fwd Segment Size'] = features['Total Length of Fwd Packets'] / features['Total Fwd Packets']
        else:
            features['Avg Fwd Segment Size'] = 0
            
        if features['Total Backward Packets'] > 0:
            features['Avg Bwd Segment Size'] = features['Total Length of Bwd Packets'] / features['Total Backward Packets']
        else:
            features['Avg Bwd Segment Size'] = 0
        
        # Fwd Header Length (redundant but in CIC format)
        features['Fwd Header Length.1'] = features['Fwd Header Length']
        
        # Bulk transfer features (simplified - detecting consecutive packets)
        # Forward bulk
        fwd_bulk_size_total = 0
        fwd_bulk_count = 0
        if len(self.fwd_packets) >= 4:  # Bulk is 4+ consecutive packets
            for i in range(len(self.fwd_packets) - 3):
                bulk_size = sum(self.fwd_packets[j]['length'] for j in range(i, i + 4))
                fwd_bulk_size_total += bulk_size
                fwd_bulk_count += 1
        
        features['Fwd Avg Bytes/Bulk'] = fwd_bulk_size_total / fwd_bulk_count if fwd_bulk_count > 0 else 0
        features['Fwd Avg Packets/Bulk'] = 4 if fwd_bulk_count > 0 else 0
        features['Fwd Avg Bulk Rate'] = fwd_bulk_size_total / duration_sec if duration_sec > 0 and fwd_bulk_count > 0 else 0
        
        # Backward bulk
        bwd_bulk_size_total = 0
        bwd_bulk_count = 0
        if len(self.bwd_packets) >= 4:
            for i in range(len(self.bwd_packets) - 3):
                bulk_size = sum(self.bwd_packets[j]['length'] for j in range(i, i + 4))
                bwd_bulk_size_total += bulk_size
                bwd_bulk_count += 1
        
        features['Bwd Avg Bytes/Bulk'] = bwd_bulk_size_total / bwd_bulk_count if bwd_bulk_count > 0 else 0
        features['Bwd Avg Packets/Bulk'] = 4 if bwd_bulk_count > 0 else 0
        features['Bwd Avg Bulk Rate'] = bwd_bulk_size_total / duration_sec if duration_sec > 0 and bwd_bulk_count > 0 else 0
        
        # Subflow features (simplified - treating entire flow as one subflow)
        features['Subflow Fwd Packets'] = features['Total Fwd Packets']
        features['Subflow Fwd Bytes'] = features['Total Length of Fwd Packets']
        features['Subflow Bwd Packets'] = features['Total Backward Packets']
        features['Subflow Bwd Bytes'] = features['Total Length of Bwd Packets']
        
        # Init_Win bytes (initial window size) - simplified
        features['Init_Win_bytes_forward'] = 0
        features['Init_Win_bytes_backward'] = 0
        
        # Act data packets
        features['act_data_pkt_fwd'] = features['Total Fwd Packets']
        features['min_seg_size_forward'] = features['Fwd Packet Length Min']
        
        # Active/Idle times (simplified - would need more sophisticated analysis)
        features['Active Mean'] = 0
        features['Active Std'] = 0
        features['Active Max'] = 0
        features['Active Min'] = 0
        features['Idle Mean'] = 0
        features['Idle Std'] = 0
        features['Idle Max'] = 0
        features['Idle Min'] = 0
        
        # Label (to be filled by user)
        features['Label'] = 'BENIGN'
        
        return features


def parse_pcap(pcap_file, flow_timeout=120):
    """
    Parse PCAP file and extract flows
    flow_timeout: seconds of inactivity before considering flow ended
    """
    print(f"Reading PCAP file: {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"Total packets read: {len(packets)}")
    
    flows = defaultdict(lambda: FlowFeatures(None))
    
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
        
        # Create flow ID (bidirectional)
        # Use sorted IPs to ensure bidirectional flow grouping
        if (ip_layer.src, sport) < (ip_layer.dst, dport):
            flow_id = f"{ip_layer.src}-{sport}-{ip_layer.dst}-{dport}-{protocol}"
            direction = 'fwd'
        else:
            flow_id = f"{ip_layer.dst}-{dport}-{ip_layer.src}-{sport}-{protocol}"
            direction = 'bwd'
        
        if flows[flow_id].flow_id is None:
            flows[flow_id].flow_id = flow_id
        
        flows[flow_id].add_packet(pkt, timestamp, direction)
    
    print(f"Total flows identified: {len(flows)}")
    return flows


def export_to_csv(flows, output_file):
    """Export flows to CIC format CSV"""
    print(f"Exporting to CSV: {output_file}")
    
    if not flows:
        print("No flows to export!")
        return
    
    # Calculate features for all flows
    flow_features_list = []
    for flow in flows.values():
        features = flow.calculate_features()
        flow_features_list.append(features)
    
    if not flow_features_list:
        print("No features calculated!")
        return
    
    # Write to CSV
    fieldnames = flow_features_list[0].keys()
    
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flow_features_list)
    
    print(f"Successfully exported {len(flow_features_list)} flows to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Convert PCAP file to CIC format CSV',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s input.pcap output.csv
  %(prog)s capture.pcap -o flows.csv --timeout 60
        """
    )
    
    parser.add_argument('input', help='Input PCAP file')
    parser.add_argument('output', nargs='?', default=None, help='Output CSV file (default: input.csv)')
    parser.add_argument('-o', '--output-file', dest='output', help='Output CSV file')
    parser.add_argument('-t', '--timeout', type=int, default=120,
                        help='Flow timeout in seconds (default: 120)')
    
    args = parser.parse_args()
    
    # Determine output filename
    if args.output is None:
        if args.input.endswith('.pcap'):
            output_file = args.input[:-5] + '.csv'
        else:
            output_file = args.input + '.csv'
    else:
        output_file = args.output
    
    try:
        # Parse PCAP
        flows = parse_pcap(args.input, args.timeout)
        
        # Export to CSV
        export_to_csv(flows, output_file)
        
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