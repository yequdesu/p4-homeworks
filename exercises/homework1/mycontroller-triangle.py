#!/usr/bin/env python3
"""
P4Runtime Controller for ECN (Explicit Congestion Notification) monitoring
"""

import argparse
import grpc
import os
import struct
import sys
from time import sleep
from typing import Dict, List, Tuple, Any

# Import P4Runtime lib from parent utils dir
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper


class SwitchConfig:
    """Configuration for switch connections"""
    SWITCHES = [
        {'name': 's1', 'address': '127.0.0.1:50051', 'device_id': 0},
        {'name': 's2', 'address': '127.0.0.1:50052', 'device_id': 1},
        {'name': 's3', 'address': '127.0.0.1:50053', 'device_id': 2}
    ]


class PacketParser:
    """Utility class for parsing packet headers"""
    
    # Binary format specifications for packet headers
    ETH_HEADER_FORMAT = "!6s6sH"  # Ethernet header: dst_mac(6), src_mac(6), ethertype(2)
    CPU_HEADER_FORMAT = "!B"      # CPU header: ECN value(1)
    
    def __init__(self):
        self.eth_header_length = struct.calcsize(self.ETH_HEADER_FORMAT)
        self.cpu_header_offset = self.eth_header_length
    
    def extract_ecn_value(self, packet_data: bytes) -> int:
        """Extract ECN value from packet data"""
        try:
            cpu_header = packet_data[self.cpu_header_offset:self.cpu_header_offset + 1]
            return struct.unpack(self.CPU_HEADER_FORMAT, cpu_header)[0]
        except (struct.error, IndexError) as e:
            print(f"Error parsing packet: {e}")
            return 0


class TableRuleWriter:
    """Helper class for writing table rules to switches"""
    
    @staticmethod
    def write_ipv4_lpm_rules(p4info_helper, switch, match_fields: List, action_params: Dict[str, Any]) -> None:
        """Write IPv4 LPM table entries"""
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={"hdr.ipv4.dstAddr": match_fields},
            action_name="MyIngress.ipv4_forward",
            action_params=action_params
        )
        switch.WriteTableEntry(table_entry)
    
    @staticmethod
    def write_ecn_check_rules(p4info_helper, switch, action_params: Dict[str, Any]) -> None:
        """Write ECN check table entries as default action"""
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyEgress.check_ecn",
            action_name="MyEgress.mark_ecn",
            action_params=action_params,
            default_action=True
        )
        switch.WriteTableEntry(table_entry)
    
    @staticmethod
    def write_clone_rules(p4info_helper, switch, clone_session_id: int, replicas: List[Dict]) -> None:
        """Write clone session entries"""
        session_entry = p4info_helper.buildCloneSessionEntry(
            clone_session_id=clone_session_id,
            replicas=replicas
        )
        switch.WritePREEntry(session_entry)


class SwitchManager:
    """Manages switch connections and operations"""
    
    def __init__(self, p4info_helper, bmv2_file_path: str):
        self.p4info_helper = p4info_helper
        self.bmv2_file_path = bmv2_file_path
        self.switches = {}
        self.packet_parser = PacketParser()
    
    def initialize_switches(self) -> None:
        """Initialize all switch connections and set up forwarding pipeline"""
        for switch_config in SwitchConfig.SWITCHES:
            self._create_switch_connection(switch_config)
        
        # Establish controller as master and install P4 program
        for switch in self.switches.values():
            switch.MasterArbitrationUpdate()
            switch.SetForwardingPipelineConfig(
                p4info=self.p4info_helper.p4info,
                bmv2_json_file_path=self.bmv2_file_path
            )
    
    def _create_switch_connection(self, config: Dict) -> None:
        """Create a switch connection with logging"""
        proto_dump_file = f"logs/{config['name']}-p4runtime-requests.txt"
        self.switches[config['name']] = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=config['name'],
            address=config['address'],
            device_id=config['device_id'],
            proto_dump_file=proto_dump_file
        )
    
    def configure_routing_tables(self, ecn_threshold: int) -> None:
        """Configure routing and ECN tables on all switches"""
        self._configure_ipv4_rules()
        self._configure_ecn_rules(ecn_threshold)
        self._configure_clone_sessions()
    
    def _configure_ipv4_rules(self) -> None:
        """Configure IPv4 LPM routing rules"""
        # Switch s1 routing rules
        s1_rules = [
            (["10.0.1.1", 32], {"dstAddr": "08:00:00:00:01:01", "port": 2}),
            (["10.0.1.11", 32], {"dstAddr": "08:00:00:00:01:11", "port": 1}),
            (["10.0.2.0", 24], {"dstAddr": "08:00:00:00:02:00", "port": 3}),
            (["10.0.3.0", 24], {"dstAddr": "08:00:00:00:03:00", "port": 4})
        ]
        
        # Switch s2 routing rules
        s2_rules = [
            (["10.0.2.2", 32], {"dstAddr": "08:00:00:00:02:02", "port": 2}),
            (["10.0.2.22", 32], {"dstAddr": "08:00:00:00:02:22", "port": 1}),
            (["10.0.1.0", 24], {"dstAddr": "08:00:00:00:01:00", "port": 3}),
            (["10.0.3.0", 24], {"dstAddr": "08:00:00:00:03:00", "port": 4})
        ]
        
        # Switch s3 routing rules
        s3_rules = [
            (["10.0.3.3", 32], {"dstAddr": "08:00:00:00:03:03", "port": 1}),
            (["10.0.1.0", 24], {"dstAddr": "08:00:00:00:01:00", "port": 2}),
            (["10.0.2.0", 24], {"dstAddr": "08:00:00:00:02:00", "port": 3})
        ]
        
        # Apply rules to respective switches
        for match_fields, action_params in s1_rules:
            TableRuleWriter.write_ipv4_lpm_rules(
                self.p4info_helper, self.switches['s1'], match_fields, action_params
            )
        
        for match_fields, action_params in s2_rules:
            TableRuleWriter.write_ipv4_lpm_rules(
                self.p4info_helper, self.switches['s2'], match_fields, action_params
            )
        
        for match_fields, action_params in s3_rules:
            TableRuleWriter.write_ipv4_lpm_rules(
                self.p4info_helper, self.switches['s3'], match_fields, action_params
            )
    
    def _configure_ecn_rules(self, ecn_threshold: int) -> None:
        """Configure ECN monitoring rules"""
        for switch in self.switches.values():
            TableRuleWriter.write_ecn_check_rules(
                self.p4info_helper, switch, {"ecn_threshold": ecn_threshold}
            )
    
    def _configure_clone_sessions(self) -> None:
        """Configure packet cloning sessions for monitoring"""
        for switch in self.switches.values():
            TableRuleWriter.write_clone_rules(
                self.p4info_helper, switch, 100, [{"egress_port": 252, "instance": 1}]
            )
    
    def monitor_congestion(self) -> None:
        """Monitor network congestion by processing switch responses"""
        print('\nMonitoring network congestion...')
        try:
            while True:
                sleep(1)
                print('.', end='', flush=True)
                self._process_switch_responses()
        except KeyboardInterrupt:
            print("\nShutting down monitoring.")
    
    def _process_switch_responses(self) -> None:
        """Process responses from all switches"""
        for switch in self.switches.values():
            self._fetch_and_process_responses(switch)
    
    def _fetch_and_process_responses(self, switch) -> None:
        """Fetch and process responses from a single switch"""
        try:
            for response in switch.stream_msg_resp:
                if response.WhichOneof("update") == "packet":
                    self._handle_packet_response(response.packet.payload)
        except grpc.RpcError:
            # Gracefully handle gRPC errors during response processing
            pass
    
    def _handle_packet_response(self, packet_data: bytes) -> None:
        """Handle incoming packet and check for congestion"""
        ecn_value = self.packet_parser.extract_ecn_value(packet_data)
        print(f"\nECN value: {ecn_value}")
        
        if ecn_value == 3:
            print('⚠️  Congestion detected!')


def validate_file_paths(p4info_path: str, bmv2_json_path: str) -> None:
    """Validate that required files exist"""
    if not os.path.exists(p4info_path):
        raise FileNotFoundError(f"p4info file not found: {p4info_path}")
    if not os.path.exists(bmv2_json_path):
        raise FileNotFoundError(f"BMv2 JSON file not found: {bmv2_json_path}")


def get_ecn_threshold() -> int:
    """Get ECN threshold from user input"""
    try:
        threshold = input("Please input the threshold of the queue: ")
        return int(threshold)
    except ValueError:
        print("Invalid input. Using default threshold of 10.")
        return 10


def main(p4info_file_path: str, bmv2_file_path: str) -> None:
    """Main controller function"""
    validate_file_paths(p4info_file_path, bmv2_file_path)
    
    # Initialize P4Runtime helper
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    
    try:
        # Set up switch manager
        switch_manager = SwitchManager(p4info_helper, bmv2_file_path)
        switch_manager.initialize_switches()
        
        # Get configuration and set up rules
        ecn_threshold = get_ecn_threshold()
        switch_manager.configure_routing_tables(ecn_threshold)
        
        # Start monitoring
        switch_manager.monitor_congestion()
        
    except grpc.RpcError as e:
        printGrpcError(e)
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        ShutdownAllSwitchConnections()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='P4Runtime Controller for ECN Monitoring',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        '--p4info',
        help='p4info proto in text format from p4c',
        type=str,
        default='./build/ecn.p4.p4info.txtpb'
    )
    
    parser.add_argument(
        '--bmv2-json',
        help='BMv2 JSON file from p4c',
        type=str,
        default='./build/ecn.json'
    )
    
    args = parser.parse_args()
    
    try:
        main(args.p4info, args.bmv2_json)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Have you run 'make' to build the required files?")
        sys.exit(1)
