#!/usr/bin/env python3
import argparse
import grpc
import os
import sys

# Import P4Runtime lib from parent utils dir
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper


class ACLController:
    """Controller for managing ACL switch configurations"""
    
    def __init__(self, p4info_helper, bmv2_file_path):
        self.p4info_helper = p4info_helper
        self.bmv2_file_path = bmv2_file_path
        self.switches = {}
    
    def add_switch(self, name, address, device_id, log_file=None):
        """Add a switch connection"""
        if not log_file:
            log_file = f'logs/{name}-p4runtime-requests.txt'
        
        self.switches[name] = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=name,
            address=address,
            device_id=device_id,
            proto_dump_file=log_file
        )
        return self.switches[name]
    
    def initialize_switches(self):
        """Initialize all switches with master arbitration and pipeline config"""
        for switch in self.switches.values():
            switch.MasterArbitrationUpdate()
            switch.SetForwardingPipelineConfig(
                p4info=self.p4info_helper.p4info,
                bmv2_json_file_path=self.bmv2_file_path
            )
    
    def write_ipv4_lpm_rule(self, switch_name, dst_addr, prefix_len, dst_mac, port):
        """Write IPv4 LPM forwarding rule"""
        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": [dst_addr, prefix_len]
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "dstAddr": dst_mac,
                "port": port
            }
        )
        self.switches[switch_name].WriteTableEntry(table_entry)
    
    def write_acl_ip_rule(self, switch_name, dst_addr, mask, priority):
        """Write ACL IP drop rule"""
        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.acl_ip_t",
            match_fields={
                "hdr.ipv4.dstAddr": [dst_addr, mask]
            },
            action_name="MyIngress.drop",
            priority=priority
        )
        self.switches[switch_name].WriteTableEntry(table_entry)
    
    def write_acl_udp_rule(self, switch_name, dst_port, mask, priority):
        """Write ACL UDP drop rule"""
        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.acl_udp_t",
            match_fields={
                "hdr.udp.dstPort": [dst_port, mask]
            },
            action_name="MyIngress.drop",
            priority=priority
        )
        self.switches[switch_name].WriteTableEntry(table_entry)


def configure_acl_rules(controller):
    """Configure ACL rules for the switch"""
    # IPv4 forwarding rules
    host_configs = [
        ("10.0.1.1", "08:00:00:00:01:01", 1),
        ("10.0.1.2", "08:00:00:00:01:02", 2),
        ("10.0.1.3", "08:00:00:00:01:03", 3),
        ("10.0.1.4", "08:00:00:00:01:04", 4)
    ]
    
    for ip, mac, port in host_configs:
        controller.write_ipv4_lpm_rule('s1', ip, 32, mac, port)
    
    # ACL drop rules
    controller.write_acl_ip_rule('s1', '10.0.1.4', 4294967295, 1)  # Drop all to 10.0.1.4
    controller.write_acl_udp_rule('s1', 80, 65535, 1)  # Drop UDP port 80


def main(p4info_file_path, bmv2_file_path):
    """Main function to setup ACL switch"""
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    
    # Create controller
    controller = ACLController(p4info_helper, bmv2_file_path)
    
    try:
        # Add switch
        controller.add_switch('s1', '127.0.0.1:50051', 0)
        
        # Initialize and configure
        controller.initialize_switches()
        configure_acl_rules(controller)
        
        print("ACL configuration completed successfully!")
        
    except KeyboardInterrupt:
        print("\nShutting down...")
    except grpc.RpcError as e:
        printGrpcError(e)
    finally:
        ShutdownAllSwitchConnections()


def validate_file_paths(p4info_path, bmv2_json_path):
    """Validate that required files exist"""
    if not os.path.exists(p4info_path):
        raise FileNotFoundError(f"P4Info file not found: {p4info_path}")
    if not os.path.exists(bmv2_json_path):
        raise FileNotFoundError(f"BMv2 JSON file not found: {bmv2_json_path}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime ACL Controller')
    parser.add_argument('--p4info', help='p4info proto in text format',
                        type=str, default='./build/acl.p4.p4info.txtpb')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file',
                        type=str, default='./build/acl.json')
    
    args = parser.parse_args()
    
    try:
        validate_file_paths(args.p4info, args.bmv2_json)
        main(args.p4info, args.bmv2_json)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
