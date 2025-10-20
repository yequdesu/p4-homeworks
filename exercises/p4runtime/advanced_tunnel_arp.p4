/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_MYTUNNEL      = 0x1212;
const bit<16> TYPE_IPV4          = 0x800;
const bit<32> MAX_TUNNEL_ID      = 1 << 16;

const bit<16> TYPE_ARP           = 0x0806;

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header myTunnel_t {
    bit<16> proto_id;
    bit<16> dst_id;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header arp_t {
    bit<16> htype; // format of hardware address
    bit<16> ptype; // format of protocol address
    bit<8>  hlen; // length of hardware address
    bit<8>  plen; // length of protocol address
    bit<16> oper; // request or reply operation
    macAddr_t sha; //src mac address
    ip4Addr_t spa; //src ip address
    macAddr_t tha; // dst mac address
    ip4Addr_t tpa; // dst ip address
}


struct metadata {
    ip4Addr_t    dst_ipv4; // dst ip
}

struct headers {
    ethernet_t   ethernet;
    arp_t        arp;
    myTunnel_t   myTunnel;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_MYTUNNEL: parse_myTunnel;
            TYPE_IPV4    : parse_ipv4;
            TYPE_ARP     : parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        meta.dst_ipv4 = hdr.arp.tpa;  //save dst ip
        transition accept;
    }
    
    state parse_myTunnel {
        packet.extract(hdr.myTunnel);
        transition select(hdr.myTunnel.proto_id) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    counter(MAX_TUNNEL_ID, CounterType.packets_and_bytes) ingressTunnelCounter;
    counter(MAX_TUNNEL_ID, CounterType.packets_and_bytes) egressTunnelCounter;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    /*Switches add the myTunnel header to an IP packet upon ingress to the network 
    then remove the myTunnel header as the packet leaves to the network to an end host*/
    
    action myTunnel_ingress(bit<16> dst_id) {
        hdr.myTunnel.setValid();
        hdr.myTunnel.dst_id = dst_id;
        hdr.myTunnel.proto_id = hdr.ethernet.etherType;
        hdr.ethernet.etherType = TYPE_MYTUNNEL;
        ingressTunnelCounter.count((bit<32>) hdr.myTunnel.dst_id);
    }
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            myTunnel_ingress;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action myTunnel_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action myTunnel_egress(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ethernet.etherType = hdr.myTunnel.proto_id;
        egressTunnelCounter.count((bit<32>) hdr.myTunnel.dst_id);
        hdr.myTunnel.setInvalid();
    }

    table myTunnel_exact {
        key = {
            hdr.myTunnel.dst_id: exact;
        }
        actions = {
            myTunnel_forward;
            myTunnel_egress;
            drop;
        }
        size = 1024;
        default_action = drop();
    }
    
    action send_arp_reply(macAddr_t macAddr) {
        hdr.ethernet.dstAddr = hdr.arp.sha;      // Ethernet target address = ARP source MAC address
        hdr.ethernet.srcAddr = macAddr; 	  // Ethernet source address = the action argument macAddr

        hdr.arp.oper         = ARP_OPER_REPLY;   // modify the ARP packet type to reply
        // set the fields to reply
        hdr.arp.tha          = hdr.arp.sha;      // ARP target MAC address = ARP source MAC address
        hdr.arp.tpa          = hdr.arp.spa;      // ARP target IP address = ARP source IP address
        hdr.arp.sha          = macAddr;          // ARP source MAC address = the action argument macAddr
        hdr.arp.spa          = meta.dst_ipv4;           // ARP source IP address = ARP target IP address

        standard_metadata.egress_spec = standard_metadata.ingress_port; // return to the port it comes from
    }


    table arp_match {
        key = {
            hdr.arp.oper           : exact;
            hdr.arp.tpa            : lpm;
        }
        actions = {
            send_arp_reply;
            drop;
        }
        const default_action = drop();
    }

    apply {
        if(hdr.ethernet.etherType == TYPE_ARP) {
            arp_match.apply();
        }
        else {
            if (hdr.ipv4.isValid() && !hdr.myTunnel.isValid()) {
                // Process only non-tunneled IPv4 packets and add tunnel header
                ipv4_lpm.apply();
            }

            if (hdr.myTunnel.isValid()) {
                // Process all tunneled packets.
                myTunnel_exact.apply();
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.myTunnel);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
