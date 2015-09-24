// Routes a packet to an interface based on its IPv4 address
// Maintains a set of counters on the routing table

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

parser start {
    return parse_ethernet;
}

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        0x800 : parse_ipv4;
        default: ingress;
    }
}

action nop() 
{}

action forward(port)
{
   modify_field(standard_metadata.egress_port, port);
}

header ipv4_t ipv4;

parser parse_ipv4 {
    extract(ipv4);
    return ingress;
}

table routing {
   reads {
      ipv4.dstAddr: exact;
   }
   actions { nop; forward; }
   size : 512;
}

counter cnt {
   type: bytes;
   direct: routing;
}

control ingress
{
    apply(routing);
}