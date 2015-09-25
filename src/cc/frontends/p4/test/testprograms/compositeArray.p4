header_type ethernet_t {
    fields {
        dstAddr : 48;
    }
}

header_type ipv4_t {
    fields {
        srcAddr : 32;
    }
}

parser start {
    return parse_ethernet;
}

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return parse_ipv4;
}

action nop() 
{}

header ipv4_t ipv4;

parser parse_ipv4 {
    extract(ipv4);
    return ingress;
}

table routing {
   reads {
      ethernet.dstAddr: exact;
      ipv4.srcAddr: exact;
   }
   actions { nop; }
   size : 512;
}

control ingress
{
    apply(routing);
}