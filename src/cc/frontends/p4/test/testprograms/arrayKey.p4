header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

parser start {
    return parse_ethernet;
}

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return ingress;
}

action nop() 
{}

table routing {
   reads {
      ethernet.dstAddr: exact;
   }
   actions { nop; }
   size : 512;
}

control ingress
{
    apply(routing);
}