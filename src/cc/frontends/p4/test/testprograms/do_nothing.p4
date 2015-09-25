/* Sample P4 program */
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

action action_0(){
    no_op();
}

table table_0 {
   reads {
      ethernet.etherType : exact;
   }
   actions {
      action_0;
   }
}

control ingress {
    apply(table_0);
}
