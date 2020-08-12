#include <linux/netdevice.h>
#include <linux/ethtool.h>
#define TRACEPOINT_NET_DEV_START_XMIT 1241
#define TRACEPOINT_NETIF_RECEIVE_SKB_ENTRY 1234
#define GROUPNUMS 5
#define MAXQUEUENUM 1024

// name of specified network interface
struct nameBuf{
    char name[IFNAMSIZ];
};

/**
* This struct is use to compare two strings
* which has a maximum length of IFNAMSIZ (16)
*/
struct strcmp{
    u64 hi;
    u64 lo;
};

// data retrieved in tracepoints
struct Leaf{
    u64 datalen;
    uint pkg;
    // avg = datalen / pkg
    uint size64;
    uint size512;
    uint size2048;
    uint size16384;
    uint size65536;
};

static inline int filter_devname(struct sk_buff* skb);
static void updateData(struct Leaf *data, u64 len);

// array of length 1 for device name
BPF_ARRAY(nameMap, struct nameBuf, 1);
// table for transmit & receive packets
BPF_HASH(TXq, u16, struct Leaf, MAXQUEUENUM);
BPF_HASH(RXq, u16, struct Leaf, MAXQUEUENUM);

TRACEPOINT_PROBE(net, net_dev_start_xmit){
    // ------------- read device name ------------------
    struct sk_buff* skb = (struct sk_buff*)args->skbaddr;
    if(!filter_devname(skb)){
        return 0;
    }

    // --------- update table -----------------------------
    u16 qid = skb->queue_mapping;
    struct Leaf newdata = {};
    __builtin_memset(&newdata, 0, sizeof(newdata));
    struct Leaf *data = TXq.lookup_or_try_init(&qid, &newdata);
    if(!data){
        return 0;
    }
    updateData(data, skb->len);

	return 0;
}

TRACEPOINT_PROBE(net, netif_receive_skb){
    struct sk_buff* skb = (struct sk_buff*)args->skbaddr;
    if(!filter_devname(skb)){
        return 0;
    }

    u16 qid = skb->queue_mapping;
    struct Leaf newdata = {};
    __builtin_memset(&newdata, 0, sizeof(newdata));
    struct Leaf *data = RXq.lookup_or_try_init(&qid, &newdata);
    if(!data){
        return 0;
    }
    updateData(data, skb->len);

    return 0;
}

static inline int filter_devname(struct sk_buff* skb){
    // ------------------- get device name from skb -------------------
    struct strcmp real_devname = {};
    struct net_device *dev;
    bpf_probe_read(&dev, sizeof(skb->dev), ((char *)skb + offsetof(typeof(*skb), dev)));
    bpf_probe_read(&real_devname, IFNAMSIZ, dev->name);

    // -------- read device name from bpf array (set in python) -------
    int key=0;
    struct nameBuf *buf = nameMap.lookup(&key);
    struct strcmp required_devname = {};
    bpf_probe_read(&required_devname, IFNAMSIZ, buf->name);

    // -------- compare -----------------------------------------------
    if(real_devname.hi != required_devname.hi || real_devname.lo != required_devname.lo){
        return 0;
    }

    return 1;
}

static void updateData(struct Leaf *data, u64 len){
    data->datalen += len;
    data->pkg ++;
    if(len / 64 == 0){
        data->size64 ++;
    }
    else if(len / 512 == 0){
        data->size512 ++;
    }
    else if(len / 2048 == 0){
        data->size2048 ++;
    }
    else if(len / 16384 == 0){
        data->size16384 ++;
    }
    else if(len / 65536 == 0){
        data->size65536 ++;
    }
}
