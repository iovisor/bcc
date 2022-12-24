#ifndef BPF_LICENSE
/* No license defined, using GPL
 * You can define your own BPF_LICENSE in your C code */
#define BPF_LICENSE GPL
#endif
#define ___LICENSE(s) #s
#define __LICENSE(s) ___LICENSE(s)
#define _LICENSE __LICENSE(BPF_LICENSE)

char LICENSE[] SEC("license") = _LICENSE;
