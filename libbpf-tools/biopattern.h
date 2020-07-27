#ifndef __BIOPATTERN_H
#define __BIOPATTERN_H

struct counter {
	__u64 last_sector;
	__u64 bytes;
	__u32 sequential;
	__u32 random;
};

#endif /* __BIOPATTERN_H */
