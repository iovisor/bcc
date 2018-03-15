int base64_encode(unsigned char *source, size_t sourcelen, char *target,
                  size_t targetlen);
size_t base64_decode(char *source, unsigned char *target, size_t targetlen);
void test_base64(char *file);
