#/bin/sh

tfile=$(mktemp /tmp/test_reallocarray_XXXXXXXX.c)
ofile=${tfile%.c}.o

cat > $tfile <<EOL
#define _GNU_SOURCE
#include <stdlib.h>

int main(void)
{
	return !!reallocarray(NULL, 1, 1);
}
EOL

gcc $tfile -o $ofile >& /dev/null
if [ $? -ne 0 ]; then echo "FAIL"; fi
/bin/rm -f $tfile $ofile
