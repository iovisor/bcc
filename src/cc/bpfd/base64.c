/*
 * Base64 Encoding/Decoding Library
 *
 * Author: freecode http://freecode-freecode.blogspot.com/
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/**
* characters used for Base64 encoding
*/
const char *BASE64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
* encode three bytes using base64 (RFC 3548)
*
* @param triple three bytes that should be encoded
* @param result buffer of four characters where the result is stored
*/
void _base64_encode_triple(unsigned char triple[3], char result[4]) {
  int tripleValue, i;

  tripleValue = triple[0];
  tripleValue *= 256;
  tripleValue += triple[1];
  tripleValue *= 256;
  tripleValue += triple[2];

  for (i = 0; i < 4; i++) {
    result[3 - i] = BASE64_CHARS[tripleValue % 64];
    tripleValue /= 64;
  }
}

/**
* encode an array of bytes using Base64 (RFC 3548)
*
* @param source the source buffer
* @param sourcelen the length of the source buffer
* @param target the target buffer
* @param targetlen the length of the target buffer
* @return 1 on success, 0 otherwise
*/
int base64_encode(unsigned char *source, size_t sourcelen, char *target,
                  size_t targetlen) {
  /* check if the result will fit in the target buffer */
  if ((sourcelen + 2) / 3 * 4 > targetlen - 1)
    return 0;

  /* encode all full triples */
  while (sourcelen >= 3) {
    _base64_encode_triple(source, target);
    sourcelen -= 3;
    source += 3;
    target += 4;
  }

  /* encode the last one or two characters */
  if (sourcelen > 0) {
    unsigned char temp[3];
    memset(temp, 0, sizeof(temp));
    memcpy(temp, source, sourcelen);
    _base64_encode_triple(temp, target);
    target[3] = '=';
    if (sourcelen == 1)
      target[2] = '=';

    target += 4;
  }

  /* terminate the string */
  target[0] = 0;

  return 1;
}

/**
* determine the value of a base64 encoding character
*
* @param base64char the character of which the value is searched
* @return the value in case of success (0-63), -1 on failure
*/
int _base64_char_value(char base64char) {
  if (base64char >= 'A' && base64char <= 'Z')
    return base64char - 'A';
  if (base64char >= 'a' && base64char <= 'z')
    return base64char - 'a' + 26;
  if (base64char >= '0' && base64char <= '9')
    return base64char - '0' + 2 * 26;
  if (base64char == '+')
    return 2 * 26 + 10;
  if (base64char == '/')
    return 2 * 26 + 11;
  return -1;
}

/**
* decode a 4 char base64 encoded byte triple
*
* @param quadruple the 4 characters that should be decoded
* @param result the decoded data
* @return lenth of the result (1, 2 or 3), 0 on failure
*/
int _base64_decode_triple(char quadruple[4], unsigned char *result) {
  int i, triple_value, bytes_to_decode = 3, only_equals_yet = 1;
  int char_value[4];

  for (i = 0; i < 4; i++)
    char_value[i] = _base64_char_value(quadruple[i]);

  /* check if the characters are valid */
  for (i = 3; i >= 0; i--) {
    if (char_value[i] < 0) {
      if (only_equals_yet && quadruple[i] == '=') {
        /* we will ignore this character anyway, make it something
        * that does not break our calculations */
        char_value[i] = 0;
        bytes_to_decode--;
        continue;
      }
      return 0;
    }
    /* after we got a real character, no other '=' are allowed anymore */
    only_equals_yet = 0;
  }

  /* if we got "====" as input, bytes_to_decode is -1 */
  if (bytes_to_decode < 0)
    bytes_to_decode = 0;

  /* make one big value out of the partial values */
  triple_value = char_value[0];
  triple_value *= 64;
  triple_value += char_value[1];
  triple_value *= 64;
  triple_value += char_value[2];
  triple_value *= 64;
  triple_value += char_value[3];

  /* break the big value into bytes */
  for (i = bytes_to_decode; i < 3; i++)
    triple_value /= 256;
  for (i = bytes_to_decode - 1; i >= 0; i--) {
    result[i] = triple_value % 256;
    triple_value /= 256;
  }

  return bytes_to_decode;
}

/**
* decode base64 encoded data
*
* @param source the encoded data (zero terminated)
* @param target pointer to the target buffer
* @param targetlen length of the target buffer
* @return length of converted data on success, -1 otherwise
*/
size_t base64_decode(char *source, unsigned char *target, size_t targetlen) {
  char *src, *tmpptr;
  char quadruple[4], tmpresult[3];
  int i;
  int tmplen = 3;
  size_t converted = 0;

  /* concatinate '===' to the source to handle unpadded base64 data */
  src = (char *)malloc(strlen(source) + 5);
  if (src == NULL)
    return -1;
  strcpy(src, source);
  strcat(src, "====");
  tmpptr = src;

  /* convert as long as we get a full result */
  while (tmplen == 3) {
    /* get 4 characters to convert */
    for (i = 0; i < 4; i++) {
      /* skip invalid characters - we won't reach the end */
      while (*tmpptr != '=' && _base64_char_value(*tmpptr) < 0)
        tmpptr++;

      quadruple[i] = *(tmpptr++);
    }

    /* convert the characters */
    tmplen = _base64_decode_triple(quadruple, (unsigned char *)tmpresult);

    /* check if the fit in the result buffer */
    if (targetlen < tmplen) {
      free(src);
      return -1;
    }

    /* put the partial result in the result buffer */
    memcpy(target, tmpresult, tmplen);
    target += tmplen;
    targetlen -= tmplen;
    converted += tmplen;
  }

  free(src);
  return converted;
}

void test_base64(char *file) {
  struct stat st;
  char *fileout, *encoded, *filebuf;
  size_t size;
  int ret;
  FILE *fp;
  char *target;

  stat(file, &st);
  size = st.st_size;

  fileout = (char *)malloc(strlen(file) + 1 + 4);
  fileout[0] = 0;
  strcat(fileout, file);
  strcat(fileout, ".b64dec");

  printf("Encoding and then decoding %s into %s, filesize is %d\n", file,
         fileout, (int)size);

  encoded = (char *)malloc((size * 4) + 1);
  encoded[(size * 4)] = 0;

  filebuf = (char *)malloc(size);
  fp = fopen(file, "rb");
  fread(filebuf, size, 1, fp);

  ret = base64_encode((unsigned char *)filebuf, size, encoded, size * 4);

  printf("encoded len: %d\n", (int)strlen(encoded));

  printf("encoded stat: %s\n", encoded);

  target = (char *)malloc(size);

  ret = base64_decode(encoded, (unsigned char*)target, size);

  fp = fopen(fileout, "wb");

  printf("fp=%p ret=%d fileout=%s\n", (void *)fp, ret, fileout);

  fwrite(target, size, 1, fp);

  fclose(fp);
}
