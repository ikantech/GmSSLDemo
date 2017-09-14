//
// Created by chuangxin on 2017/9/13.
//

#ifndef MYAPPLICATION2_UTILS_H
#define MYAPPLICATION2_UTILS_H

unsigned char *hex2bin(const char *data, int size, int *outlen);

char *bin2hex(unsigned char *data, int size);

int b64_op(const unsigned char *in, int in_len, char *out, int out_len, int op);

int writeBufToFile(char *file, char *buf);

int readBufFromFile(char *file, char *buf);

int initEcKey(EC_KEY *ec_key,char * path);


#endif //MYAPPLICATION2_UTILS_H
