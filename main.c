#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <math.h>

ftable[] = {0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3,0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9,0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28,0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53,0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2,0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8,0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90,0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76,0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d,0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18,0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4,0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40,0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5,0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2,0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8,0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac,0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46};

unsigned char FTable(unsigned char val) {
    unsigned char row = (val >> 4) & 0x0f;
    unsigned char col = val &0x0f;
    return ftable[row*16 + col];
}

unsigned char K_Encrypt(unsigned long x, unsigned long * keyPtr) {
    *keyPtr = (*keyPtr << 1)|(*keyPtr >> 63);
    unsigned long whichByte = x%8;
    unsigned long result = (*keyPtr >> (whichByte * 8)) & 0xff; 
    return (unsigned char) (result & 0xff);
}

int K_Decrypt(unsigned long subRound, unsigned long * keyPtr) {
    unsigned long key = &keyPtr;

    return subRound;
}

unsigned short G_Encrypt(unsigned short w, unsigned long round, unsigned char subKey1,unsigned char subKey2,unsigned char subKey3,unsigned char subKey4) {
    unsigned char g1 = (w >> 8) &0xff;
    unsigned char g2 = w & 0xff;
    unsigned char g3, g4, g5, g6;

    g3 = FTable(g2^subKey1)^g1;
    g4 = FTable(g3^subKey2)^g2;
    g5 = FTable(g4^subKey3)^g3;
    g6 = FTable(g5^subKey4)^g4;

    return ((unsigned short) (g5)) << 8 | (unsigned short) g6;

}

unsigned short funcF(unsigned short r0, unsigned short r1, unsigned long round, unsigned long * keyPtr) {
    unsigned char gk1, gk2, gk3, gk4, gk5, gk6, gk7, gk8, fk9, fk10, fk11, fk12;

    //first 4 subkeys from 1st call from G
    gk1 = K_Encrypt(4*round, keyPtr);
    gk2 = K_Encrypt(4*round+1, keyPtr);
    gk3 = K_Encrypt(4*round+2, keyPtr);
    gk4 = K_Encrypt(4*round+3, keyPtr);

    gk5 = K_Encrypt(4*round, keyPtr);
    gk6 = K_Encrypt(4*round+1, keyPtr);
    gk7 = K_Encrypt(4*round+2, keyPtr);
    gk8 = K_Encrypt(4*round+3, keyPtr);

    fk9 = K_Encrypt(4*round, keyPtr);
    fk10 = K_Encrypt(4*round+1, keyPtr);
    fk11 = K_Encrypt(4*round+2, keyPtr);
    fk12 = K_Encrypt(4*round+3, keyPtr);

    unsigned short t0 = G_Encrypt(r0, gk1, gk2, gk3, gk4, round);
    unsigned short t1 = G_Encrypt(r1, gk5, gk6, gk7, gk8, round);

    unsigned short *f0 = (t0 + 2*t1 + ((unsigned short) (fk9) << 8 | (unsigned short) fk10)) % 65536; //2^16
    unsigned short *f1 = (2*t0 + t1 + ((unsigned short) (fk11) << 8 | (unsigned short) fk12)) % 65536;

    return f0

}

void encrypt(unsigned char * block, unsigned long * keyPtr) {
    int i = 0;
    unsigned long round = 0;

    //whitening
    unsigned short w0 = ( ((unsigned short) block[0]& 0xff) << 8) + block[1]& 0xff;
    unsigned short w1 = ( ((unsigned short) block[2]& 0xff) << 8) + block[3]& 0xff;
    unsigned short w2 = ( ((unsigned short) block[4]& 0xff) << 8) + block[5]& 0xff;
    unsigned short w3 = ( ((unsigned short) block[6]& 0xff) << 8) + block[7]& 0xff;

    unsigned short k0 = ( ((unsigned short) keyPtr[0]& 0xff) << 8) + keyPtr[1]& 0xff;
    unsigned short k1 = ( ((unsigned short) keyPtr[2]& 0xff) << 8) + keyPtr[3]& 0xff;
    unsigned short k2 = ( ((unsigned short) keyPtr[4]& 0xff) << 8) + keyPtr[5]& 0xff;
    unsigned short k3 = ( ((unsigned short) keyPtr[6]& 0xff) << 8) + keyPtr[7]& 0xff;

    unsigned short r0 = w0^k0;
    unsigned short r1 = w1^k1;
    unsigned short r2 = w2^k2;
    unsigned short r3 = w3^k3;

    for(i; i <= 15; i++) {
        funcF(r0, r1, round, keyPtr);
        round++;
    }
}

void decrypt() {
    
}

int main(int argc, char* argv[]) {
	FILE *keyFilePtr, *inputFilePtr, *outputFilePtr;
    unsigned char block[9];
    unsigned long key;
    int i, keySize, readSize;
    bool isEndcode;

    if (strcmp(argv[1], "-e") == 0) {
        isEndcode = true;
    } else {
        isEndcode = false;
    }

    //Key Code
    keyFilePtr = fopen(argv[2], "r");
    //finding size of key file
    fseek(keyFilePtr, 0L, SEEK_END);
    keySize = ftell(keyFilePtr);
    fseek(keyFilePtr, 0L, SEEK_SET);
    if (keySize > 8) {
        keySize = 8;
    } else if (keySize < 8) {
        printf("key file is not 64 bits");
        exit(1);
    }

    readSize = fread(&key, 1, keySize, keyFilePtr);
    if (readSize != keySize) {
        printf("Mismatch in key file size");
        exit(1);
    }
    fclose(keyFilePtr);


    //input code
    inputFilePtr = fopen(argv[3], "r");
    readSize = fread(block, 1, 8, inputFilePtr);
    while (readSize > 0) {
        if (readSize < 8) {
            for (i = readSize; i < 8; i++) {
                block[i] = ' '; //space
            }
        }
        readSize = fread(block, 1, 8, inputFilePtr);
        encrypt(block, &key);

    }

    fclose(inputFilePtr);
	exit(0);
}