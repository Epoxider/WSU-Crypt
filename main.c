#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

struct TValues {
    unsigned short t0;
    unsigned short t1;
};

unsigned short TValues G(unsigned short w, short round) {

}

void funcF(unsigned short r0, unsigned short r1, short round) {

    struct TValues tvals;
    tvals.t0 = G(r0, round);
    tvals.t1 = G(r1, round);
    //unsigned short t0 = G(r0, round);
    //unsigned short t1 = G(r0, round);

}

void whitening(unsigned char* block, unsigned char * keyPtr) {
    unsigned short w0 = ( ((unsigned short) block[0]) << 8) + block[1];
    unsigned short w1 = ( ((unsigned short) block[2]) << 8) + block[3];
    unsigned short w2 = ( ((unsigned short) block[4]) << 8) + block[5];
    unsigned short w3 = ( ((unsigned short) block[6]) << 8) + block[7];

    unsigned short k0 = ( ((unsigned short) keyPtr[0]) << 8) + keyPtr[1];
    unsigned short k1 = ( ((unsigned short) keyPtr[2]) << 8) + keyPtr[3];
    unsigned short k2 = ( ((unsigned short) keyPtr[4]) << 8) + keyPtr[5];
    unsigned short k3 = ( ((unsigned short) keyPtr[6]) << 8) + keyPtr[7];

    unsigned short r0 = w0^k0;
    unsigned short r1 = w1^k1;
    unsigned short r2 = w2^k2;
    unsigned short r3 = w3^k3;
}

void encrypt(unsigned char * block, unsigned char * keyPtr) {
    short round = 0;

    //whitening(block, keyPtr);
    unsigned short w0 = ( ((unsigned short) block[0]) << 8) + block[1];
    unsigned short w1 = ( ((unsigned short) block[2]) << 8) + block[3];
    unsigned short w2 = ( ((unsigned short) block[4]) << 8) + block[5];
    unsigned short w3 = ( ((unsigned short) block[6]) << 8) + block[7];

    unsigned short k0 = ( ((unsigned short) keyPtr[0]) << 8) + keyPtr[1];
    unsigned short k1 = ( ((unsigned short) keyPtr[2]) << 8) + keyPtr[3];
    unsigned short k2 = ( ((unsigned short) keyPtr[4]) << 8) + keyPtr[5];
    unsigned short k3 = ( ((unsigned short) keyPtr[6]) << 8) + keyPtr[7];

    unsigned short r0 = w0^k0;
    unsigned short r1 = w1^k1;
    unsigned short r2 = w2^k2;
    unsigned short r3 = w3^k3;

    funcF(r0, r1, round);
}

void decrypt() {
    
}

int main(int argc, char* argv[]) {
	FILE *keyFilePtr, *inputFilePtr, *outputFilePtr;
    unsigned char * keyPtr, block[9];
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
    keyPtr = (unsigned char *) malloc(keySize * sizeof(unsigned char));
    if (keyPtr == NULL) {
        printf("could not allocate key file");
        exit(1);
    }
    readSize = fread(keyPtr, 1, keySize, keyFilePtr);
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
        encrypt(block, keyPtr);

    }

    free(keyPtr);
    keyPtr = NULL;
    fclose(inputFilePtr);
	exit(0);
}