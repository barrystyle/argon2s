#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include "argon2.h"

static const size_t INPUT_BYTES = 80;
static const size_t OUTPUT_BYTES = 32;
static const unsigned int DEFAULT_ARGON2_FLAG = 2;

void argon2s(void* input, void* output)
{
        char hashout[32];

        argon2_context context;
        context.out = (uint8_t*)hashout;
        context.outlen = (uint32_t)OUTPUT_BYTES;
        context.pwd = (uint8_t*)input;
        context.pwdlen = (uint32_t)INPUT_BYTES;
        context.salt = (uint8_t *)input;
        context.saltlen = (uint32_t)INPUT_BYTES;
        context.secret = NULL;
        context.secretlen = 0;
        context.ad = NULL;
        context.adlen = 0;
        context.allocate_cbk = NULL;
        context.free_cbk = NULL;
        context.flags = DEFAULT_ARGON2_FLAG;
        context.m_cost = 8192;
        context.lanes = 2;
        context.threads = 1;
        context.t_cost = 2;
        context.version = ARGON2_VERSION_13;
        argon2_ctx( &context, Argon2_d );

        memcpy(output,hashout,32);
}

int main()
{
        uint8_t genesisdata[80] = { 0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1c,0xcc,0xa6,0x6a,
                                    0x44,0xf8,0xbd,0x55,0x45,0xc3,0x16,0x4a,0x3a,0x76,0xda,0x50,0x39,0x53,0x28,0xc9,0x07,0x56,0x33,0x77,
                                    0x5b,0xc4,0xc8,0x79,0x8f,0xd6,0x77,0x2b,0x70,0x0d,0x21,0x5c,0xf0,0xff,0x0f,0x1e,0x00,0x00,0x00,0x00 };
        char inputdata[80];
        char outputhash[32];
        int i;
        uint32_t nonce = 0;
        uint32_t ncount = nonce;

        unsigned int starttimer = time(NULL);

        while (true) {

           ++nonce;

           if(nonce % 4 == 0)
              printf("\r%08x",nonce);

           memcpy(inputdata,genesisdata,76);
           memcpy(inputdata+76,&nonce,4); 
           argon2s((void*)inputdata,(void*)outputhash);
           uint32_t *target = *(uint32_t*)&outputhash[28];

           if (target < 0xfff) {
              printf("\n");
              for (i=0; i<32; i++)
                 printf("%02hhx",outputhash[31-i]);
              printf("\n");
           }

           if ((time(NULL)-starttimer) > 1) {
              uint32_t hashes = nonce - ncount;
              printf("\n\n\n%u hashes/sec\n", hashes);
              ncount = nonce;
              starttimer = time(NULL);
           }
       }
}
