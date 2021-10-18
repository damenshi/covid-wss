#include <iostream>
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include "contact.h"
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#include "sm3.cpp"

#define PUBLICKEYBYTES		        33
#define HASHOUTPUTBYTES                 32

using namespace std;

#ifndef _CONTACT_INFO_
#define _CONTACT_INFO_

typedef struct Contact_info {
	unsigned char *contact_pk;
	unsigned char *contact_id;
	unsigned char *contact_v;
	unsigned char *contact_date;
}contact_info;
#endif

#ifndef _CONTACT_NODE_
#define _CONTACT_NODE_

typedef struct Contact_node {
    Contact_info data;
    struct Contact_node *next;
}contact_node;
#endif

#ifndef _USER_
#define _USER_   
typedef struct User {
    unsigned char *id;
    unsigned char *date;
    unsigned char *pb_key;
    unsigned char *sec_key;
    unsigned char *sig;
	Contact_node *contact;
}user;
#endif

unsigned char *u;
unsigned char *u1;
unsigned char *g;
unsigned char *g1;
unsigned char *g2;
unsigned char *vA;
unsigned char *vB;

int printChar( unsigned char * str, int length)
{
    printf("[");
    int j; 
    for(j=0;j<length;j++){
        printf("%02X",*(str+j));
    }
    printf("]\n");
}

int B_generate_vB_toA(unsigned char * IDA,
                     unsigned char *SKB,
                     pairing_t pairing) {
    sm3_context sm3_ctx;
    // 定义一些参数
    element_t eu, index, one;
    element_t v, div, H3;
    element_t secret_key;

    // 实例化 元素 属于 G1.G2，GT
    element_init_G1(v, pairing);
    element_init_G1(eu, pairing);
    element_init_Zr(one, pairing);
    element_init_Zr(H3, pairing);
    element_init_Zr(secret_key, pairing);
    element_init_Zr(div, pairing);
    element_init_Zr(index, pairing);

    unsigned char H3_byte[HASHOUTPUTBYTES];
    sm3_starts( &sm3_ctx );
    sm3_update( &sm3_ctx, IDA, HASHOUTPUTBYTES);
    sm3_finish( &sm3_ctx, H3_byte);
    element_from_bytes(H3, H3_byte);
    element_from_bytes(secret_key, SKB);
    element_from_bytes(eu, u);
    element_add(div, H3, secret_key);
    element_set1(one);
    element_div(index, one, div);
    element_pow_zn(v, eu, index);
    int n = element_length_in_bytes(v);
    vB = (unsigned char *)malloc(n*sizeof(unsigned char));
    element_to_bytes(vB, v);

    element_clear(v);
    element_clear(eu);
    element_clear(one);
    element_clear(H3);
    element_clear(secret_key);
    element_clear(div);
    element_clear(index);

    return 0;
}

int A_generate_vA_toB(unsigned char * IDB,
                     unsigned char *SKA,
                     pairing_t pairing){
    sm3_context sm3_ctx;
    // 定义一些参数
    element_t eu, index, one, H3;
    element_t v, div;
    element_t secret_key;

    // 实例化 元素 属于 G1.G2，GT
    element_init_G1(v, pairing);
    element_init_G1(eu, pairing);
    element_init_Zr(one, pairing);
    element_init_Zr(H3, pairing);
    element_init_Zr(secret_key, pairing);
    element_init_Zr(div, pairing);
    element_init_Zr(index, pairing);

    unsigned char H3_byte[HASHOUTPUTBYTES];
    sm3_starts( &sm3_ctx );
    sm3_update( &sm3_ctx, IDB, HASHOUTPUTBYTES);
    sm3_finish( &sm3_ctx, H3_byte);
    element_from_bytes(H3, H3_byte);
    element_from_bytes(secret_key, SKA);
    element_from_bytes(eu, u);
    element_add(div, H3, secret_key);
    element_set1(one);
    element_div(index, one, div);
    element_pow_zn(v, eu, index);
    int n = element_length_in_bytes(v);
    vA = (unsigned char *)malloc(n*sizeof(unsigned char));
    element_to_bytes(vA, v);

    element_clear(v);
    element_clear(eu);
    element_clear(one);
    element_clear(H3);
    element_clear(secret_key);
    element_clear(div);
    element_clear(index);

    return 0;
}

int A_vertify_B(unsigned char * PKB,
                    unsigned char * SigB,
                    unsigned char * IDA,
                    pairing_t pairing) {
    sm3_context sm3_ctx;
    
    int flag = 1;
    // 定义一些参数
    element_t eg, eu, H3;
    element_t v, gH, cID, gB;
    element_t public_key;
    element_t temp1, temp2;

    // 实例化 元素 属于 G1.G2，GT
    element_init_G1(v, pairing);
    element_init_G1(eu, pairing);
    element_init_G1(cID, pairing);
    element_init_Zr(H3, pairing);
    element_init_G2(gH, pairing);
    element_init_G2(gB, pairing);
    element_init_G2(eg, pairing);
    element_init_G2(public_key, pairing);
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);

    // printf("\nA vertify B\n");
    element_from_bytes(eg, g);
    element_from_bytes(eu, u);
    element_from_bytes(v, vB);
    element_from_bytes(public_key, PKB);

    //计算gB
    unsigned char H3_byte[HASHOUTPUTBYTES];
    sm3_starts( &sm3_ctx );
    sm3_update( &sm3_ctx, IDA, HASHOUTPUTBYTES);
    sm3_finish( &sm3_ctx, H3_byte);
    // printChar(H3_byte, HASHOUTPUTBYTES);
    element_from_bytes(H3, H3_byte);
    // element_printf("h3 = %B\n", H3);
    element_pow_zn(gH, eg, H3);
    // element_printf("gh = g ^ h3 = %B\n", gH);
    element_mul(gB, gH, public_key);
    // element_printf("gB = g ^ h3 = %B\n", gB);

    //verification part 1
    element_pairing(temp1, v, gB);
    // element_printf("vB = %B\n", v);
    // element_printf("e(vB, g^H3(IDA)*pub_key) = %B\n", temp1);

    //verification part 3
    //should match above
    element_pairing(temp2, eu, eg);
    // element_printf("e(u, g) = %B\n", temp2);

    if (!element_cmp(temp1, temp2)) {
        // printf("signature verifies\n");
        flag = 0;
    } else {
        printf("signature verifies fail\n");
        flag = 1;
    }

    //最后释放元素空间
    element_clear(v);
    element_clear(eu);
    element_clear(public_key);
    element_clear(eg);
    element_clear(cID);
    element_clear(H3);
    element_clear(gH);
    element_clear(gB);
    element_clear(temp1);
    element_clear(temp2);

    return flag;
}

int B_vertify_A(unsigned char * PKA,
                    unsigned char * SigA,
                    unsigned char * IDB,
                    pairing_t pairing) {
    sm3_context sm3_ctx;
    
    int flag = 1;
    // 定义一些参数
    element_t eg, eu, H3;
    element_t v, gH, cID, gA;
    element_t public_key;
    element_t temp1, temp2;
    
    // 实例化 元素 属于 G1.G2，GT
    element_init_G1(v, pairing);
    element_init_G1(eu, pairing);
    element_init_G1(cID, pairing);
    element_init_Zr(H3, pairing);
    element_init_G2(gH, pairing);
    element_init_G2(gA, pairing);
    element_init_G2(eg, pairing);
    element_init_G2(public_key, pairing);
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);

    // printf("\nB vertify A\n");
    element_from_bytes(eg, g);
    element_from_bytes(eu, u);
    element_from_bytes(public_key, PKA);
    element_from_bytes(v, vA);

    // element_printf("vA = %B\n", v);
    // element_printf("eu = %B\n", eu);
    // element_printf("eg = %B\n", eg);
    // element_printf("public_key = %B\n", public_key);

    // element_from_hash(eg, g, HASHOUTPUTBYTES);
    // element_from_hash(eu, u, HASHOUTPUTBYTES);
    // element_from_hash(public_key, PKA, HASHOUTPUTBYTES);
    // element_from_hash(v, vA, HASHOUTPUTBYTES);

    //计算gB
    unsigned char H3_byte[HASHOUTPUTBYTES];
    sm3_starts( &sm3_ctx );
    sm3_update( &sm3_ctx, IDB, HASHOUTPUTBYTES);
    sm3_finish( &sm3_ctx, H3_byte);
    // printChar(H3_byte, HASHOUTPUTBYTES);
    element_from_bytes(H3, H3_byte);
    // element_printf("h3 = %B\n", H3);
    element_pow_zn(gH, eg, H3);
    // element_printf("gh = g ^ h3 = %B\n", gH);
    element_mul(gA, gH, public_key);
    // element_printf("gB = g ^ h3 = %B\n", gA);

    //verification part 1
    element_pairing(temp1, v, gA);
    // element_printf("e(vA, g^H3(IDB)*pub_key) = %B\n", temp1);

    //verification part 3
    //should match above
    element_pairing(temp2, eu, eg);
    // element_printf("e(u, g) = %B\n", temp2);

    if (!element_cmp(temp1, temp2)) {
        // printf("signature verifies\n");
        flag = 0;
    } else {
        printf("signature verifies fail\n");
        flag = 1;
    }

    //最后释放元素空间
    element_clear(v);
    element_clear(eu);
    element_clear(public_key);
    element_clear(eg);
    element_clear(cID);
    element_clear(H3);
    element_clear(gH);
    element_clear(gA);
    element_clear(temp1);
    element_clear(temp2);

    return flag;
}


//A first message

int A_Pseudo_Public_generate(unsigned char * PKB, unsigned char * h, unsigned char * B_hat , unsigned char * s , pairing_t pairing)
{
  
    int flag = 1;
    // 定义一些参数
    element_t eg, eu, es;
    element_t eh, ePKB, eB_hat;
    element_t temp1, temp2;

    // 实例化 元素 属于 G1.G2，GT
 
    element_init_G1(eu, pairing);
  
    element_init_Zr(es, pairing);

    element_init_G2(eg, pairing);
    element_init_G2(ePKB, pairing);
    element_init_GT(eB_hat, pairing);
    element_init_GT(eh, pairing);
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);

    // printf("\nA_Pseudo-Public_generate\n");
    element_from_bytes(eg, g);
    element_from_bytes(eu, u);
    element_from_bytes(ePKB, PKB);

    //计算 h
    element_pairing(temp1, eu, eg);
    element_pow_zn(eh, temp1, es);
 
    element_to_bytes(h, eh);

    //计算B_hat
    element_pairing(temp2, eu, ePKB);
    element_pow_zn(eB_hat, temp2, es);
 
    element_to_bytes(B_hat, eB_hat);
    element_to_bytes(s, es);
 
    //最后释放元素空间
    element_clear(es);
    element_clear(eu);
    element_clear(eg);
    element_clear(eh);
     element_clear(ePKB);
     element_clear(eB_hat);
    element_clear(temp1);
    element_clear(temp2);

    return flag;
 
}



//A second message

int A_Proof_generate(unsigned char * PKB, unsigned char * s, unsigned char * h,   unsigned char * IDA, int idlength,  unsigned char * B_hat,
                      unsigned char * A1, unsigned char * A2,   unsigned char * C,  unsigned char *proof, pairing_t pairing)
{
    sm3_context sm3_ctx;
    
    int flag = 1;
    int n, n1,n4;
    // 定义一些参数
    element_t eg, eg1, eg2, eu, eu1 ;
    element_t s1, s2, t, cz;
    element_t r1, r2, r3, r4, r5, r6, r7, r8;
    element_t z1, z2, z3, z4, z5, z6, z7, z8;
    element_t nr3, nr5, nr6, nr8;
    element_t evb;
    element_t H3;
    element_t eh, ePKB,  es;
    element_t eA1,eA2,eC; 
    element_t eT1,eT2,eT3,eT4,eT5,eT6; 
    element_t tempA,   temp, temp1, temp2,temp3,tempe1, tempe2;
    element_t tempG21,  tempG2;
    element_t tempz, tempz1;

    unsigned char * T1bytes, * T2bytes,* T3bytes,* T4bytes,* T5bytes,* T6bytes;
    unsigned char H3_byte[HASHOUTPUTBYTES];

    // 实例化 元素 属于 G1.G2，GT
    
    element_init_G1(evb, pairing);
    element_init_G1(eu, pairing);
    element_init_G1(eu1, pairing);  
    element_init_Zr(t, pairing);
    element_init_Zr(s1, pairing);
    element_init_Zr(s2, pairing);
    element_init_Zr(H3, pairing);
    element_init_Zr(cz, pairing);
    element_init_Zr(tempz, pairing);
    element_init_Zr(tempz1, pairing);
    element_init_Zr(es, pairing);

    element_init_G2(eg, pairing);
    element_init_G2(eg1, pairing);
    element_init_G2(eg2, pairing);


    element_init_G2(ePKB, pairing);
    element_init_G2(eA1, pairing);
    element_init_G2(eA2, pairing);
    element_init_G2(tempA, pairing);
    element_init_G2(tempG2, pairing);
    element_init_G2(tempG21, pairing);
 
    element_init_G2(eT1, pairing);
    element_init_G2(eT2, pairing);
    element_init_G2(eT3, pairing);

    element_init_G1(eC, pairing);
    element_init_G1(temp1, pairing);
    element_init_G1(temp2, pairing);
    element_init_G1(temp3, pairing);

     
     element_init_GT(eh, pairing);
     element_init_GT(temp, pairing);
     element_init_GT(tempe1, pairing);
     element_init_GT(tempe2, pairing);
     element_init_GT(eT4, pairing);
     element_init_GT(eT5, pairing);
     element_init_GT(eT6, pairing);

    // printf("\nA_Proof_generate\n");
 
    element_from_bytes(eg, g);
    element_from_bytes(eg1, g1);
    element_from_bytes(eg2, g2);
    element_from_bytes(eu, u);
    element_from_bytes(eu1, u1);
    element_from_bytes(ePKB, PKB);
    element_from_bytes(es, s);
    element_from_bytes(evb, vB);
 
   element_init_Zr(r1, pairing);
   element_init_Zr(r2, pairing);
   element_init_Zr(r3, pairing);
   element_init_Zr(r4, pairing);
   element_init_Zr(r5, pairing);
   element_init_Zr(r6, pairing);
   element_init_Zr(r7, pairing);
   element_init_Zr(r8, pairing);

   element_init_Zr(z1, pairing);
   element_init_Zr(z2, pairing);
   element_init_Zr(z3, pairing);
   element_init_Zr(z4, pairing);
   element_init_Zr(z5, pairing);
   element_init_Zr(z6, pairing);
   element_init_Zr(z7, pairing);
   element_init_Zr(z8, pairing);

   element_init_Zr(nr3, pairing);
   element_init_Zr(nr5, pairing);
   element_init_Zr(nr6, pairing);
   element_init_Zr(nr8, pairing);

   element_random(s1);
   element_random(s2);
   element_random(t);
   element_random(r1);
   element_random(r2);
   element_random(r3);
   element_random(r4);
   element_random(r5);
   element_random(r6);

    //计算 A1, A2 

    element_pow_zn(eA1, eg1, s1);
    element_pow_zn(tempA, eg2, s2);
    element_mul(eA1, eA1, tempA);

    element_pow_zn(tempA, eg1, s2);
    element_mul(eA2, ePKB, tempA);
 
    //计算  C 
    element_pow_zn(temp1, eu1, t);
    element_mul(eC, evb, temp1);

    element_to_bytes(A1, eA1);
    element_to_bytes(A2, eA2);
    element_to_bytes(C, eC);

 
    //计算  T1
    element_pow_zn(eT1, eg1, r1);
    element_pow_zn(tempG2, eg2, r2);
    element_mul(eT1, eT1, tempG2);
 
    //计算  T2
    element_neg(nr6, r6);
    element_pow_zn(tempA, eA1, nr6);
    element_pow_zn(tempG2, eg1, r4);
    element_mul(eT2, tempA, tempG2);

    element_pow_zn(tempG2, eg2, r5);
    element_mul(eT2, eT2, tempG2);

    //计算  T3
    element_neg(nr3, r3);
    element_pow_zn(tempA, eA1, nr3);
    element_pow_zn(tempG2, eg1, r7);
    element_mul(eT3, tempA, tempG2);

    element_pow_zn(tempG2, eg2, r8);
    element_mul(eT3, eT3, tempG2);

    //计算  T4
    element_pairing(temp, eu, eg);
    element_pow_zn(eT4, temp, r6);

    //计算  T5
    element_pow_zn(tempA, eA2, r6);
    element_neg(nr5, r5);
    element_pow_zn(tempG2, eg1, nr5);
    element_mul(tempG21, tempA, tempG2);
    element_pairing(eT5, eu, tempG21);

    //计算  T6

    //compute left side
 
    sm3_starts( &sm3_ctx );
    sm3_update( &sm3_ctx, IDA, HASHOUTPUTBYTES);
    sm3_finish( &sm3_ctx, H3_byte);
    element_from_bytes(H3, H3_byte);
 
   
    element_pow_zn(tempA, eg, H3);
    element_mul(tempG2, tempA, eA2);
 
    element_pow_zn(temp1, eu1, r3);
    element_pairing(tempe1, temp1, tempG2);

    //compute right side
    element_neg(nr8, r8);
    element_pow_zn(temp1, eC, r2);
    element_pow_zn(temp2, eu1, nr8);
    element_mul(temp3, temp1, temp2);
    element_pairing(tempe2, temp3, eg1);

    element_mul(eT6, tempe1, tempe2);
 

    //conver into bytes
    n1 = element_length_in_bytes(eT1);
    n4 = element_length_in_bytes(eT4);
    T1bytes = (unsigned char *)malloc(n1*sizeof(unsigned char));
    T2bytes = (unsigned char *)malloc(n1*sizeof(unsigned char));
    T3bytes = (unsigned char *)malloc(n1*sizeof(unsigned char));
    T4bytes = (unsigned char *)malloc(n4*sizeof(unsigned char));
    T5bytes = (unsigned char *)malloc(n4*sizeof(unsigned char));
    T6bytes = (unsigned char *)malloc(n4*sizeof(unsigned char));

    element_to_bytes(T1bytes, eT1);
    element_to_bytes(T2bytes, eT2);
    element_to_bytes(T3bytes, eT3);
    element_to_bytes(T4bytes, eT4);
    element_to_bytes(T5bytes, eT5);
    element_to_bytes(T6bytes, eT6);
 
    //计算  hash c
    sm3_starts( &sm3_ctx );
    sm3_update( &sm3_ctx, T1bytes, n1);
    sm3_update( &sm3_ctx, T2bytes, n1);
    sm3_update( &sm3_ctx, T3bytes, n1);
    sm3_update( &sm3_ctx, T4bytes, n4);
    sm3_update( &sm3_ctx, T5bytes, n4);
    sm3_update( &sm3_ctx, T6bytes, n4);

    sm3_update( &sm3_ctx, B_hat, n4);
    sm3_update( &sm3_ctx, h, n4);
    sm3_update( &sm3_ctx, A1, n1);
    sm3_update( &sm3_ctx, A2, n1);
    sm3_update( &sm3_ctx, C, n1);

    sm3_finish( &sm3_ctx, proof);
 
   //计算 Z1-Z8     //element_printf("tempz = %B\n", tempz);

   element_from_hash(cz, proof, HASHOUTPUTBYTES);
 
   element_mul(tempz, cz, s1);        //Z1
   element_sub(z1, r1, tempz);
 
 

   element_mul(tempz1, tempz, es);
   element_sub(z4, r4, tempz1);        //Z4



   element_mul(tempz1, tempz, t);
   element_sub(z7, r7, tempz1);        //Z7

   element_mul(tempz, cz, s2); 
   element_sub(z2, r2, tempz);         //Z2
 
   element_mul(tempz1, tempz, es);
   element_sub(z5, r5, tempz1);         //Z5

   element_mul(tempz1, tempz, t);
   element_sub(z8, r8, tempz1);        //Z8

   element_mul(tempz, cz, t);
   element_sub(z3, r3, tempz);         //Z3

   element_mul(tempz, cz, es);
   element_sub(z6, r6, tempz);         //Z6
 
   n = element_length_in_bytes(z1);
 
    element_to_bytes(proof+HASHOUTPUTBYTES, z1);
    element_to_bytes(proof+HASHOUTPUTBYTES+n, z2);
    element_to_bytes(proof+HASHOUTPUTBYTES + 2*n, z3);
    element_to_bytes(proof+HASHOUTPUTBYTES + 3*n, z4);
    element_to_bytes(proof+HASHOUTPUTBYTES + 4*n, z5);
    element_to_bytes(proof+HASHOUTPUTBYTES + 5*n, z6);
    element_to_bytes(proof+HASHOUTPUTBYTES + 6*n, z7);
    element_to_bytes(proof+HASHOUTPUTBYTES + 7*n, z8);
 
    //最后释放元素空间
    element_clear(t);
    element_clear(s1);
    element_clear(s2);
    element_clear(cz);
    element_clear(eu);
    element_clear(eu1);
    element_clear(eg);
    element_clear(eg1);
    element_clear(eg2);
    element_clear(r1);
    element_clear(r2);
    element_clear(r3);
    element_clear(r4);
    element_clear(r5);
    element_clear(r6);
    element_clear(r7);
    element_clear(r8);

    element_clear(nr3);
    element_clear(nr5);
    element_clear(nr6);
    element_clear(nr8);

    element_clear(z1);
    element_clear(z2);
    element_clear(z3);
    element_clear(z4);
    element_clear(z5);
    element_clear(z6);
    element_clear(z7);
    element_clear(z8);
 
    element_clear(evb);
    element_clear(H3);
    element_clear(eh);
    element_clear(ePKB);
 
  
    element_clear(es);
    element_clear(eA1);
    element_clear(eA2);
    element_clear(eC);
    element_clear(eT1);
 
    element_clear(eT2);
    element_clear(eT3);
    element_clear(eT4);
    element_clear(eT5);
    element_clear(eT6);

   
    element_clear(temp);
    element_clear(temp1);
    element_clear(temp2);
    element_clear(temp3);
    element_clear(tempG2);
    element_clear(tempG21);

 
    element_clear(tempA);
   
    element_clear(tempe1);
    element_clear(tempe2);
 
    return flag;
}


/*

   return -1 if failed
*/

int D_Proof_verify( unsigned char * h, unsigned char * B_hat, unsigned char * IDA,  int idlength,
                      unsigned char * A1, unsigned char * A2,   unsigned char * C,  unsigned char *proof, pairing_t pairing)
{


    sm3_context sm3_ctx;
    
    int flag = 1;
    int n,n1,n4;
    // 定义一些参数
    element_t eg, eg1, eg2, eu, eu1 ;
    element_t cz;


    element_t z1, z2, z3, z4, z5, z6, z7, z8;
    element_t nz3, nz5, nz6, nz8;
 
    element_t H3;
    element_t eh, eB_hat ;
    element_t eA1,eA2,eC; 
    element_t eT1,eT2,eT3,eT4,eT5,eT6; 
    element_t tempA,  tempT, temp, temp1, temp2,temp3,tempe1, tempe2, tempe3;
    element_t tempG21,  tempG2;
    element_t tempz, tempz1;

    unsigned char * T1bytes, * T2bytes,* T3bytes,* T4bytes,* T5bytes,* T6bytes;
    unsigned char H3_byte[HASHOUTPUTBYTES];

    unsigned char Hout_byte[HASHOUTPUTBYTES];
 

    // 实例化 元素 属于 G1.G2，GT
    
 
    element_init_G1(eu, pairing);
    element_init_G1(eu1, pairing);  
 
    element_init_Zr(H3, pairing);
    element_init_Zr(cz, pairing);
    element_init_Zr(tempz, pairing);
    element_init_Zr(tempz1, pairing);
 

    element_init_Zr(z1, pairing);
    element_init_Zr(z2, pairing);
    element_init_Zr(z3, pairing);
    element_init_Zr(z4, pairing);
    element_init_Zr(z5, pairing);
    element_init_Zr(z6, pairing);
    element_init_Zr(z7, pairing);
    element_init_Zr(z8, pairing);

    element_init_Zr(nz3, pairing);
    element_init_Zr(nz5, pairing);
    element_init_Zr(nz6, pairing);
    element_init_Zr(nz8, pairing);

    element_init_G2(eg, pairing);
    element_init_G2(eg1, pairing);
    element_init_G2(eg2, pairing);
 
    element_init_G2(eA1, pairing);
    element_init_G2(eA2, pairing);
    element_init_G2(tempA, pairing);
    element_init_G2(tempG2, pairing);
    element_init_G2(tempG21, pairing);
 
    element_init_G2(eT1, pairing);
    element_init_G2(eT2, pairing);
    element_init_G2(eT3, pairing);

    element_init_G1(eC, pairing);
    element_init_G1(temp1, pairing);
    element_init_G1(temp2, pairing);
    element_init_G1(temp3, pairing);

    element_init_GT(eB_hat, pairing);
    element_init_GT(eh, pairing);
    element_init_GT(temp, pairing);
    element_init_GT(tempT, pairing);
    element_init_GT(tempe1, pairing);
    element_init_GT(tempe2, pairing);
    element_init_GT(tempe3, pairing);

    element_init_GT(eT4, pairing);
    element_init_GT(eT5, pairing);
    element_init_GT(eT6, pairing);


 
    // printf("\nD_Proof_verify\n");
    element_from_bytes(eg, g);
    element_from_bytes(eg1, g1);
    element_from_bytes(eg2, g2);
    element_from_bytes(eu, u);
    element_from_bytes(eu1, u1);
    element_from_bytes(eB_hat, B_hat);
    element_from_bytes(eh,  h);
    element_from_bytes(eA1,  A1);
    element_from_bytes(eA2,  A2);
    element_from_bytes(eC,  C);
 

    n = element_length_in_bytes(z1);

    element_from_hash(cz,  proof, HASHOUTPUTBYTES);
    element_from_bytes(z1,  proof+HASHOUTPUTBYTES);
 
    element_from_bytes(z2,  proof+HASHOUTPUTBYTES + n);
    element_from_bytes(z3,  proof+HASHOUTPUTBYTES + 2*n);
    element_from_bytes(z4,  proof+HASHOUTPUTBYTES + 3*n);
    element_from_bytes(z5,  proof+HASHOUTPUTBYTES + 4*n);
    element_from_bytes(z6,  proof+HASHOUTPUTBYTES + 5*n);
    element_from_bytes(z7,  proof+HASHOUTPUTBYTES + 6*n);
    element_from_bytes(z8,  proof+HASHOUTPUTBYTES + 7*n);
 
    //计算  T1
 
    element_pow_zn(tempA, eA1, cz);
    element_pow_zn(tempG2, eg1, z1);
    element_mul(eT1, tempA, tempG2);
 
    element_pow_zn(tempG2, eg2, z2);
    element_mul(eT1, eT1, tempG2);

  

    //计算  T2

    element_neg(nz6, z6);
    element_pow_zn(tempA, eA1, nz6);

 
    element_pow_zn(tempG2, eg1, z4);
    element_mul(eT2, tempA, tempG2);

    element_pow_zn(tempG2, eg2, z5);
    element_mul(eT2, eT2, tempG2);

 
    //计算  T3
    element_neg(nz3, z3);
    element_pow_zn(tempA, eA1, nz3);
    element_pow_zn(tempG2, eg1, z7);
    element_mul(eT3, tempA, tempG2);

    element_pow_zn(tempG2, eg2, z8);
    element_mul(eT3, eT3, tempG2);
 
    //计算  T4
    element_pow_zn(tempT, eh, cz);

    element_pairing(temp, eu, eg);
    element_pow_zn(eT4, temp, z6);

    element_mul(eT4, eT4, tempT);

 
    //计算  T5
    element_pow_zn(tempA, eA2, z6);
    element_neg(nz5, z5);
    element_pow_zn(tempG2, eg1, nz5);
    element_mul(tempG21, tempA, tempG2);
    element_pairing(tempe1, eu, tempG21);
 
    element_pow_zn(tempe2, eB_hat, cz); 

    element_mul(eT5, tempe1, tempe2);
 
    //计算  T6

    //compute left side
 
    sm3_starts( &sm3_ctx );
    sm3_update( &sm3_ctx, IDA, HASHOUTPUTBYTES);
    sm3_finish( &sm3_ctx, H3_byte);
    element_from_bytes(H3, H3_byte);
  
    element_pow_zn(tempA, eg, H3);
    element_mul(tempG2, tempA, eA2);
     element_pow_zn(temp1, eu1, z3);
    element_pairing(tempe1, temp1, tempG2);

    //compute right side
    element_neg(nz8, z8);
    element_pow_zn(temp1, eC, z2);
    element_pow_zn(temp2, eu1, nz8);
    element_mul(temp3, temp1, temp2);
    element_pairing(tempe2, temp3, eg1);

    //element_mul(eT6, tempe1, tempe2);

    //compute head
    //compute up side
 
    element_pairing(temp, eC, tempG2);
    element_pairing(tempT, eu, eg);
    element_div(tempe3, temp, tempT);
    element_pow_zn(tempe3, tempe3, cz);

    element_mul(eT6, tempe3, tempe1);
    element_mul(eT6, eT6, tempe2);
 
    //conver into bytes
    n1 = element_length_in_bytes(eT1);
    n4 = element_length_in_bytes(eT4);
    T1bytes = (unsigned char *)malloc(n1*sizeof(unsigned char));
    T2bytes = (unsigned char *)malloc(n1*sizeof(unsigned char));
    T3bytes = (unsigned char *)malloc(n1*sizeof(unsigned char));
    T4bytes = (unsigned char *)malloc(n4*sizeof(unsigned char));
    T5bytes = (unsigned char *)malloc(n4*sizeof(unsigned char));
    T6bytes = (unsigned char *)malloc(n4*sizeof(unsigned char));

    element_to_bytes(T1bytes, eT1);
    element_to_bytes(T2bytes, eT2);
    element_to_bytes(T3bytes, eT3);
    element_to_bytes(T4bytes, eT4);
    element_to_bytes(T5bytes, eT5);
    element_to_bytes(T6bytes, eT6);
 
    //计算  hash c
    sm3_starts( &sm3_ctx );
    sm3_update( &sm3_ctx, T1bytes, n1);
    sm3_update( &sm3_ctx, T2bytes, n1);
    sm3_update( &sm3_ctx, T3bytes, n1);
    sm3_update( &sm3_ctx, T4bytes, n4);
    sm3_update( &sm3_ctx, T5bytes, n4);
    sm3_update( &sm3_ctx, T6bytes, n4);
 

    sm3_update( &sm3_ctx, B_hat, n4);
    sm3_update( &sm3_ctx, h, n4);
    sm3_update( &sm3_ctx, A1, n1);
    sm3_update( &sm3_ctx, A2, n1);
    sm3_update( &sm3_ctx, C, n1);

    sm3_finish( &sm3_ctx, Hout_byte);

      if (memcmp(proof, Hout_byte, HASHOUTPUTBYTES) != 0) {
            printf("\n ERROR!\n");
	        return -1;
        }
 
    //最后释放元素空间
     element_init_G1(eu, pairing);
    element_init_G1(eu1, pairing);  
 
    element_clear(H3 );
    element_clear(cz );
    element_clear(tempz );
    element_clear(tempz1);
 

    element_clear(z1);
    element_clear(z2);
    element_clear(z3);
    element_clear(z4);
    element_clear(z5);
    element_clear(z6);
    element_clear(z7);
    element_clear(z8);

    element_clear(nz3);
    element_clear(nz5);
    element_clear(nz6);
    element_clear(nz8);

    element_clear(eg);
    element_clear(eg1);
    element_clear(eg2);


 
    element_clear(eA1);
    element_clear(eA2);
    element_clear(tempA);
    element_clear(tempG2);
    element_clear(tempG21);
 
    element_clear(eT1);
    element_clear(eT2);
    element_clear(eT3);

    element_clear(eC);
    element_clear(temp1);
    element_clear(temp2);
    element_clear(temp3);

    element_clear(eB_hat);
    element_clear(eh);
    element_clear(temp);
    element_clear(tempT);
    element_clear(tempe1);
    element_clear(tempe2);
    element_clear(tempe3);

    element_clear(eT4);
    element_clear(eT5);
    element_clear(eT6);
     
 
    return flag ;
 
}





int contact_confirmation(user A, user B, pairing_t pairing) {
    if(B_generate_vB_toA(A.id, B.sec_key, pairing) != 0) {
        printf("B产生VB失败！\n");
        return 1;
    }

    // printf("vB = ");
    // printChar(vB, HASHOUTPUTBYTES);

    if(A_vertify_B(B.pb_key, B.sig, A.id, pairing) != 0) {
        printf("A验证B信息失败！\n");
        return 1;
    }
    // A store B's info
    contact_node *nodeB = (contact_node *)malloc(sizeof(contact_node));
    nodeB->data.contact_date = B.date;
    nodeB->data.contact_id = B.id;
    nodeB->data.contact_pk = B.pb_key;
    nodeB->data.contact_v = vB;
    nodeB->next = A.contact->next;
    A.contact = nodeB;
    // printf("A储存B的信息成功！\n");

    if(A_generate_vA_toB(B.id, A.sec_key, pairing) != 0) {
        printf("A产生VA失败！\n");
        return 1;
    }

    // printf("vA = ");
    // printChar(vA, HASHOUTPUTBYTES);

    if(B_vertify_A(A.pb_key, A.sig, B.id, pairing) != 0) {
        printf("B验证A信息失败！\n");
        return 1;
    }
    // B store A's info
    contact_node *nodeA = (contact_node *)malloc(sizeof(contact_node));
    nodeA->data.contact_date = A.date;
    nodeA->data.contact_id = A.id;
    nodeA->data.contact_pk = A.pb_key;
    nodeA->data.contact_v = vA;
    nodeA->next = A.contact->next;
    B.contact = nodeA;
    // printf("B储存A的信息成功！\n");

    return 0;
};

int main() {
    element_t eg, eg1, eg2, eu,eu1, epkA, eskA, epkB, eskB, eidA, eidB;

    element_t  tempT;

    pairing_t pairing;

    struct timeval start;
  	struct timeval end;
  	struct timeval setup_start;
  	struct timeval setup_end;
    struct timeval fig4_start;
  	struct timeval fig4_end;
    struct timeval zk_start;
  	struct timeval zk_end;
  	unsigned long timer;
  	unsigned long setup_timer;
  	unsigned long fig4_timer;
  	unsigned long zk_timer;

    int uCount = 100000;
    int iCount = 1;
    int i = 0;


	printf("begin the complete process test\n");
	printf("the test times is [%d]\n",iCount);
  	gettimeofday(&start, NULL);
 
    int ret;
    // 实例化 paring
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);//读大小为1的个数最大为1024到param，返回真实读入的个数
    printf("param = %s\n", param);
    printf("count = %lu\n", count);//size_t是标准C库中定义的，应为unsigned int，在64位系统中为 long unsigned int
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);

    gettimeofday(&setup_start, NULL);
    for(i=0;i<uCount;i++){
        element_init_G2(eg, pairing);
        element_init_G2(eg1, pairing);
        element_init_G2(eg2, pairing);
        element_init_G1(eu, pairing);
        element_init_G1(eu1, pairing);
        element_init_G1(eidA, pairing);
        element_init_G1(eidB, pairing);
        element_init_Zr(eskA, pairing);
        element_init_Zr(eskB, pairing);
        element_init_G2(epkA, pairing);
        element_init_G2(epkB, pairing);
        element_init_GT(tempT, pairing);
        
        
        element_random(eg);
        element_random(eg1);
        element_random(eg2);
        // element_printf("system parameter g = %B\n", eg);

        element_random(eu);
        element_random(eu1);
        // element_printf("system parameter u = %B\n", eu);

        element_random(eskA);
        // element_printf("A secret key = %B\n", eskA);

        element_pow_zn(epkA, eg, eskA);
        // element_printf("A public key = %B\n", epkA);

        element_random(eskB);
        // element_printf("B secret key = %B\n", eskB);

        element_pow_zn(epkB, eg, eskB);
        // element_printf("B public key = %B\n", epkB);

        element_random(eidA);
        // element_printf("A id = %B\n", eidA);

        element_random(eidB);
        // element_printf("B id = %B\n", eidB);

        int ng = element_length_in_bytes(eg);
        g = (unsigned char *)malloc(ng*sizeof(unsigned char));
        g1 = (unsigned char *)malloc(ng*sizeof(unsigned char));
        g2 = (unsigned char *)malloc(ng*sizeof(unsigned char));
        int nu = element_length_in_bytes(eu);
        u = (unsigned char *)malloc(nu*sizeof(unsigned char));
        u1 = (unsigned char *)malloc(nu*sizeof(unsigned char));

        element_to_bytes(g, eg);
        element_to_bytes(g1, eg1);
        element_to_bytes(g2, eg2);
        // printf("g = ");
        // printChar(g, HASHOUTPUTBYTES);
        element_to_bytes(u, eu);
        element_to_bytes(u1, eu1);
        // printf("u = ");
        // printChar(u, HASHOUTPUTBYTES);
    }
    gettimeofday(&setup_end, NULL);
    setup_timer = 1000000 * (setup_end.tv_sec - setup_start.tv_sec) + fig4_end.tv_usec - fig4_start.tv_usec;
 	printf("setup_timer = %ld us\nave time= %ld us\n",setup_timer, setup_timer/uCount);

    user A;
    user B;
    int n = element_length_in_bytes(eidA);

    A.id = (unsigned char *)malloc(n*sizeof(unsigned char));
    element_to_bytes(A.id, eidA);
    n = element_length_in_bytes(eidB);
    B.id = (unsigned char *)malloc(n*sizeof(unsigned char));
    element_to_bytes(B.id, eidB);
    n = element_length_in_bytes(eskA);
    A.sec_key = (unsigned char *)malloc(n*sizeof(unsigned char));
    element_to_bytes(A.sec_key, eskA);
    n = element_length_in_bytes(epkA);
    A.pb_key = (unsigned char *)malloc(n*sizeof(unsigned char));
    element_to_bytes(A.pb_key, epkA);
    n = element_length_in_bytes(eskB);
    B.sec_key = (unsigned char *)malloc(n*sizeof(unsigned char));
    element_to_bytes(B.sec_key, eskB);
    n = element_length_in_bytes(epkB);
    B.pb_key = (unsigned char *)malloc(n*sizeof(unsigned char));
    element_to_bytes(B.pb_key, epkB);
    A.contact = (contact_node *)malloc(sizeof(contact_node));
    A.contact -> next = NULL;
    B.contact = (contact_node *)malloc(sizeof(contact_node));
    B.contact -> next = NULL;


    //Figure 4
    gettimeofday(&fig4_start, NULL);
    for(i=0;i<iCount;i++){

        int con_res = contact_confirmation(A, B, pairing);
        if (con_res != 0) printf("contact_confirmation fail!\n");

        
    }

  	gettimeofday(&fig4_end, NULL);
    fig4_timer = 1000000 * (fig4_end.tv_sec - fig4_start.tv_sec) + fig4_end.tv_usec - fig4_start.tv_usec;
 	printf("fig4_timer = %ld us\nave time= %ld us\n",fig4_timer, fig4_timer/iCount);
    
    int nt = element_length_in_bytes(tempT);
    int nz = element_length_in_bytes(eskA);
    int ng1 = element_length_in_bytes(eidA);
    int ng2 = element_length_in_bytes(epkA);

    //zero-knowledge part
    gettimeofday(&zk_start, NULL);
    unsigned char * h;
    unsigned char * B_hat;
    unsigned char * s;
    unsigned char * A1;
    unsigned char * A2;
    unsigned char * C;
    unsigned char *proof;
 
    h = (unsigned char *)malloc(nt*sizeof(unsigned char));
    B_hat = (unsigned char *)malloc(nt*sizeof(unsigned char));
    s   = (unsigned char *)malloc(nz*sizeof(unsigned char));
    A1= (unsigned char *)malloc(ng2*sizeof(unsigned char));
    A2= (unsigned char *)malloc(ng2*sizeof(unsigned char));
    C= (unsigned char *)malloc(ng1*sizeof(unsigned char));
    proof = (unsigned char *)malloc((HASHOUTPUTBYTES+8*nz)*sizeof(unsigned char));
 
    for(i=0;i<iCount;i++){
        ret = A_Pseudo_Public_generate(B.pb_key,  h,  B_hat ,  s ,  pairing);

        // printf("A_Pseudo_Public_generate = %d\n", ret);
    
        ret =A_Proof_generate(B.pb_key,  s, h,  A.id, ng1,  B_hat, A1, A2, C, proof, pairing);

        // printf("A_Proof_generate = %d\n", ret);


        ret = D_Proof_verify( h,  B_hat,  A.id, ng1, A1,  A2,  C,  proof,  pairing);

        // printf("D_Proof_verify = %d\n", ret);
    }

    gettimeofday(&zk_end, NULL);
    zk_timer = 1000000 * (zk_end.tv_sec - zk_start.tv_sec) + zk_end.tv_usec - zk_start.tv_usec;
 	printf("zk_timer = %ld us\nave time= %ld us\n",zk_timer, zk_timer/iCount);

    element_clear(eg);
    element_clear(eu);
    element_clear(eidA);
    element_clear(eidB);
    element_clear(epkA);
    element_clear(epkB);
    element_clear(eskA);
    element_clear(eskB);
    pairing_clear(pairing);

    return 0;
}

