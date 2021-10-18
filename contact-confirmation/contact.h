#include<stdio.h>
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>

typedef struct Contact_info contact_info;

typedef struct Contact_node  contact_node;
    
typedef struct User user;

//（见匿签密）
/*
* 生成发送者a的信息
* 输入：a的公钥，a的证书pid
* 输出：a->b的message
* 返回 ：0 成功；
*/
// int kex_kdf_a();
int printChar( unsigned char * str, int length);
/*
* B计算出vb，并将vb发送给A
* input: IDA, u
* output: vB
* return:0 - success
*        1 - fail
*/
int B_generate_vB_toA(unsigned char * IDA,
                     unsigned char *SKB,
                     pairing_t pairing);

/*
* A计算出va，并将va发送给B
* input: IDB, u
* output: vA
* return:0 - success
*        1 - fail
*/
int A_generate_vA_toB(unsigned char * IDB,
                     unsigned char *SKA,
                     pairing_t pairing);

/*
* A与B互相验证签名，若验证成功则绑定身份
* 当两者互相绑定后则成功，若一方验证签名失败则失败
* return:0 - success
*        1 - fail
*/
int contact_confirmation(user A, user B);

/*
* A验证B的签名
* input:PKB, SKB, SigB, IDA, g, u
* output:vB
* return:0 - success
*        1 - fail
*/
int A_vertify_B(unsigned char * PKB,
                    unsigned char * SigB,
                    unsigned char * IDA,
                    pairing_t pairing);

/*
* B验证A的签名
* input:PKA, SKA, SigA, IDB, g, u
* output:vA
* return:0 - success
*        1 - fail
*/
int B_vertify_A(unsigned char * PKA,
                    unsigned char * SigA,
                    unsigned char * IDB,
                    pairing_t pairing);





/*
* A Generate Pseudo-Public Key and  sends them to Doctor
* input:PKB, g, u
* output:h, B_hat
* return:0 - success
*        1 - fail
*/
int A_Pseudo_Public_generate(unsigned char * PKB, unsigned char * h, unsigned char * B_hat , unsigned char * s , pairing_t pairing);


/*
* A Generate proof and  send it  to Doctor
* input:PKB, s, h  IDA
* output:A1, A2, C, proof
* return:0 - success
*        1 - fail
*/
int A_Proof_generate(unsigned char * PKB, unsigned char * s, unsigned char * h,   unsigned char * IDA, int idlength,  unsigned char * B_hat,
                      unsigned char * A1, unsigned char * A2,   unsigned char * C,  unsigned char *proof, pairing_t pairing);




/*
* Doctor verify the proof  
* input:all
* return:0 - success
*        -1 - fail
*/
int D_Proof_verify( unsigned char * h, unsigned char * B_hat, unsigned char * IDA,  int idlength,  
                      unsigned char * A1, unsigned char * A2,   unsigned char * C,  unsigned char *proof, pairing_t pairing);





















