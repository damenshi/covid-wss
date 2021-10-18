#ifndef KEX_API_H
#define KEX_API_H





#define KEX_SECRETKEYBYTES		33
#define KEX_PUBLICKEYBYTES		177
#define KEX_BYTES		        32

#define KEX_ATOB_MESSAGEBYES		33
#define KEX_BTOA_MESSAGEBYES		177
#define KEX_ATOB_MESSAGEBYES2		144

#define SECRETKEYBYTES		        32
#define PUBLICKEYBYTES		        33
#define CERT_BYTES		        64
#define PID_BYTES		        PUBLICKEYBYTES + CERT_BYTES
#define CIPHER_BYTES                    144
#define PT_BYTES                        130

#define KEX_ALGNAME "CAKE_KEX_ALGORITHM"


/* the relization of this api is in cake_kex_impl.h*/



/****************initial and destroy methord**********/


/*************************************
function:kex_init
desc :to initialize the algorithm library and CA's public and private key
input : null
output: null
return: 0  -succ;
           -1 -fail
*************************************/
int kex_init(void);


/*************************************
function:kex_destroy
desc :to destrop context at the end of program and free CA's public and private key
input : null
output: null
return:  null
*************************************/
void kex_destroy(void);


int  send_pid(unsigned char * message1, unsigned char * static_pk, unsigned char * static_sk, unsigned char * h);

int  send_r(unsigned char * message2, 
            unsigned char * h, 
            unsigned char * message1);

int  send_cert_bar(unsigned char * message3, 
                   unsigned char * message2, 
                   unsigned char *static_sk);

int  kex_verify(unsigned char * message1, 
                unsigned char * message2, 
                unsigned char * message3,
                unsigned char * static_pk_a);



#endif
