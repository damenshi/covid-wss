#ifndef  CAKE_KEX_IMPL_H_
#define   CAKE_KEX_IMPL_H_

#include <sys/types.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unistd.h>
#include <sys/syscall.h>



#include "include/kex_api.h"
#include "myOpenSSL.h"
#include "sm3.h"
#include "encrypt.h"


static unsigned char *CA_pk = NULL;
static unsigned char *CA_sk = NULL;

static secp256k1_context *kctx = NULL;

unsigned char *flag = "-HE";

/*************************************************Initial and Destroy methord***********************************************/

int kex_init(void)
{
    secp256k1_gej pubj;
    secp256k1_ge pub;   /*public key B */
    secp256k1_scalar scalar_sk;   /*private key b */

    int ret;
    size_t size;

   	kctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	if(NULL == kctx)
	{
	   printf("gamma init fail!");
       	   return -1;
	}

     CA_pk   =  (unsigned char *)malloc(PUBLICKEYBYTES*sizeof(unsigned char));
     CA_sk =  (unsigned char *)malloc(SECRETKEYBYTES*sizeof(unsigned char));


     { /*generate CA's public and private key */
     random_scalar_generation(&scalar_sk);
     secp256k1_ecmult_gen(&kctx->ecmult_gen_ctx, &pubj, &scalar_sk);
     secp256k1_ge_set_gej(&pub, &pubj);

     /*serialize server side static public key */
     ret =  secp256k1_eckey_pubkey_serialize(&pub, CA_pk,  &size, 1);
     if (size!= PUBLICKEYBYTES ||ret ==0 ) return -1;
     /*serialize server side static private key */
     secp256k1_scalar_get_b32(CA_sk, &scalar_sk);
     }

return 0;
}



void kex_destroy()
{
 	secp256k1_context_destroy(kctx);
        free (CA_pk);
        free (CA_sk);



}


int printChar( unsigned char * str, int length)
{
			int j; 
			for(j=0;j<length;j++)
			{
				printf("%02X",*(str+j));
			}
			printf("]\n");


}


int  send_pid(unsigned char * message1, unsigned char * static_pk, unsigned char * static_sk, unsigned char * h)
{
    secp256k1_gej pubj;
    secp256k1_ge pub;   /*public key B */
    secp256k1_scalar scalar_sk;   /*private key b */
    secp256k1_scalar nonce;
    sm3_context sm3_ctx;
    unsigned char output_hash[33];
    int ret;
    size_t size;

   
 if (NULL == static_pk || NULL == static_sk || NULL == message1 || NULL == h)
    return -2;

     /*generate server's public and private key */
     {
     random_scalar_generation(&scalar_sk);
     secp256k1_ecmult_gen(&kctx->ecmult_gen_ctx, &pubj, &scalar_sk);
     secp256k1_ge_set_gej(&pub, &pubj);

     /*serialize server side static public key */
     ret =  secp256k1_eckey_pubkey_serialize(&pub, static_pk,  &size, 1);
     if (size!= PUBLICKEYBYTES ||ret ==0 ) return -1;
     /*serialize server side static private key */
     secp256k1_scalar_get_b32(static_sk, &scalar_sk);
     }
     { /*generate AtoBmessage*/
         memcpy(message1, static_pk, PUBLICKEYBYTES);
         random_scalar_generation(&nonce);
         ret = ecdsa_sig_sign(&kctx->ecmult_gen_ctx, message1 + PUBLICKEYBYTES, CA_sk,  static_pk, PUBLICKEYBYTES, &nonce);
         if (ret != 0) return ret;
     }
     /*generate h*/
     {
        sm3_starts( &sm3_ctx );
        sm3_update( &sm3_ctx, flag, strlen(flag));
        sm3_update( &sm3_ctx, message1, PID_BYTES);
        sm3_finish( &sm3_ctx, output_hash );
        memcpy(h, output_hash, SECRETKEYBYTES);
     }
    return 0;
}

int  send_r(unsigned char * message2, unsigned char * h, unsigned char * message1)
{
    sm3_context sm3_ctx;
    unsigned char output_hash[KEX_SECRETKEYBYTES];
    unsigned char h_bar_char[SECRETKEYBYTES];

    secp256k1_gej pubj;
    secp256k1_ge pub;
    secp256k1_scalar scalar_r;   

    if (NULL == h || NULL == message2 || NULL == message1)
        return -2;

    /*generate h'*/
     {
        sm3_starts( &sm3_ctx );
        sm3_update( &sm3_ctx, flag, strlen(flag));
        sm3_update( &sm3_ctx, message1, PID_BYTES);
        sm3_finish( &sm3_ctx, output_hash );
        memcpy(h_bar_char, output_hash, SECRETKEYBYTES);
     }

    int ret = stringCompare(h, h_bar_char, SECRETKEYBYTES);

    if (ret!=0)
       {
         printf("error: h != h'\n");
         return -1;
       }


    /*generate r*/
    random_scalar_generation(&scalar_r);
    secp256k1_ecmult_gen(&kctx->ecmult_gen_ctx, &pubj, &scalar_r);
    secp256k1_ge_set_gej(&pub, &pubj);

     /*serialize r*/
    secp256k1_scalar_get_b32(message2, &scalar_r);


return 0;

}

int  send_cert_bar(unsigned char * message3, unsigned char * message2, unsigned char *static_sk)
{
    sm3_context sm3_ctx;

    secp256k1_gej pubj;
    secp256k1_ge pub;   /*g^k */
    secp256k1_scalar scalar_k;   /*k */
    secp256k1_scalar scalar_s;
    secp256k1_scalar scalar_sk;
    secp256k1_scalar scalar_t;
    secp256k1_scalar temp;
    
    int ret;
    size_t size;
    int overflow;

    unsigned char output_hash[KEX_SECRETKEYBYTES];
    unsigned char k_char[SECRETKEYBYTES];
    unsigned char gk_char[PUBLICKEYBYTES];
    unsigned char t_char[PUBLICKEYBYTES];
    unsigned char s_char[PUBLICKEYBYTES];
 

     { /*generate k and g^k */
     random_scalar_generation(&scalar_k);
     secp256k1_ecmult_gen(&kctx->ecmult_gen_ctx, &pubj, &scalar_k);
     secp256k1_ge_set_gej(&pub, &pubj);

     /*serialize server side g^k */
     ret =  secp256k1_eckey_pubkey_serialize(&pub, gk_char,  &size, 1);
     if (size!= PUBLICKEYBYTES ||ret ==0 ) return -1;
     /*serialize server side k */
     secp256k1_scalar_get_b32(k_char, &scalar_k);
     }

    sm3_starts( &sm3_ctx );
    sm3_update( &sm3_ctx, gk_char, PUBLICKEYBYTES);
    sm3_update( &sm3_ctx, message2, PUBLICKEYBYTES);
    sm3_finish( &sm3_ctx, output_hash);
    memcpy(t_char, output_hash, PUBLICKEYBYTES);

    /*compute s = k - at mod q*/
    secp256k1_scalar_set_b32(&scalar_sk, static_sk, &overflow);
    VERIFY_CHECK(overflow == 0);
    secp256k1_scalar_set_b32(&scalar_t, t_char, &overflow);
    VERIFY_CHECK(overflow == 0);
    secp256k1_scalar_mul(&temp, &scalar_sk, &scalar_t);
    secp256k1_scalar_negate(&scalar_s, &temp);
    secp256k1_scalar_add(&scalar_s, &scalar_k, &scalar_s);      /*compute s = k - at mod q*/
    secp256k1_scalar_get_b32(s_char, &scalar_s);
    

    /*cert = (s,t)*/
    memcpy(message3, s_char, PUBLICKEYBYTES);
    memcpy(message3+PUBLICKEYBYTES, t_char, PUBLICKEYBYTES);

return 0;

}


int  kex_verify(  unsigned char * message1, unsigned char * message2, unsigned char * message3,
                    unsigned char * static_pk_a)
{
    sm3_context sm3_ctx;

    int ret,  overflow;
    size_t  size;

    secp256k1_gej pk_t_gej;
    secp256k1_ge pk_t_ge;

    secp256k1_gej pk_gej;
    secp256k1_ge pk_ge;

    secp256k1_gej g_s_gej;
    secp256k1_ge g_s_ge;
   
    unsigned char output_hash[PUBLICKEYBYTES];
    
    unsigned char pida_sig_char[CERT_BYTES];
    unsigned char t_char[PUBLICKEYBYTES];
    unsigned char s_char[PUBLICKEYBYTES];
    unsigned char g_s_char[PUBLICKEYBYTES];
    unsigned char pk_t_char[PUBLICKEYBYTES];
    unsigned char t_bar_char[PUBLICKEYBYTES];

    secp256k1_scalar scalar_pk; 
    secp256k1_scalar scalar_s;
    secp256k1_scalar scalar_t;


   if (NULL == message1 || NULL == message2 ||  NULL == static_pk_a ||   NULL == message3  )
    return -2;


    memcpy(pida_sig_char, message1 + PUBLICKEYBYTES, CERT_BYTES);
    memcpy(t_char, message3 + PUBLICKEYBYTES, PUBLICKEYBYTES);
    memcpy(s_char, message3, PUBLICKEYBYTES);

    /*verify*/
    int ret1 = ecdsa_sig_verify(&kctx->ecmult_ctx, pida_sig_char, CA_pk, static_pk_a, PUBLICKEYBYTES);
    
    /*verify if t = H(g^s, PK^t, r)*/
        /*compute g^s*/
        secp256k1_scalar_set_b32(&scalar_s, s_char, &overflow);
        VERIFY_CHECK(overflow == 0);
        secp256k1_ecmult_gen(&kctx->ecmult_gen_ctx, &g_s_gej, &scalar_s);
        secp256k1_ge_set_gej(&g_s_ge, &g_s_gej);
        ret =  secp256k1_eckey_pubkey_serialize(&g_s_ge, g_s_char,  &size, 1);
        if (size!= PUBLICKEYBYTES ||ret ==0 ) return -1;

        /*compute pk^t*/
        secp256k1_scalar_set_b32(&scalar_t, t_char, &overflow);
        VERIFY_CHECK(overflow == 0);
        ret = secp256k1_eckey_pubkey_parse(&pk_ge,  static_pk_a, PUBLICKEYBYTES); 
        if(ret==0) return -1;
        secp256k1_gej_set_ge(&pk_ge, &pk_gej);
        secp256k1_ecmult(&kctx->ecmult_ctx, &pk_t_gej, &pk_gej, &scalar_t, NULL);    /* pk_t_j = t*pk_j + Null*G  */
        secp256k1_ge_set_gej(&pk_t_ge, &pk_t_gej);
        ret =  secp256k1_eckey_pubkey_serialize(&pk_t_ge, pk_t_char,  &size, 1);
        if (size!= PUBLICKEYBYTES ||ret ==0 ) return -1;

    sm3_starts( &sm3_ctx);
    sm3_update( &sm3_ctx, g_s_char, PUBLICKEYBYTES);
    sm3_update( &sm3_ctx, pk_t_char, PUBLICKEYBYTES);
    sm3_update( &sm3_ctx, message2, PUBLICKEYBYTES);
    sm3_finish( &sm3_ctx, output_hash);
    memcpy(t_bar_char, output_hash, PUBLICKEYBYTES );

    int ret2 = stringCompare(t_bar_char, t_char, PUBLICKEYBYTES);
        if (ret1!=0 && ret2!=0)
       {
         printf("message3 verify fail !!");
           return -1;
       }

return 0;

}

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

/*
 * SM3 context setup
 */
void sm3_starts( sm3_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x7380166F;
    ctx->state[1] = 0x4914B2B9;
    ctx->state[2] = 0x172442D7;
    ctx->state[3] = 0xDA8A0600;
    ctx->state[4] = 0xA96F30BC;
    ctx->state[5] = 0x163138AA;
    ctx->state[6] = 0xE38DEE4D;
    ctx->state[7] = 0xB0FB0E4E;

}

static void sm3_process( sm3_context *ctx, unsigned char data[64] )
{
    unsigned long SS1, SS2, TT1, TT2, W[68],W1[64];
    unsigned long A, B, C, D, E, F, G, H;
	unsigned long T[64];
	unsigned long Temp1,Temp2,Temp3,Temp4,Temp5;
	int j;
#ifdef _DEBUG
	int i;
#endif

	
	for(j = 0; j < 16; j++)
		T[j] = 0x79CC4519;
	for(j =16; j < 64; j++)
		T[j] = 0x7A879D8A;

    GET_ULONG_BE( W[ 0], data,  0 );
    GET_ULONG_BE( W[ 1], data,  4 );
    GET_ULONG_BE( W[ 2], data,  8 );
    GET_ULONG_BE( W[ 3], data, 12 );
    GET_ULONG_BE( W[ 4], data, 16 );
    GET_ULONG_BE( W[ 5], data, 20 );
    GET_ULONG_BE( W[ 6], data, 24 );
    GET_ULONG_BE( W[ 7], data, 28 );
    GET_ULONG_BE( W[ 8], data, 32 );
    GET_ULONG_BE( W[ 9], data, 36 );
    GET_ULONG_BE( W[10], data, 40 );
    GET_ULONG_BE( W[11], data, 44 );
    GET_ULONG_BE( W[12], data, 48 );
    GET_ULONG_BE( W[13], data, 52 );
    GET_ULONG_BE( W[14], data, 56 );
    GET_ULONG_BE( W[15], data, 60 );

#ifdef _DEBUG 
	printf("Message with padding:\n");
	for(i=0; i< 8; i++)
		printf("%08x ",W[i]);
	printf("\n");
	for(i=8; i< 16; i++)
		printf("%08x ",W[i]);
	printf("\n");
#endif

#define FF0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )


#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

#define P0(x) ((x) ^  ROTL((x),9) ^ ROTL((x),17)) 
#define P1(x) ((x) ^  ROTL((x),15) ^ ROTL((x),23)) 

	for(j = 16; j < 68; j++ )
	{
		Temp1 = W[j-16] ^ W[j-9];
		Temp2 = ROTL(W[j-3],15);
		Temp3 = Temp1 ^ Temp2;
		Temp4 = P1(Temp3);
		Temp5 =  ROTL(W[j - 13],7 ) ^ W[j-6];
		W[j] = Temp4 ^ Temp5;
	}

#ifdef _DEBUG 
	printf("Expanding message W0-67:\n");
	for(i=0; i<68; i++)
	{
		printf("%08x ",W[i]);
		if(((i+1) % 8) == 0) printf("\n");
	}
	printf("\n");
#endif

	for(j =  0; j < 64; j++)
	{
        W1[j] = W[j] ^ W[j+4];
	}

#ifdef _DEBUG 
	printf("Expanding message W'0-63:\n");
	for(i=0; i<64; i++)
	{
		printf("%08x ",W1[i]);
		if(((i+1) % 8) == 0) printf("\n");
	}
	printf("\n");
#endif

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];
#ifdef _DEBUG       
	printf("j     A       B        C         D         E        F        G       H\n");
	printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n",A,B,C,D,E,F,G,H);
#endif

	for(j =0; j < 16; j++)
	{
		SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j)), 7); 
		SS2 = SS1 ^ ROTL(A,12);
		TT1 = FF0(A,B,C) + D + SS2 + W1[j];
		TT2 = GG0(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTL(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTL(F,19);
		F = E;
		E = P0(TT2);
#ifdef _DEBUG 
		printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n",j,A,B,C,D,E,F,G,H);
#endif
	}
	
	for(j =16; j < 64; j++)
	{
		SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j)), 7); 
		SS2 = SS1 ^ ROTL(A,12);
		TT1 = FF1(A,B,C) + D + SS2 + W1[j];
		TT2 = GG1(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTL(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTL(F,19);
		F = E;
		E = P0(TT2);
#ifdef _DEBUG 
		printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n",j,A,B,C,D,E,F,G,H);
#endif	
	}

    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H;
#ifdef _DEBUG 
	   printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n",ctx->state[0],ctx->state[1],ctx->state[2],
		                          ctx->state[3],ctx->state[4],ctx->state[5],ctx->state[6],ctx->state[7]);
#endif
}

/*
 * SM3 process buffer
 */
void sm3_update( sm3_context *ctx, const unsigned char *input, int ilen )
{
    int fill;
    unsigned long left;

    if( ilen <= 0 )
        return;

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < (unsigned long) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, fill );
        sm3_process( ctx, ctx->buffer );
        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 64 )
    {
        sm3_process( ctx, input );
        input += 64;
        ilen  -= 64;
    }

    if( ilen > 0 )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, ilen );
    }
}

static const unsigned char sm3_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * SM3 final digest
 */
void sm3_finish( sm3_context *ctx, unsigned char output[32] )
{
    unsigned long last, padn;
    unsigned long high, low;
    unsigned char msglen[8];

    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_ULONG_BE( high, msglen, 0 );
    PUT_ULONG_BE( low,  msglen, 4 );

    last = ctx->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    sm3_update( ctx, (unsigned char *) sm3_padding, padn );
    sm3_update( ctx, msglen, 8 );

    PUT_ULONG_BE( ctx->state[0], output,  0 );
    PUT_ULONG_BE( ctx->state[1], output,  4 );
    PUT_ULONG_BE( ctx->state[2], output,  8 );
    PUT_ULONG_BE( ctx->state[3], output, 12 );
    PUT_ULONG_BE( ctx->state[4], output, 16 );
    PUT_ULONG_BE( ctx->state[5], output, 20 );
    PUT_ULONG_BE( ctx->state[6], output, 24 );
    PUT_ULONG_BE( ctx->state[7], output, 28 );
}

/*
 * output = SM3( input buffer )
 */
void sm3( unsigned char *input, int ilen,
           unsigned char output[32] )
{
    sm3_context ctx;

    sm3_starts( &ctx );
    sm3_update( &ctx, input, ilen );
    sm3_finish( &ctx, output );

    memset( &ctx, 0, sizeof( sm3_context ) );
}

/*
 * output = SM3( file contents )
 */
int sm3_file( char *path, unsigned char output[32] )
{
    FILE *f;
    size_t n;
    sm3_context ctx;
    unsigned char buf[1024];

    if( ( f = fopen( path, "rb" ) ) == NULL )
        return( 1 );

    sm3_starts( &ctx );

    while( ( n = fread( buf, 1, sizeof( buf ), f ) ) > 0 )
        sm3_update( &ctx, buf, (int) n );

    sm3_finish( &ctx, output );

    memset( &ctx, 0, sizeof( sm3_context ) );

    if( ferror( f ) != 0 )
    {
        fclose( f );
        return( 2 );
    }

    fclose( f );
    return( 0 );
}

/*
 * SM3 HMAC context setup
 */
void sm3_hmac_starts( sm3_context *ctx, unsigned char *key, int keylen )
{
    int i;
    unsigned char sum[32];

    if( keylen > 64 )
    {
        sm3( key, keylen, sum );
        keylen = 32;
        key = sum;
    }

    memset( ctx->ipad, 0x36, 64 );
    memset( ctx->opad, 0x5C, 64 );

    for( i = 0; i < keylen; i++ )
    {
        ctx->ipad[i] = (unsigned char)( ctx->ipad[i] ^ key[i] );
        ctx->opad[i] = (unsigned char)( ctx->opad[i] ^ key[i] );
    }

    sm3_starts( ctx);
    sm3_update( ctx, ctx->ipad, 64 );

    memset( sum, 0, sizeof( sum ) );
}

/*
 * SM3 HMAC process buffer
 */
void sm3_hmac_update( sm3_context *ctx, unsigned char *input, int ilen )
{
    sm3_update( ctx, input, ilen );
}

/*
 * SM3 HMAC final digest
 */
void sm3_hmac_finish( sm3_context *ctx, unsigned char output[32] )
{
    int hlen;
    unsigned char tmpbuf[32];

    hlen =  32;

    sm3_finish( ctx, tmpbuf );
    sm3_starts( ctx );
    sm3_update( ctx, ctx->opad, 64 );
    sm3_update( ctx, tmpbuf, hlen );
    sm3_finish( ctx, output );

    memset( tmpbuf, 0, sizeof( tmpbuf ) );
}

/*
 * output = HMAC-SM#( hmac key, input buffer )
 */
void sm3_hmac( unsigned char *key, int keylen,
                unsigned char *input, int ilen,
                unsigned char output[32] )
{
    sm3_context ctx;

    sm3_hmac_starts( &ctx, key, keylen);
    sm3_hmac_update( &ctx, input, ilen );
    sm3_hmac_finish( &ctx, output );

    memset( &ctx, 0, sizeof( sm3_context ) );
}

 

#endif /* CAKE_KEX_IMPL_H_ */
