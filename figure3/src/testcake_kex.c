
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <assert.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/time.h>
#include "include/kex_api.h"
#include "test.h"


#define CAKE_KEX_TEST_DATA_OUTFILE "cake_kex_custom_result.txt"


void test_writef(const char *filepath, char *epcFormat, ...)
{
	FILE *fp;
	va_list args;

	 fp = fopen(filepath, "a+");
	if (NULL == fp)
	{
		syslog(LOG_ERR, "WriteF error: fail to open log file[%s]",filepath);
		return;
	}

	va_start(args,epcFormat);
	vfprintf(fp, epcFormat, args);
	va_end(args);

	fprintf(fp, "\n");
	fflush(fp);
	fclose(fp);
	return;
}



void test_writehexf(const char *filepath,unsigned char *data, int datalen, char *epcFormat, ...)
{
	FILE *fp;
	va_list args;

	char *hexdata=NULL;
	int i=0;


	 fp = fopen(filepath, "a+");
	if (NULL == fp)
	{
		syslog(LOG_ERR, "WriteF error: fail to open log file[%s]",filepath);
		return;
	}

	va_start(args,epcFormat);
	vfprintf(fp, epcFormat, args);
	va_end(args);

	hexdata=malloc(datalen*2+1);
	if(NULL == hexdata)
		return;

	memset(hexdata,0, datalen*2+1);
	for(i=0;i<datalen;i++)
	{
		sprintf(hexdata+i*2,"%02X",*(data+i));
	}
	fprintf(fp, "%s\n",hexdata);

	free(hexdata);
	/*fprintf(fp, "\n");*/
	fflush(fp);
	fclose(fp);
	return;
}


int testcake_kex_complete_process_print(void)
{
	int iRet=-1;
	int i=0;
	unsigned char ucStaticPkA[PUBLICKEYBYTES+1];
	unsigned char ucStaticSkA[SECRETKEYBYTES+1];
	unsigned char ucPidA[PID_BYTES+1];
	unsigned char ucHA[SECRETKEYBYTES+1];
	
	unsigned char ucStaticPkB[PUBLICKEYBYTES+1];
	unsigned char ucStaticSkB[SECRETKEYBYTES+1];
	unsigned char ucPidB[PID_BYTES+1];
	unsigned char ucHB[SECRETKEYBYTES+1];

	unsigned char ucAtoBMsg[PUBLICKEYBYTES+1];
	unsigned char ucEphSkX[SECRETKEYBYTES+1];
	unsigned char ucEphPkX[PUBLICKEYBYTES+1];
	unsigned char ucEphD[SECRETKEYBYTES+1];

	unsigned char ucBtoAMsg[KEX_PUBLICKEYBYTES+1];
	unsigned char ucK1[SECRETKEYBYTES+1];
	unsigned char ucBSs[KEX_BYTES+1];

	unsigned char ucAtoBMsg2[CIPHER_BYTES+1];
	unsigned char ucASs[KEX_BYTES+1];
	int iCount=1;
	int uCount = 100000;


	printf("begin the complete process test of cake-kex\n");
	printf("the test times of complete cake-kex is [%d]\n",iCount);
	test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"begin the complete process test of cake-kex");
	test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"the test times is [%d]", iCount);

	struct timeval start;
  	struct timeval end;
	struct timeval reg_start;
  	struct timeval reg_end;
  	unsigned long timer;
  	unsigned long reg_timer;
  	gettimeofday(&start, NULL);

	for(i=0;i<iCount;i++)
	{
		test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"test %d",i+1);
		/*to generate A's static pulic,  private static key  and certtificate pid*/
		gettimeofday(&reg_start, NULL);
		
		for (i=0;i<uCount;i++){
			memset(ucStaticPkA,0,sizeof(ucStaticPkA));
			memset(ucStaticSkA,0,sizeof(ucStaticSkA));
			memset(ucPidA,0,sizeof(ucPidA));
			memset(ucHA,0,sizeof(ucHA));
			iRet=cake_kex_keygen(ucStaticPkA, ucStaticSkA, ucPidA, ucHA);
			if(iRet != SUCC)
			{
				printf("A: cake_kex_keygen execute fail!\n");
				test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"A: cake_kex_keygen execute fail!");
				return FAIL;
			}
		}
		gettimeofday(&reg_end,NULL);
  		reg_timer = 1000000 * (reg_end.tv_sec - reg_start.tv_sec) + reg_end.tv_usec - reg_start.tv_usec;
 		printf("reg_timer = %ld us\nave time= %ld us\n",reg_timer, reg_timer/uCount);
		
		test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"-api :cake_kex_keygen");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucStaticPkA, PUBLICKEYBYTES, "A's static pk:");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucStaticSkA, SECRETKEYBYTES, "A's static sk:");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucPidA, PID_BYTES, "A's certtificate pid:");


		/*to generate B's static pulic,  private static key  and certtificate pid*/
		memset(ucStaticPkB,0,sizeof(ucStaticPkB));
		memset(ucStaticSkB,0,sizeof(ucStaticSkB));
		memset(ucPidB,0,sizeof(ucPidA));
		memset(ucHB,0,sizeof(ucHB));
		iRet=cake_kex_keygen(ucStaticPkB, ucStaticSkB, ucPidB, ucHB);
		if(iRet != SUCC)
		{
			printf("B: cake_kex_keygen execute fail!\n");
			test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"B: cake_kex_keygen execute fail!");
			return FAIL;
		}
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucStaticPkB, PUBLICKEYBYTES, "B's static pk:");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucStaticSkB, SECRETKEYBYTES, "B's static sk:");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucPidB, PID_BYTES, "B's certtificate pid:");


		memset(ucAtoBMsg,0,sizeof(ucAtoBMsg));
		memset(ucEphSkX,0,sizeof(ucEphSkX));
		memset(ucEphPkX,0,sizeof(ucEphPkX));
		memset(ucEphD,0,sizeof(ucEphD));
		iRet=cake_kex_kdf_Alice(ucAtoBMsg, ucEphSkX, ucEphPkX, ucEphD, ucStaticPkA, ucPidA);
		if(iRet != SUCC)
		{
			printf("cake_kex_kdf_Alice execute fail!\n");
			test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"cake_kex_kdf_Alice execute fail!");
			return FAIL;
		}
		test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"-api :cake_kex_kdf_Alice");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucAtoBMsg, PUBLICKEYBYTES, "AtoB's message:");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucEphSkX, SECRETKEYBYTES, "A's ephmeral sk:");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucEphPkX, PUBLICKEYBYTES, "A's ephmeral pk:");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucEphD, SECRETKEYBYTES, "A's ephmeral d:");

		memset(ucBtoAMsg,0,sizeof(ucBtoAMsg));
		memset(ucK1, 0, sizeof(ucK1));
		memset(ucBSs,0,sizeof(ucBSs));
		iRet=cake_kex_kdf_Bob(ucBtoAMsg, ucK1,ucAtoBMsg, ucStaticSkB, ucStaticPkB,ucPidB, ucBSs);
		if(iRet != SUCC)
		{
			printf("cake_kex_kdf_Bob execute fail!\n");
			test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"cake_kex_kdf_Bob execute fail!");
			return FAIL;
		}
		test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"-api :cake_kex_kdf_Bob");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucBtoAMsg, KEX_PUBLICKEYBYTES, "BtoA's message:");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucK1, SECRETKEYBYTES, "B's K1:");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucBSs, KEX_BYTES, "B's ss:");

		memset(ucAtoBMsg2, 0, sizeof(ucAtoBMsg2));
		memset(ucASs,0,sizeof(ucASs));
		iRet=cake_kex_kdf_Alice2(ucAtoBMsg2, ucBtoAMsg, ucAtoBMsg, ucStaticPkB, ucEphPkX, ucPidA, ucStaticSkA, ucEphSkX, ucEphD, ucASs, ucHB);
		if(iRet != SUCC)
		{
			printf("cake_kex_kdf_Alice2 execute fail!\n");
			test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"cake_kex_kdf_Alice2 execute fail!");
			return FAIL;
		}
		test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"-api :cake_kex_kdf_Alice2");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucAtoBMsg2, CIPHER_BYTES, "AtoB's message2:");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucASs, KEX_BYTES, "A's ss:");

		iRet=cake_kex_kdf_Bob2(ucAtoBMsg, ucAtoBMsg2, ucStaticPkA, ucK1, ucHA);
		if(SUCC != iRet)
		{
			printf("cake_kex_kdf_Bob2 execute fail!\n");
			test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"cake_kex_kdf_Bob2 execute fail!");
			return FAIL;
		}

		if(0 != memcmp(ucASs,ucBSs,KEX_BYTES))
		{
			printf("the share keys of two party is inconsistent!\n");
			test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"the share keys of two party is inconsistent!");
			return FAIL;
		}

	}
	gettimeofday(&end,NULL);
  	timer = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
 	printf("timer = %ld us\nave time= %ld us\n",timer, timer/iCount);
	
	test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"the complete process test of cake-kex has finished.\n");
	printf("test has finished, the test data has been written in[%s]\n",CAKE_KEX_TEST_DATA_OUTFILE);
	return SUCC;
}


int main(int argc, char *argv[])
{
	int iRet=-1;

	iRet=kex_init();
	if(SUCC != iRet)
		return FAIL;

	iRet=testcake_kex_complete_process_print();
	kex_destroy();
	return SUCC;
}
