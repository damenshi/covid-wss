
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


int testcake_kex_complete_process_print()
{
	int iRet=-1;
	int i=0;
	unsigned char ucStaticPkA[PUBLICKEYBYTES+1];
	unsigned char ucStaticSkA[SECRETKEYBYTES+1];
	unsigned char ucHA[SECRETKEYBYTES+1];
	
	unsigned char ucStaticPkB[PUBLICKEYBYTES+1];
	unsigned char ucStaticSkB[SECRETKEYBYTES+1];
	unsigned char ucHB[SECRETKEYBYTES+1];

	unsigned char ucPidA[PID_BYTES+1];
	unsigned char ucrB[SECRETKEYBYTES+1];
	unsigned char ucCertA[PUBLICKEYBYTES*2+1];

	unsigned char ucPidB[PID_BYTES+1];
	unsigned char ucrA[SECRETKEYBYTES+1];
	unsigned char ucCertB[PUBLICKEYBYTES*2+1];
	int iCount=100000;


	printf("begin the complete process test of cake-kex\n");
	printf("the test times of complete cake-kex is [%d]\n",iCount);
	test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"begin the complete process test of cake-kex");
	test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"the test times is [%d]", iCount);

	struct timeval start;
  	struct timeval end;
  	unsigned long timer;
  	gettimeofday(&start, NULL);

	for(i=0;i<iCount;i++)
	{
	/*first: Alice let Bob validate his packge*/
		test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"test %d",i+1);
		/*to generate A's static pulic,  private static key  and certtificate pid*/
		memset(ucStaticPkA,0,sizeof(ucStaticPkA));
		memset(ucStaticSkA,0,sizeof(ucStaticSkA));
		memset(ucHA,0,sizeof(ucHA));
		memset(ucPidA,0,sizeof(ucPidA));
		memset(ucrB,0,sizeof(ucrB));
		memset(ucCertA,0,sizeof(ucCertA));

		iRet=send_pid(ucPidA, ucStaticPkA, ucStaticSkA, ucHA);
		if(iRet != SUCC)
		{
			printf("A: send pid fail!\n");
			test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"A: send pid fail!");
			return FAIL;
		}
		test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"-api :send_pid");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucStaticPkA, PUBLICKEYBYTES, "A's static pk:");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucStaticSkA, SECRETKEYBYTES, "A's static sk:");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucPidA, PID_BYTES, "A's certtificate pid:");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucHA, PUBLICKEYBYTES, "HA:");


		iRet=send_r(ucrB, ucHA, ucPidA);
		if(iRet != SUCC)
		{
			printf("send rB to A fail!\n");
			test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"send rB to A fail!");
			return FAIL;
		}
		test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"-api :send_r");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucrB, SECRETKEYBYTES, "rB:");

		
		iRet=send_cert_bar(ucCertA, ucrB, ucStaticSkA);
		if(iRet != SUCC)
		{
			printf("cend certA to B execute fail!\n");
			test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"cend certA to B execute fail!");
			return FAIL;
		}
		test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"-api :send_cert_bar");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucCertA, KEX_PUBLICKEYBYTES, "A's cert:");

		
		iRet=kex_verify(ucPidA, ucrB, ucCertA, ucStaticPkA);
		if(iRet != SUCC)
		{
			printf("B verify A's sig execute fail!\n");
			test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"B verify A's sig execute fail!");
			return FAIL;
		}
		test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"-api :kex_verify");

	/*second: Bob let Alice validate his packge*/
		/*to generate B's static pulic,  private static key  and certtificate pid*/
		memset(ucStaticPkB,0,sizeof(ucStaticPkB));
		memset(ucStaticSkB,0,sizeof(ucStaticSkB));
		memset(ucHB,0,sizeof(ucHB));
		memset(ucPidB,0,sizeof(ucPidB));
		memset(ucrA,0,sizeof(ucrA));
		memset(ucCertB,0,sizeof(ucCertB));
		iRet=send_pid(ucPidB, ucStaticPkB, ucStaticSkB, ucHB);

		if(iRet != SUCC)
		{
			printf("B: send pid execute fail!\n");
			test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"B: send pid execute fail!");
			return FAIL;
		}
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucStaticPkB, PUBLICKEYBYTES, "B's static pk:");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucStaticSkB, SECRETKEYBYTES, "B's static sk:");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucPidB, PID_BYTES, "B's certtificate pid:");

		iRet=send_r(ucrA, ucHB, ucPidB);
		if(iRet != SUCC)
		{
			printf("send rA to B execute fail!\n");
			test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"send rA to B execute fail!");
			return FAIL;
		}
		test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"-api :send_r");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucrA, SECRETKEYBYTES, "rA:");

		
		iRet=send_cert_bar(ucCertB, ucrA, ucStaticSkB);
		if(iRet != SUCC)
		{
			printf("cend certB to A execute fail!\n");
			test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"cend certB to A execute fail!");
			return FAIL;
		}
		test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"-api :send_cert_bar");
		test_writehexf(CAKE_KEX_TEST_DATA_OUTFILE, ucCertB, KEX_PUBLICKEYBYTES, "B's cert:");

		
		iRet=kex_verify(ucPidB, ucrA, ucCertB, ucStaticPkB);
		if(iRet != SUCC)
		{
			printf("A verify B's sig execute fail!\n");
			test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"A verify B's sig execute fail!");
			return FAIL;
		}
		test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"-api :kex_verify");


	}
	gettimeofday(&end,NULL);
  	timer = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
 	printf("timer = %ld us\nave time= %ld us\n",timer, timer/iCount);
	
	test_writef(CAKE_KEX_TEST_DATA_OUTFILE,"the complete process test of cake-kex has finished.\n");
	printf("test has finished, the test data has been written in[%s]\n",CAKE_KEX_TEST_DATA_OUTFILE);
	return SUCC;
}


int main()
{
	int iRet=-1;

	iRet=kex_init();
	if(SUCC != iRet)
		return FAIL;

	iRet=testcake_kex_complete_process_print();
	kex_destroy();
	return SUCC;
}
