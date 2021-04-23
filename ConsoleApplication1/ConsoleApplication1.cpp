// ConsoleApplication1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <Windows.h>
//#include <string>
#include <direct.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h> 
#include <openssl/crypto.h> 
using namespace std;

#define BUFSIZE 1024*8

#define PUBLIC_KEY_PATH  ("./rsa_client_2048.pem")
#define PRIVATE_KEY_PATH ("./rsa_client_2048.key")


void printHex(unsigned char *md, int len)
{

	int i = 0;
	for (i = 0; i < len; i++)
	{
		printf("%02x", md[i]);
	}

	printf("\n");
}


/*读取私钥*/
EVP_PKEY* ReadPrivateKey(char* p_KeyPath)
{
	EVP_PKEY  *priRsa = NULL;
	BIO *in;

	in = BIO_new_file(p_KeyPath, "r");
	if (in == NULL) {
		printf("BIO_s_file\n");
		goto end;
	}

	printf("PrivateKeyPath[%s] \n", p_KeyPath);

	/*  获取私钥 */
	priRsa = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);

end:
	BIO_free(in);

	return priRsa;
}

int PKCS7_SignFile(char* infile, char *signerfile, char *keyfile, char *FilePath, unsigned char **SignBuffer)
{
	PKCS7 *p7 = NULL;
	STACK_OF(X509) *encerts = NULL, *other = NULL;
	BIO *in;
	int flags = PKCS7_DETACHED;
	STACK_OF(OPENSSL_STRING) *sksigners = NULL, *skkeys = NULL;
	sksigners = sk_OPENSSL_STRING_new_null();
	skkeys = sk_OPENSSL_STRING_new_null();

	sk_OPENSSL_STRING_push(sksigners, signerfile);
	sk_OPENSSL_STRING_push(skkeys, keyfile);

	in = BIO_new_file(infile, "rb");
	if (in == NULL)
	{
		//错误处理
	}

	flags |= PKCS7_STREAM;
	flags |= PKCS7_PARTIAL;
	p7 = PKCS7_sign(NULL, NULL, other, in, flags);
}

int SignFile(char *FilePath, unsigned char **SignBuffer)
{
	RSA *pubKey = NULL;
	RSA *privKey = NULL;
	EVP_PKEY *prikey = NULL;
	const EVP_MD *md = NULL;
	int nRet = 0;
	BIO *bmd = NULL, *in = NULL, *inp = NULL;

	EVP_MD_CTX *mctx = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	int r;

	md = EVP_get_digestbyname("sha1");
	bmd = BIO_new(BIO_f_md());
	in = BIO_new(BIO_s_file());
	if ((in == NULL) || (bmd == NULL)) {
		printf("Error BIO new\n");
		//ERR_print_errors(bio_err);
		goto quit;
	}

	if (!BIO_get_md_ctx(bmd, &mctx)) {
		//BIO_printf(bio_err, "Error getting context\n");
		//ERR_print_errors(bio_err);
		printf("Error getting context\n");
		goto quit;
	}
	// 2. 读取私钥

	prikey = ReadPrivateKey(PRIVATE_KEY_PATH);
	if (!prikey)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}

	// 3. 签名
	r = EVP_DigestSignInit(mctx, &pctx, md, NULL, prikey);
	if (!r) {
		//BIO_printf(bio_err, "Error setting context\n");
		//ERR_print_errors(bio_err);
		printf("Error setting context\n");
		goto quit;
	}

	inp = BIO_push(bmd, in);

	EVP_MD_CTX *tctx;
	BIO_get_md_ctx(bmd, &tctx);
	md = EVP_MD_CTX_md(tctx);

	BIO_read_filename(in, FilePath);

	unsigned char *buf = (unsigned char *)calloc(1, BUFSIZE);
	int i = 0;
	size_t len;

	for (;;) {
		i = BIO_read(inp, (char *)buf, BUFSIZE);
		if (i < 0) {
			//BIO_printf(bio_err, "Read Error in %s\n", file);
			//ERR_print_errors(bio_err);
			printf("Error BIO_read\n");
			goto quit;
		}
		if (i == 0)
			break;
	}

	EVP_MD_CTX *ctx;
	BIO_get_md_ctx(inp, &ctx);
	len = BUFSIZE;
	if (!EVP_DigestSignFinal(ctx, buf, &len)) {
		//BIO_printf(bio_err, "Error Signing Data\n");
		//ERR_print_errors(bio_err);
		printf("Error EVP_DigestSignFinal\n");
		return 1;
	}

	printHex((unsigned char *)buf, len);
	//free(buf);

	*SignBuffer = buf;

quit:
	RSA_free(privKey);

	BIO_free(in);
	BIO_free(bmd);
	//BIO_free(inp);

	return 0;
}

static unsigned int pe_cksum(unsigned short int *addr, unsigned int len, unsigned long long base_sum)
{
	unsigned int        nleft = len;
	unsigned long long  sum = ~base_sum + 1;
	unsigned short int *w = addr;
	unsigned short int  answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (1 == nleft)
	{
		*(unsigned char *)(&answer) = *(unsigned char *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);

	sum += (sum >> 16);

	answer = (unsigned short)(sum & 0xFFFF);

	sum = answer + len;
	return((unsigned int)sum);
}


LPCSTR wtoc(LPCWSTR wText)
{
	DWORD dwNum = WideCharToMultiByte(CP_ACP, NULL, wText, -1, NULL, 0, NULL, FALSE);//把第五个参数设成NULL的到宽字符串的长度包括结尾符
	char *psText = NULL;
	psText = new char[dwNum];
	if (!psText)
	{
		delete[]psText;
		psText = NULL;
	}
	WideCharToMultiByte(CP_ACP, NULL, wText, -1, psText, dwNum, NULL, FALSE);
	LPCSTR ret = psText;
	delete[]psText;
	return ret;
}

BOOL OpenFile(HANDLE *hFile, HANDLE *hFileMapping, LPVOID *lpBase, char *lpFileName)
{
	BOOL ret = FALSE;
	HANDLE hFile_t = NULL, hFileMapping_t = NULL;
	LPVOID lpBase_t = NULL;

	hFile_t = CreateFile(lpFileName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile_t == INVALID_HANDLE_VALUE) {
		printf("Open File Failed!\n");
		system("pause");
		return ret;
	}

	hFileMapping_t = CreateFileMapping(hFile_t, NULL, PAGE_READWRITE, 0, 0, 0);
	if (hFileMapping_t == NULL) {
		printf("Create Mapping File Failed!\n");
		CloseHandle(hFile_t);
		return ret;
	}

	lpBase_t = MapViewOfFile(hFileMapping_t, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if (lpBase_t == NULL) {
		printf("Failed to Map the File!\n");
		CloseHandle(hFileMapping_t);
		CloseHandle(hFile_t);
	}

	*hFile = hFile_t;
	*hFileMapping = hFileMapping_t;
	*lpBase = lpBase_t;

	ret = TRUE;

	return ret;
}

BOOL PE_CheckSum(HANDLE *hFile, LPVOID *lpBase)
{
	BOOL bRet = FALSE;
	DWORD HeadCheckSum = 0, MyCheckSum = 0;
	DWORD FileSize = 0, FileSizeHigh = 0;

	FileSize = GetFileSize(*hFile, 0);

	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)(*lpBase);
	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((PCHAR)pIDH + pIDH->e_lfanew);

	HeadCheckSum = pINH->OptionalHeader.CheckSum;
	pINH->OptionalHeader.CheckSum = 0;

	MyCheckSum = pe_cksum((unsigned short *)(*lpBase), FileSize, 0);
	printf("My CheckSum2 is : 0x%08X\n", MyCheckSum);
	pINH->OptionalHeader.CheckSum = HeadCheckSum;
	printf("HeadCheckSum set done!\n");

	if (HeadCheckSum == MyCheckSum)
	{
		bRet = TRUE;
		printf("HeadCheckSum equal!\n");
	}

	return bRet;
}

int main(int argc, char* argv[])
{
	BOOL ret = FALSE;
	HANDLE hFile = NULL, hFileMapping = NULL;
	LPVOID lpBase = NULL;
	unsigned char *SignBuffer;
	if (argc<2)
	{
		printf("usage %s c:\\myfile.exe\n", argv[0]);
		system("pause");
		return 0;
	}

	SignFile(argv[0], &SignBuffer);

	ret = OpenFile(&hFile, &hFileMapping, &lpBase, argv[1]);
	if (ret == FALSE)
	{
		printf("Open file failed!\n");

		return -1;
	}

	ret = PE_CheckSum(&hFile, &lpBase);
	if (ret == FALSE)
	{
		printf("calculate checksum failed\n");
	}

	UnmapViewOfFile(lpBase);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
	//free(SignBuffer);
	system("pause");
	return 0;
}

