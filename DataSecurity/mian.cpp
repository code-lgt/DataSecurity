#include<iostream>
#include<windows.h>

#include "include\checkDll.h"
#include "include\desDll.h"
#include "include\rsaDll.h"

using namespace std;

#pragma comment(lib, "lib//RSASecurity.lib")
#pragma comment(lib, "lib//DataCheck.lib")
#pragma comment(lib, "lib//DesSecurity.lib")

// ����һЩ���������ڵ���
#define STR_ENCRY_KEY	"b0fc74401d28879b2b1f5a77e13fd6fc5507c622"
#define STR_PUB_KEY		".//rsapub.key"
#define STR_PRIV_KEY	".//rsapriv.key"
#define STR_TEST_FILE	".//cmdlineFunc.lua"
#define STR_TEST_STRING "asdfsafsdaf===========dfgdfg---------sgdfg\\\\//////67678~~~"
#define STR_PASSWD		"llggtt"

int main(int argc, char *argv[])
{
	printf("********************************************\n");
	printf("*  ��ӭʹ����Ϣ��ȫdemo���Գ���            *\n");
	printf("*  1�������ַ���crc32                      *\n");
	printf("*  2�������ļ�crc32                        *\n");
	printf("*  3�������ַ���MD5ֵ                      *\n");
	printf("*  4�������ļ�MD5ֵ                        *\n");
	printf("*  5��ʹ��DES�㷨����                      *\n");
	printf("*  6��ʹ��DES�㷨����                      *\n");
	printf("*  7��ʹ��RSA�㷨˽Կ����                  *\n");
	printf("*  8��ʹ��RSA�㷨��Կ����                  *\n");
	printf("*  9��ʹ��RSA�㷨��Կ����                  *\n");
	printf("* 10��ʹ��RSA�㷨˽Կ����                  *\n");
	printf("* 11��ʹ��RSA�㷨˽Կ����,��Կ����(�ַ���) *\n");
	printf("* 12��ʹ��RSA�㷨��Կ����,˽Կ����(�ַ���) *\n");
	printf("* 13�������ַ���SHA1                       *\n");
	printf("* 14�������ļ�SHA1                         *\n");
	printf("********************************************\n");

	while (true)
	{
		printf("input num:");
		int iNo;
		scanf("%d", &iNo);

		switch (iNo)
		{
		case 0:
			exit(0);
		case 1:
		{
			unsigned int crc32 = GetStringCrc32(STR_TEST_STRING, strlen(STR_TEST_STRING));
			printf("crc32-val: %X\n", crc32);
		}
			break;
		case 2:
		{
			unsigned int crc32 = GetFileCrc32(STR_TEST_FILE);
			printf("crc32-val: %X\n", crc32);
		}
			break;
		case 3:
		{
			unsigned char* digest = NULL;
			GetStringMd5((unsigned char*)STR_TEST_STRING, strlen(STR_TEST_STRING), &digest);
			
			printf("md5-val: ");
			for (int i = 0; i < 16; i++)
			{
				printf("%02X", digest[i]);
			}
			printf("\n");
		}
			break;
		case 4:
		{
			unsigned char* digest = NULL;
			GetFileMd5(STR_TEST_FILE, &digest);

			printf("md5-val: ");
			for (int i = 0; i < 16; i++)
			{
				printf("%02X", digest[i]);
			}
			printf("\n");
		}
			break;
		case 5:
			EncryptSignalLua(STR_TEST_FILE, STR_ENCRY_KEY);
			break;
		case 6:
			DecryptSignalLua(STR_TEST_FILE, STR_ENCRY_KEY);
			break;
		case 7:
		{
			// ������Կ�ļ�
			RSAGenerateKeyFiles(STR_PUB_KEY, STR_PRIV_KEY, (const unsigned char*)STR_PASSWD, strlen(STR_PASSWD));

			// �����ļ�
			RSAPrivateEncryptFile(STR_TEST_FILE, STR_PRIV_KEY, (const unsigned char*)STR_PASSWD);
		}
			break;
		case 8:
			// �����ļ�
			RSAPublicDecryptFile(STR_TEST_FILE, STR_PUB_KEY);
			break;
		case 9:
		{
			// ������Կ�ļ�
			RSAGenerateKeyFiles(STR_PUB_KEY, STR_PRIV_KEY, (const unsigned char*)STR_PASSWD, strlen(STR_PASSWD));

			// �����ļ�
			RSAPublicEncryptFile(STR_TEST_FILE, STR_PUB_KEY);
		}
		break;
		case 10:
			// �����ļ�
			RSAPrivateDecryptFile(STR_TEST_FILE, STR_PRIV_KEY, (const unsigned char*)STR_PASSWD);
			break;
		case 11:
		{
			// ������Կ�ļ�
			RSAGenerateKeyFiles(STR_PUB_KEY, STR_PRIV_KEY, (const unsigned char*)STR_PASSWD, strlen(STR_PASSWD));

			char *szSrc = STR_TEST_STRING;
			printf("src-in: %s\n", szSrc);
			unsigned char *encrypt_out = NULL;
			unsigned char *decrypt_out = NULL;
			int encrypt_len = 0;
			int decrypt_len = 0;

			RSAPrivateEncryptString((const unsigned char*)szSrc, strlen(szSrc),
				&encrypt_out, encrypt_len, STR_PRIV_KEY, (const unsigned char*)STR_PASSWD);
			printf("encrypt-out: %s\n", encrypt_out);

			RSAPublicDecryptString(encrypt_out, encrypt_len,
				&decrypt_out, decrypt_len, STR_PUB_KEY);
			printf("decrypt-out: %s\n", decrypt_out);
		}
			break;
		case 12:
		{
			// ������Կ�ļ�
			RSAGenerateKeyFiles(STR_PUB_KEY, STR_PRIV_KEY, (const unsigned char*)STR_PASSWD, strlen(STR_PASSWD));

			char *szSrc = STR_TEST_STRING;
			printf("src-in: %s\n", szSrc);
			unsigned char *encrypt_out = NULL;
			unsigned char *decrypt_out = NULL;
			int encrypt_len = 0;
			int decrypt_len = 0;

			RSAPublicEncryptString((const unsigned char*)szSrc, strlen(szSrc),
				&encrypt_out, encrypt_len, STR_PUB_KEY);
			printf("encrypt-out: %s\n", encrypt_out);

			RSAPrivateDecryptString(encrypt_out, encrypt_len,
				&decrypt_out, decrypt_len, STR_PRIV_KEY, (const unsigned char*)STR_PASSWD);
			printf("decrypt-out: %s\n", decrypt_out);
		}
			break;
		case 13:
		{
			unsigned char* pSHA1 = NULL;
			GetStringSHA1((unsigned char*)STR_TEST_STRING, strlen(STR_TEST_STRING), &pSHA1);

			printf("sha1-val: ");
			for (int i = 0; i < 20; i++)
			{
				printf("%02X", pSHA1[i]);
			}
			printf("\n");
		}
			break;
		case 14:
		{
			unsigned char* pSHA1 = NULL;
			GetFileSHA1(STR_TEST_FILE, &pSHA1);

			printf("sha1-val: ");
			for (int i = 0; i < 20; i++)
			{
				printf("%02X", pSHA1[i]);
			}
			printf("\n");
		}
			break;
		default:
			break;
		}
	}

	return 0;
}