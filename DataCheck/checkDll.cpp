#include "checkDll.h"
#include "Crc32Check.h"
#include "md5.h"
#include "sha1.h"
#include <string>
#include <fstream>
using namespace std;

// ��ȡ�ַ���crc32ֵ
unsigned int GetStringCrc32(const char *buff, int len)
{
	unsigned int ui_ret = getCRC(buff, len);

	return ui_ret;
}

// ��ȡ�ļ�crc32ֵ
unsigned int GetFileCrc32(const char *szCheckFile)
{
	unsigned int ui_ret = getCRC(szCheckFile);

	return ui_ret;
}

// ��ȡ�ַ���MD5����ǩ��
void GetStringMd5(unsigned char* input, unsigned int inputLen, unsigned char** digest)
{
	*digest = new unsigned char[16];
	memset(*digest, 0, 16);

	MD5_CTX md5;

	MD5_Init(&md5);
	MD5_Update(&md5, input, inputLen);
	MD5_Final(*digest, &md5);
}

// ��ȡ�ļ�MD5����ǩ��
void GetFileMd5(const char* szCheckFile, unsigned char **digest)
{
	*digest = new unsigned char[16];
	memset(*digest, 0, 16);

	ifstream t(szCheckFile, ios::binary);
	string buffer((istreambuf_iterator<char>(t)),
		istreambuf_iterator<char>());
	t.close();

	MD5_CTX md5;

	MD5_Init(&md5);
	MD5_Update(&md5, (unsigned char*)buffer.c_str(), buffer.length());

	MD5_Final(*digest, &md5);
}

// ��ȡ�ַ���SHA1ֵ
EXPORT_INTEFACE void GetStringSHA1(unsigned char* input, unsigned int inputLen, unsigned char** pSHA)
{
	CSHA1 sha1;
	*pSHA = new unsigned char[20];

	sha1.Update(input, strlen((const char*)input));
	sha1.Final();

	sha1.GetHash(*pSHA);
}

// ��ȡ�ļ�SHA1ֵ
EXPORT_INTEFACE void GetFileSHA1(const char* szCheckFile, unsigned char **pSHA)
{
	CSHA1 sha1;
	*pSHA = new unsigned char[20];

	ifstream t(szCheckFile, ios::binary);
	string buffer((istreambuf_iterator<char>(t)),
		istreambuf_iterator<char>());
	t.close();

	sha1.Update((unsigned char*)buffer.c_str(), buffer.length());
	sha1.Final();

	sha1.GetHash(*pSHA);
}