#include "checkDll.h"
#include "Crc32Check.h"
#include "md5.h"
#include "sha1.h"
#include <string>
#include <fstream>
using namespace std;

// 获取字符串crc32值
unsigned int GetStringCrc32(const char *buff, int len)
{
	unsigned int ui_ret = getCRC(buff, len);

	return ui_ret;
}

// 获取文件crc32值
unsigned int GetFileCrc32(const char *szCheckFile)
{
	unsigned int ui_ret = getCRC(szCheckFile);

	return ui_ret;
}

// 获取字符串MD5数字签名
void GetStringMd5(unsigned char* input, unsigned int inputLen, unsigned char** digest)
{
	*digest = new unsigned char[16];
	memset(*digest, 0, 16);

	MD5_CTX md5;

	MD5_Init(&md5);
	MD5_Update(&md5, input, inputLen);
	MD5_Final(*digest, &md5);
}

// 获取文件MD5数字签名
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

// 获取字符串SHA1值
EXPORT_INTEFACE void GetStringSHA1(unsigned char* input, unsigned int inputLen, unsigned char** pSHA)
{
	CSHA1 sha1;
	*pSHA = new unsigned char[20];

	sha1.Update(input, strlen((const char*)input));
	sha1.Final();

	sha1.GetHash(*pSHA);
}

// 获取文件SHA1值
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