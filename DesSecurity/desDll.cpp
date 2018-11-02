#include <string>  
#include <fstream>  
#include <streambuf> 
#include "des.h"
#include "cbase64.h"
#include "desDll.h"
using namespace std;

// 加/解密密钥
#define STR_ENCRY_KEY	"b0fc74401d28879b2b1f5a77e13fd6fc5507c622"

// 对单个文件加/解密
void EncryptSignalLua(const char* szPath, const char *szKey)
{
#if 0
	std::ifstream t;
	int length;
	t.open(strcat(".//", szPath));  // open input file  
	t.seekg(0, std::ios::end);		// go to the end  
	length = t.tellg();				// report location (this is the length)  
	t.seekg(0, std::ios::beg);		// go back to the beginning  
	char *buffer = new char[length];    // allocate memory for a buffer of appropriate dimension  
	t.read(buffer, length);			// read the whole file into the buffer  
	t.close();						// close file handle
#else
	string comple_path(".//");
	comple_path += szPath;
	ifstream t(comple_path, ios::binary);
	string buffer((istreambuf_iterator<char>(t)),
		istreambuf_iterator<char>());
	t.close();
#endif

	// base64编码，用于des算法加密
	char *szBase64 = base64_encode(buffer.c_str(), buffer.length());

	// DES算法加密
	DES *pDes = new DES();
	string strDst = pDes->Encrypt(szBase64, szKey);

	ofstream oft(comple_path, ios::binary);
	oft.write(strDst.c_str(), strDst.length());

	delete[] szBase64;
	delete pDes;

}

// 对单个文件解密
void DecryptSignalLua(const char* szPath, const char *szKey)
{
	string comple_path(".//");
	comple_path += szPath;
	ifstream t(comple_path, ios::binary);
	string buffer((istreambuf_iterator<char>(t)),
		istreambuf_iterator<char>());

	// DES算法解密
	DES *pDes = new DES();
	string strDst = pDes->Decrypt(buffer, szKey);

	// base64编码
	char *szBase64 = base64_decode(strDst.c_str(), strDst.length());
	strDst = szBase64;

	ofstream oft(comple_path, ios::binary);
	oft.write(strDst.c_str(), strDst.length());

	delete[] szBase64;
	delete pDes;
}

// 对字符串加密
void EncryptSignalString(const char *in, int in_len, char *out, int &out_len, const char *szKey)
{
	// base64编码，用于des算法加密
	char *szBase64 = base64_encode(in, in_len);

	// DES算法加密
	DES *pDes = new DES();
	string strDst = pDes->Encrypt(szBase64, szKey);

	out_len = strDst.length();
	memcpy(out, strDst.c_str(), out_len);
}

// 对字符串解密
void DecryptSignalString(const char *in, int in_len, char *out, int &out_len, const char *szKey)
{
	// DES算法解密
	DES *pDes = new DES();
	string srcData(in, in + in_len);
	string strDst = pDes->Decrypt(srcData, szKey);

	// base64编码
	char *szBase64 = base64_decode(strDst.c_str(), strDst.length());
	strDst = szBase64;

	out_len = strDst.length();
	memcpy(out, strDst.c_str(), out_len);
}