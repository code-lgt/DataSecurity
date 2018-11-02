#include "rsaDll.h"
#include "rsa_op.h"
#include <fstream>
using namespace std;

// 生成公、私钥文件
int RSAGenerateKeyFiles(const char *pub_keyfile, const char *pri_keyfile,
	const unsigned char *passwd, int passwd_len)
{
	rsa_op ro;

	int iRet = ro.generate_key_files(pub_keyfile, pri_keyfile, passwd, passwd_len);

	return iRet;
}

// 私钥加密，公钥解密（文件）
int RSAPrivateEncryptFile(const char* encrypt_path, const char* pri_key_path, const unsigned char* passwd)
{
	ifstream fInput(encrypt_path, ios::binary);
	string buffer((istreambuf_iterator<char>(fInput)),
		istreambuf_iterator<char>());
	fInput.close();

	int origin_len = buffer.length();

	int out_len = 0;
	unsigned char *out_data = NULL;
	rsa_op ro;

	ro.open_private_key(pri_key_path, (unsigned char*)passwd);
	int iRet = ro.en_decrypt_template((const unsigned char *)buffer.c_str(), origin_len, (unsigned char **)&out_data, out_len, PRIVATE_ENCRYPT_FUNC);

	ofstream fOutput(encrypt_path, ios::binary);
	fOutput.write((char*)out_data, out_len);
	fOutput.close();

	delete[] out_data;
	return iRet;
}

int RSAPublicDecryptFile(const char* decrypt_path, const char* pub_key_path)
{
	ifstream fInput(decrypt_path, ios::binary);
	string buffer((istreambuf_iterator<char>(fInput)),
		istreambuf_iterator<char>());
	fInput.close();

	int origin_len = buffer.length();

	int out_len = 0;
	unsigned char *out_data = NULL;
	rsa_op ro;

	ro.open_public_key(pub_key_path);
	int iRet = ro.en_decrypt_template((const unsigned char *)buffer.c_str(), origin_len, (unsigned char **)&out_data, out_len, PUBLIC_DECRYPT_FUNC);

	ofstream fOutput(decrypt_path, ios::binary);
	fOutput.write((char*)out_data, out_len);
	fOutput.close();

	delete[] out_data;
	return iRet;
}

// 公钥加密，私钥解密（文件）
int RSAPublicEncryptFile(const char* encrypt_path, const char* pub_key_path)
{
	ifstream fInput(encrypt_path, ios::binary);
	string buffer((istreambuf_iterator<char>(fInput)),
		istreambuf_iterator<char>());
	fInput.close();

	int origin_len = buffer.length();

	int out_len = 0;
	unsigned char *out_data = NULL;
	rsa_op ro;

	ro.open_public_key(pub_key_path);
	int iRet = ro.en_decrypt_template((const unsigned char *)buffer.c_str(), origin_len, (unsigned char **)&out_data, out_len, PUBLIC_ENCRYPT_FUNC);

	ofstream fOutput(encrypt_path, ios::binary);
	fOutput.write((char*)out_data, out_len);
	fOutput.close();

	delete[] out_data;
	return iRet;
}

int RSAPrivateDecryptFile(const char* decrypt_path, const char* pri_key_path, const unsigned char* passwd)
{
	ifstream fInput(decrypt_path, ios::binary);
	string buffer((istreambuf_iterator<char>(fInput)),
		istreambuf_iterator<char>());
	fInput.close();

	int origin_len = buffer.length();

	int out_len = 0;
	unsigned char *out_data = NULL;
	rsa_op ro;

	ro.open_private_key(pri_key_path, (unsigned char*)passwd);
	int iRet = ro.en_decrypt_template((const unsigned char *)buffer.c_str(), origin_len, (unsigned char **)&out_data, out_len, PRIVATE_DECRYPT_FUNC);

	ofstream fOutput(decrypt_path, ios::binary);
	fOutput.write((char*)out_data, out_len);
	fOutput.close();

	delete[] out_data;
	return iRet;
}

// 私钥加密，公钥解密（字符串）
int RSAPrivateEncryptString(const unsigned char *in, int in_len,
	unsigned char **out, int &out_len, const char* pri_key_path, const unsigned char* passwd)
{
	rsa_op ro;

	ro.open_private_key(pri_key_path, (unsigned char*)passwd);

	int iRet = ro.en_decrypt_template((const unsigned char *)in, in_len, (unsigned char **)out, out_len, PRIVATE_ENCRYPT_FUNC);

	return iRet;
}

int RSAPublicDecryptString(const unsigned char *in, int in_len,
	unsigned char **out, int &out_len, const char* pub_key_path)
{
	rsa_op ro;

	ro.open_public_key(pub_key_path);

	int iRet = ro.en_decrypt_template((const unsigned char *)in, in_len, (unsigned char **)out, out_len, PUBLIC_DECRYPT_FUNC);

	return iRet;
}

// 公钥加密，私钥解密（字符串）
int RSAPublicEncryptString(const unsigned char *in, int in_len,
	unsigned char **out, int &out_len, const char* pub_key_path)
{
	rsa_op ro;

	ro.open_public_key(pub_key_path);

	int iRet = ro.en_decrypt_template((const unsigned char *)in, in_len, (unsigned char **)out, out_len, PUBLIC_ENCRYPT_FUNC);

	return iRet;
}

int RSAPrivateDecryptString(const unsigned char *in, int in_len,
	unsigned char **out, int &out_len, const char* pri_key_path, const unsigned char* passwd)
{
	rsa_op ro;

	ro.open_private_key(pri_key_path, (unsigned char*)passwd);

	int iRet = ro.en_decrypt_template((const unsigned char *)in, in_len, (unsigned char **)out, out_len, PRIVATE_DECRYPT_FUNC);

	return iRet;
}