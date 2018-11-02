#pragma once

/* 参考文献：https://blog.csdn.net/fenghaibo00/article/details/17249493 */

#include <openssl/ossl_typ.h>

#define PRIVATE_KEY_FILE	".//rsapriv.key"
#define PUBLIC_KEY_FILE		".//rsapub.key"

#define RSA_KEY_LENGTH 1024

#define PART_ENCRYPT_LEN 100	// 分段加密长度
#define PART_DECRYPT_LEN 128	// 分段解密长度

static const char rnd_seed[] = "string to make the random number generator initialized";

class rsa_op;
typedef int(rsa_op::*template_func)(const unsigned char *in, int in_len,
	unsigned char **out, int &out_len);

// 加密库内部接口类型
enum FUNC_TYPE
{
	PRIVATE_ENCRYPT_FUNC = 0,
	PUBLIC_DECRYPT_FUNC,
	PUBLIC_ENCRYPT_FUNC,
	PRIVATE_DECRYPT_FUNC,
};

typedef struct TemplateArg
{
	int part_len;
	template_func p_func;
}TemplateArg;

class rsa_op
{
public:
	rsa_op();
	~rsa_op();

	// 生成公钥文件和私钥文件，私钥文件带密码
	int generate_key_files(const char *pub_keyfile, const char *pri_keyfile,
		const unsigned char *passwd, int passwd_len);

	// 打开公钥文件，返回EVP_PKEY结构的指针
	int open_public_key(const char *keyfile);

	// 打开私钥文件，返回EVP_PKEY结构的指针
	int open_private_key(const char *keyfile, const unsigned char *passwd);

	// 分段处理，私钥加密，公钥解密
	int en_decrypt_template(const unsigned char *in, int in_len,
		unsigned char **out, int &out_len, FUNC_TYPE funcType);
private:

	int close_key();

	// private key to encryption and public key to decryption
	int prikey_encrypt(const unsigned char *in, int in_len,
		unsigned char **out, int &out_len);

	int pubkey_decrypt(const unsigned char *in, int in_len,
		unsigned char **out, int &out_len);

	// public key to encryption and private key to decryption
	int pubkey_encrypt(const unsigned char *in, int in_len,
		unsigned char **out, int &out_len);

	int prikey_decrypt(const unsigned char *in, int in_len,
		unsigned char **out, int &out_len);

	RSA *_pub_key;
	RSA *_pri_key;

	TemplateArg m_optList[4];
};

