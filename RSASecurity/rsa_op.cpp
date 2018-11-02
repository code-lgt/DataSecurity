
#include <stdio.h>   // rsa_op.cpp

#include <string.h>

#include <openssl/evp.h>

#include <openssl/rand.h>

#include <openssl/rsa.h>

#include <openssl/pem.h>

#include <openssl/err.h>

#include "rsa_op.h"

rsa_op::rsa_op()
{
	m_optList[0].part_len = PART_ENCRYPT_LEN;
	m_optList[0].p_func = &rsa_op::prikey_encrypt;

	m_optList[1].part_len = PART_DECRYPT_LEN;
	m_optList[1].p_func = &rsa_op::pubkey_decrypt;

	m_optList[2].part_len = PART_ENCRYPT_LEN;
	m_optList[2].p_func = &rsa_op::pubkey_encrypt;

	m_optList[3].part_len = PART_DECRYPT_LEN;
	m_optList[3].p_func = &rsa_op::prikey_decrypt;

	_pub_key = NULL;
	_pri_key = NULL;
}

rsa_op::~rsa_op()
{
	close_key();
}

// 生成公钥文件和私钥文件，私钥文件带密码
int rsa_op::generate_key_files(const char *pub_keyfile, const char *pri_keyfile,
	const unsigned char *passwd, int passwd_len)
{

	RSA *rsa = NULL;
	RAND_seed(rnd_seed, sizeof(rnd_seed));
	rsa = RSA_generate_key(RSA_KEY_LENGTH, RSA_F4, NULL, NULL);

	if (rsa == NULL)
	{
		printf("RSA_generate_key error!\n");
		return -1;
	}

	// 开始生成公钥文件
	BIO *bp = BIO_new(BIO_s_file());
	if (NULL == bp)
	{
		printf("generate_key bio file new error!\n");
		return -1;
	}

	if (BIO_write_filename(bp, (void *)pub_keyfile) <= 0)
	{
		printf("BIO_write_filename error!\n");
		return -1;
	}

	if (PEM_write_bio_RSAPublicKey(bp, rsa) != 1)
	{
		printf("PEM_write_bio_RSAPublicKey error!\n");
		return -1;
	}

	// 公钥文件生成成功，释放资源
	printf("Create public key ok!\n");
	BIO_free_all(bp);

	// 生成私钥文件
	bp = BIO_new_file(pri_keyfile, "w+");
	if (NULL == bp)
	{
		printf("generate_key bio file new error2!\n");
		return -1;
	}

	if (PEM_write_bio_RSAPrivateKey(bp, rsa,
		EVP_des_ede3_ofb(), (unsigned char *)passwd,
		passwd_len, NULL, NULL) != 1)
	{
		printf("PEM_write_bio_RSAPublicKey error!\n");
		return -1;
	}

	// 释放资源
	printf("Create private key ok!\n");
	BIO_free_all(bp);
	RSA_free(rsa);

	return 0;
}

// 打开公钥文件，返回EVP_PKEY结构的指针
int rsa_op::open_public_key(const char *keyfile)
{
	_pub_key = RSA_new();

	OpenSSL_add_all_algorithms();
	BIO *bp = BIO_new(BIO_s_file());;
	BIO_read_filename(bp, keyfile);

	if (NULL == bp)
	{
		printf("open_public_key bio file new error!\n");
		return -1;
	}

	_pub_key = PEM_read_bio_RSAPublicKey(bp, NULL, NULL, NULL);
	if (_pub_key == NULL)
	{
		printf("open_public_key failed to PEM_read_bio_RSAPublicKey!\n");
		BIO_free(bp);
		RSA_free(_pub_key);

		return -1;
	}

	printf("open_public_key success to PEM_read_bio_RSAPublicKey!\n");
	return 0;
}

// 打开私钥文件，返回EVP_PKEY结构的指针
int rsa_op::open_private_key(const char *keyfile, const unsigned char *passwd)
{
	_pri_key = RSA_new();
	OpenSSL_add_all_algorithms();
	BIO *bp = NULL;

	bp = BIO_new_file(keyfile, "rb");
	if (NULL == bp)
	{
		printf("open_private_key bio file new error!\n");
		return -1;
	}

	_pri_key = PEM_read_bio_RSAPrivateKey(bp, &_pri_key, NULL, (void *)passwd);
	if (_pri_key == NULL)
	{
		printf("open_private_key failed to PEM_read_bio_RSAPrivateKey!\n");
		BIO_free(bp);
		RSA_free(_pri_key);

		return NULL;
	}

	printf("open_private_key success to PEM_read_bio_RSAPrivateKey!\n");
	return 0;
}

// 私钥加密函数
int rsa_op::prikey_encrypt(const unsigned char *in, int in_len,
	unsigned char **out, int &out_len)
{
	out_len = RSA_size(_pri_key);
	*out = (unsigned char *)malloc(out_len);

	if (NULL == *out)
	{
		printf("prikey_encrypt:malloc error!\n");
		return -1;
	}

	memset((void *)*out, 0, out_len);
	//printf("prikey_encrypt:Begin RSA_private_encrypt ...\n");

	int ret = RSA_private_encrypt(in_len, in, *out, _pri_key, RSA_PKCS1_PADDING);
	//RSA_public_decrypt(flen, encData, decData, r,  RSA_NO_PADDING);

	return ret;
}

// 公钥解密函数，返回解密后的数据长度
int rsa_op::pubkey_decrypt(const unsigned char *in, int in_len,
	unsigned char **out, int &out_len)
{
	out_len = RSA_size(_pub_key);
	*out = (unsigned char *)malloc(out_len);

	if (NULL == *out)
	{
		printf("pubkey_decrypt:malloc error!\n");
		return -1;
	}

	memset((void *)*out, 0, out_len);
	//printf("pubkey_decrypt:Begin RSA_public_decrypt ...\n");

	int ret = RSA_public_decrypt(in_len, in, *out, _pub_key, RSA_PKCS1_PADDING);

	return ret;
}

// 公钥加密函数
int rsa_op::pubkey_encrypt(const unsigned char *in, int in_len,
	unsigned char **out, int &out_len)
{
	out_len = RSA_size(_pub_key);
	*out = (unsigned char *)malloc(out_len);

	if (NULL == *out)
	{
		printf("pubkey_encrypt:malloc error!\n");
		return -1;
	}

	memset((void *)*out, 0, out_len);
	//printf("pubkey_encrypt:Begin RSA_public_encrypt ...\n");

	int ret = RSA_public_encrypt(in_len, in, *out, _pub_key, RSA_PKCS1_PADDING/*RSA_NO_PADDING*/);

	return ret;
}

// 私钥解密函数，返回解密后的长度
int rsa_op::prikey_decrypt(const unsigned char *in, int in_len,
	unsigned char **out, int &out_len)
{
	out_len = RSA_size(_pri_key);
	*out = (unsigned char *)malloc(out_len);

	if (NULL == *out)
	{
		printf("prikey_decrypt:malloc error!\n");
		return -1;
	}

	memset((void *)*out, 0, out_len);
	//printf("prikey_decrypt:Begin RSA_private_decrypt ...\n");

	int ret = RSA_private_decrypt(in_len, in, *out, _pri_key, RSA_PKCS1_PADDING);

	return ret;
}

// 分段处理
int rsa_op::en_decrypt_template(const unsigned char *in, int in_len,
	unsigned char **out, int &out_len, FUNC_TYPE funcType)
{
	int iRet = -1;
	out_len = 0;
	int padd = (in_len % m_optList[funcType].part_len != 0);
	int s_size = (in_len / m_optList[funcType].part_len + padd) * 128 + 1;
	* out = (unsigned char *)malloc(s_size);

	int t_len = in_len;
	while (t_len)
	{
		int len = t_len >= m_optList[funcType].part_len ? m_optList[funcType].part_len : t_len;
		int outLen = 0;
		unsigned char *part_out = NULL;

		iRet = (this->*m_optList[funcType].p_func)(in + (in_len - t_len), len, &part_out, outLen);
		if (iRet == -1) break;

		memcpy(*out + out_len, part_out, iRet);
		out_len += iRet;

		t_len -= len;
	}

	(*out)[out_len + 1] = '\0';
	if (iRet == -1)
	{
		// 解密失败，清除数据
		*out = NULL;
		return -1;
	}

	return out_len;
}

int rsa_op::close_key()
{
	if (_pub_key != NULL)
	{
		RSA_free(_pub_key);
		_pub_key = NULL;
	}

	if (_pri_key != NULL)
	{
		RSA_free(_pri_key);
		_pri_key = NULL;
	}

	return 0;
}
