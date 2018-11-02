#pragma once

#ifdef __cplusplus
#define EXPORT_INTEFACE_API extern "C" __declspec(dllexport)
#else
#define EXPORT_INTEFACE_API __declspec(dllexport)
#endif

// 生成公、私钥文件
EXPORT_INTEFACE_API int RSAGenerateKeyFiles(const char *pub_keyfile, const char *pri_keyfile,
	const unsigned char *passwd, int passwd_len);

// 私钥加密，公钥解密（文件）
EXPORT_INTEFACE_API int RSAPrivateEncryptFile(const char* encrypt_path, const char* pri_key_path, const unsigned char* passwd);
EXPORT_INTEFACE_API int RSAPublicDecryptFile(const char* decrypt_path, const char* pub_key_path);

// 公钥加密，私钥解密（文件）
EXPORT_INTEFACE_API int RSAPublicEncryptFile(const char* encrypt_path, const char* pub_key_path);
EXPORT_INTEFACE_API int RSAPrivateDecryptFile(const char* decrypt_path, const char* pri_key_path, const unsigned char* passwd);

// 私钥加密，公钥解密（字符串）
EXPORT_INTEFACE_API int RSAPrivateEncryptString(const unsigned char *in, int in_len,
			unsigned char **out,int &out_len, const char* pri_key_path, const unsigned char* passwd);
EXPORT_INTEFACE_API int RSAPublicDecryptString(const unsigned char *in, int in_len,
	unsigned char **out, int &out_len, const char* pub_key_path);

// 公钥加密，私钥解密（字符串）
EXPORT_INTEFACE_API int RSAPublicEncryptString(const unsigned char *in, int in_len,
	unsigned char **out, int &out_len, const char* pri_key_path);
EXPORT_INTEFACE_API int RSAPrivateDecryptString(const unsigned char *in, int in_len,
	unsigned char **out, int &out_len, const char* pub_key_path, const unsigned char* passwd);

