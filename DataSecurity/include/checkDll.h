#pragma once

#ifdef __cplusplus
#define EXPORT_INTEFACE extern "C" __declspec(dllexport)
#else
#define EXPORT_INTEFACE __declspec(dllexport)
#endif

// 获取字符串crc32值
EXPORT_INTEFACE unsigned int GetStringCrc32(const char *buff, int len);

// 获取文件crc32值
EXPORT_INTEFACE unsigned int GetFileCrc32(const char *szCheckFile);

// 获取字符串MD5数字签名
EXPORT_INTEFACE void GetStringMd5(unsigned char* input, unsigned int inputLen, unsigned char** digest);

// 获取文件MD5数字签名
EXPORT_INTEFACE void GetFileMd5(const char* szCheckFile, unsigned char **digest);

// 获取字符串SHA1值
EXPORT_INTEFACE void GetStringSHA1(unsigned char* input, unsigned int inputLen, unsigned char** pSHA);

// 获取文件SHA1值
EXPORT_INTEFACE void GetFileSHA1(const char* szCheckFile, unsigned char **pSHA);

