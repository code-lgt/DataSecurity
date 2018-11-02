#pragma once

#ifdef __cplusplus
#define EXPORT_INTEFACE extern "C" __declspec(dllexport)
#else
#define EXPORT_INTEFACE __declspec(dllexport)
#endif

// ��ȡ�ַ���crc32ֵ
EXPORT_INTEFACE unsigned int GetStringCrc32(const char *buff, int len);

// ��ȡ�ļ�crc32ֵ
EXPORT_INTEFACE unsigned int GetFileCrc32(const char *szCheckFile);

// ��ȡ�ַ���MD5����ǩ��
EXPORT_INTEFACE void GetStringMd5(unsigned char* input, unsigned int inputLen, unsigned char** digest);

// ��ȡ�ļ�MD5����ǩ��
EXPORT_INTEFACE void GetFileMd5(const char* szCheckFile, unsigned char **digest);

// ��ȡ�ַ���SHA1ֵ
EXPORT_INTEFACE void GetStringSHA1(unsigned char* input, unsigned int inputLen, unsigned char** pSHA);

// ��ȡ�ļ�SHA1ֵ
EXPORT_INTEFACE void GetFileSHA1(const char* szCheckFile, unsigned char **pSHA);

