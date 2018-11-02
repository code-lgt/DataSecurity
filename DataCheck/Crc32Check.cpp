#include "Crc32Check.h"

#include <fstream>
using namespace std;

UINT32 POLYNOMIAL = 0xEDB88320;
int have_table = 0;
UINT32 table[256];

void make_table()
{
	int i, j, crc;
	have_table = 1;
	for (i = 0; i < 256; i++)
		for (j = 0, table[i] = i; j < 8; j++)
			table[i] = (table[i] >> 1) ^ ((table[i] & 1) ? POLYNOMIAL : 0);
}

UINT32 getCRC(const char *buff, int len)
{
	if (!have_table) make_table();
	UINT32 crc = 0;
	crc = ~crc;
	for (int i = 0; i < len; i++)
		crc = (crc >> 8) ^ table[(crc ^ buff[i]) & 0xff];
	return ~crc;
}

// 获取文件crc32
UINT32 getCRC(const char *szCheckFile)
{
	ifstream t(szCheckFile, ios::binary);
	string buffer((istreambuf_iterator<char>(t)),
		istreambuf_iterator<char>());
	t.close();

	UINT32 crcVal = getCRC(buffer.c_str(), buffer.length());

	return crcVal;
}