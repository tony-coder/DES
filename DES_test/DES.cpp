#include "DES.h"
#include<bitset>

using namespace std;

DES::DES()
{
}


DES::~DES()
{
}

bitset<32> DES::F(bitset<32> R, bitset<48> k) {
	//E盒扩展
	bitset<48> expandR;  
	for (int i = 0; i < 48; i++)
		expandR[47 - i] = R[32 - E[i]];  //expandR[i] = R[E[i] - 1];
	//异或
	expandR = expandR ^ k;
	//S盒代替
	bitset<32> output;
	int x = 0;
	for (int i = 0; i < 48; i = i + 6)
	{
		int row = expandR[i] * 2 + expandR[i + 5];
		int col = expandR[i + 1] * 8 + expandR[i + 2] * 4 + expandR[i + 3] * 2 + expandR[i + 4];
		int num = S_BOX[i / 6][row][col];
		bitset<4> temp(num);
		output[x + 3] = temp[0];
		output[x + 2] = temp[1];
		output[x + 1] = temp[2];
		output[x] = temp[3];
		x += 4;
	}
	//P盒置换
	bitset<32> tmp = output;
	for (int i = 0; i < 32; i++)
		output[i] = tmp[P[i] - 1];

	return output;
}
//左移函数
bitset<28> DES::leftshift(bitset<28> k, int shift) {
	bitset<28> temp = k;
	if (shift == 1)
	{
		for (int i = 0; i < 27; i++)
		{
			if (i - shift < 0)
				k[i - shift + 28] = temp[i];
			else
				k[i] = temp[i + shift];
		}
	}
	if (shift == 2)
	{
		for (int i = 0; i < 26; i++)
		{
			if (i - shift < 0)
				k[i - shift + 28] = temp[i];
			else
				k[i] = temp[i + shift];
		}
	}
	return k;
}

void DES::generateKeys() {
	bitset<56> real_key;
	bitset<28> left;
	bitset<28> right;
	bitset<48> compressKey;

	//首先经过选择置换PC-1，将初始密钥的8bit奇偶校验位去掉
	//并重新编排
	for (int i = 0; i < 56; i++)
		real_key[i] = key[PC_1[i] - 1];

	for (int round = 0; round < 16; round++)
	{
		for (int i = 0; i < 28; i++)
			left[i] = real_key[i];
		for (int i = 28; i < 56; i++)
			right[i - 28] = real_key[i];
		//左移
		left = leftshift(left, shiftBits[round]);
		right = leftshift(right, shiftBits[round]);
		//连接，置换选择PC-2做重排，进行压缩
		for (int i=0; i < 28; i++)
			real_key[i] = left[i];
		for (int i = 28; i < 56; i++)
			real_key[i] = right[i - 28];
		for (int i = 0; i < 48; i++)
		{
			int m = PC_2[i];
			compressKey[i] = real_key[m - 1];//i=39 时就报错。。。。。
		}                                    //。。。数组越界，应-1.。。
		/*compressKey[i] = real_key[PC_2[i]];*/ 
		//wrong!!!

		subkey[round] = compressKey;
	}

}


// 工具函数：将char字符数组转为二进制
bitset<64> DES::char_to_bit(const char s[8]) {
	bitset<64> bits;
	int x = 0;
	for (int i = 0; i < 8; i++)
	{
		int num = int(s[i]);
		bitset<8> temp(num);
		for (int j = 7; j >= 0; j--)
		{
			bits[x + j] = temp[7 - j];
		}
		x += 8;
	}
	/*for (int i = 0; i<8; ++i)
		for (int j = 0; j<8; ++j)
			bits[i * 8 + j] = ((s[i] >> j) & 1);
			*/
	return bits;
}
//工具函数：进行二进制逆向转换
bitset<64> DES::change(bitset<64> temp) {
	bitset<64> bits;
	bitset<8> n;
	int x;
	for (int i = 0; i < 64; i = i + 8)
	{
		for (int j = 0; j < 8; j++)
		{
			bits[i + j] = temp[i + 7 - j];
		}
	}
	return bits;
}
/*char * DES::bit_to_char(const bitset<64> test) {
	int count = 0;
	int temp;
	char now[8];
	for (int i = 0; i < 64; i = i + 8)
	{
		temp = 0;
		for (int j = 0; j < 8; j++)
		{
			if (test[i + j] == 0)
				continue;
			else
				temp += int(pow(2, 7 - j));
		}
		now[count] = char(temp);
		count++;
	}
	return now;
}
*/

bitset<64> DES::DES_encryp(bitset<64> &plain) {
	bitset<64> cipher;
	bitset<64> currentBits;
	bitset<32> left;
	bitset<32> right;
	bitset<32> newLeft;
	//初始置换IP
	for (int i = 0; i < 64; i++)
		currentBits[i] = plain[IP[i] - 1];//

	for (int i = 0; i < 32; i++)
		left[i] = currentBits[i];
	for (int i = 32; i < 64; i++)
		right[i - 32] = currentBits[i];
	//进入16轮轮变换
	for (int round = 0; round < 16; round++)
	{
		newLeft = right;
		right = left ^ F(right, subkey[round]);
		left = newLeft;
	}
	//合并
	for (int i = 0; i < 32; i++)
		cipher[i] = right[i];
	for (int i = 32; i < 64; i++)
		cipher[i] = left[i - 32];
	//逆初始化置换
	currentBits = cipher;
	for (int i = 0; i < 64; i++)
		cipher[i] = currentBits[IP_1[i] - 1];

	return cipher;
}

bitset<64> DES::DES_decrypt(bitset<64> & cipher) {
	bitset<64> plain;
	bitset<64> currentBits;
	bitset<32> left;
	bitset<32> right;
	bitset<32> newLeft;
	//置换IP
	for (int i = 0; i < 64; i++)
		currentBits[i] = cipher[IP[i] - 1];

	for (int i = 0; i < 32; i++)
		left[i] = currentBits[i];
	for (int i = 32; i < 64; i++)
		right[i - 32] = currentBits[i];
	//进入16轮迭代（子密钥逆序应用）
	for (int round = 0; round < 16; round++)
	{
		newLeft = right;
		right = left ^ F(right, subkey[15 - round]);
		left = newLeft;
	}
	//合并
	for (int i = 0; i < 32; i++)
		plain[i] = right[i];
	for (int i = 32; i < 64; i++)
		plain[i] = left[i - 32];
	//逆初始化置换
	currentBits = plain;
	for (int i = 0; i < 64; i++)
		plain[i] = currentBits[IP_1[i] - 1];

	return plain;
}

void DES::get_key(bitset<64> k) {
	key = k;
}