#include<iostream>
#include<string>
#include<fstream>
#include"DES.h"

using namespace std;
int main() {
	DES C;
	string s = "computer";
	string k = "01234567";
	bitset<64> plain = C.char_to_bit(s.c_str());
	C.get_key(C.char_to_bit(k.c_str()));
	// 生成16个子密钥
	C.generateKeys();
	// 密文写入 c.txt
	bitset<64> cipher = C.DES_encryp(plain);
	fstream file1;
	file1.open("D://c.txt", ios::binary | ios::out);
	file1.write((char*)&cipher, sizeof(cipher));
	file1.close();

	// 读文件 c.txt
	bitset<64> temp;
	file1.open("D://c.txt", ios::binary | ios::in);
	file1.read((char*)&temp, sizeof(temp));
	file1.close();

	// 解密，并写入文件 d.txt
	bitset<64> temp_plain = C.DES_decrypt(temp);
	bitset<64> temp_1 = C.change(temp_plain);
	
	file1.open("D://d.txt", ios::binary | ios::out);
	file1.write((char*)&temp_1, sizeof(temp_1));
	file1.close();
	

	return 0;
}