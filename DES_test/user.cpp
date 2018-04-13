#include<iostream>
#include<string>
#include"DES.h"

using namespace std;
int main() {
	DES C;
	string s = "computer";
	string k = "01234567";
	C.get_s(s);
	C.get_key(k);

	C.show_encryp();  //加密，生成密文并写入a.txt
	C.show_decrypt(); //读取a.txt中的密文，解密，生成明文并写入b.txt

	return 0;
}