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

	C.show_encryp();  //���ܣ��������Ĳ�д��a.txt
	C.show_decrypt(); //��ȡa.txt�е����ģ����ܣ��������Ĳ�д��b.txt

	return 0;
}