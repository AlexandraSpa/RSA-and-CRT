#include <iostream>
#include <NTL/ZZ.h>

using namespace std;
NTL::ZZ p, q, n, e, d;
NTL::ZZ gcd(NTL::ZZ a, NTL::ZZ b) {
	if (b==0){
		return a;
		}
	NTL::ZZ R;
	R = a% b;
	while (R > 0) {
		a = b;
		b = R;
		R = a % b;
	}
	return b;
}
void generateKey() {
	
	NTL::ZZ phi;

	NTL::GenPrime(p, 512);
	NTL::GenPrime(q, 512); //distinct prime
	n = p * q;
	phi = (p - 1)*(q - 1);

	NTL::GenPrime(e, 32); // 1< e< phi && gcd(e, phi)=1
	//Use the extended Euclidean algorithm to compute the unique integer d, 1 <d< phi
	//d is the modular multiplicative inverse of e modulo phi(n).
	d = NTL::InvMod(e, phi); //private key of A
}
NTL::ZZ RSAencrypt(NTL::ZZ message) {
	generateKey();
	NTL::ZZ ciphertext;
	ciphertext = NTL::PowerMod(message, e, n); //message^e mod n
	return ciphertext;
}
NTL::ZZ RSAdecrypt(NTL::ZZ ciphertext) {
	NTL::ZZ message;
	message = NTL::PowerMod(ciphertext, d, n); //cipehrtext^d mod n
	return message;
}
NTL::ZZ CRTdecrypt(NTL::ZZ ciphertext) {
	NTL::ZZ m1, m2, message, d1, d2, Inv;
	d1 = d % (p - 1);
	d2 = d % (q - 1);
	if (p > q) {
		swap(p, q);
		swap(d1, d2);
	}
	Inv = NTL::InvMod(p, q);
	m1 = NTL::PowerMod(ciphertext% p, d1, p);
	m2 = NTL::PowerMod(ciphertext% q, d2, q);
	message = m1+ p * ( ( (m2 - m1) * Inv) % q);

	return message;
}
int length(int a) {
	int l=0;
	while (a) {
		l++;
		a /= 10;
	}
	return l;
}
int power(int a, int b) {
	int result=1;
	while (b) {
		result *= a;
		b--;
	}
	return result;
}
NTL::ZZ convertMesstoNo(string message) {
	NTL::ZZ number;
	number = 0;
	for (auto& c : message) {
		number = number * power(10, length((int)c)) + (int)c;
	}
	return number;

}


int main() {
	string message = "acesta este un mesaj";
	cout << "Converted message: " << convertMesstoNo(message)<< endl;
	NTL::ZZ ciphertext= RSAencrypt(convertMesstoNo(message));
	cout << "Encrypted message: " << ciphertext << endl;
		
	cout << "Decrypted message: " << RSAdecrypt(ciphertext)<< endl;
	cout << "Decrypted message using CRT: " << CRTdecrypt(ciphertext)<< endl;

}