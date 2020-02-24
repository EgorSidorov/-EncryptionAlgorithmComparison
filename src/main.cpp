#include <iostream>
#include <fstream>
#include <streambuf>
#include "blowfish.h"
#include "xor.h"

using namespace std;

void getFromFiles(std::string& text, std::string& key){
    ifstream testText("text.txt");
    ifstream keyText("key.txt");
    string _key((std::istreambuf_iterator<char>(keyText)),
            std::istreambuf_iterator<char>());
    string _text((std::istreambuf_iterator<char>(testText)),
            std::istreambuf_iterator<char>());
    key = _key;
    text = _text;
}

void XORTest(std::string& text, std::string& key){
    XOR x;
    string encrypted = x.encryptOrDectypt(text,key);
    cout << "Encrypted XOR:" << encrypted << "\n";
    string decrypted = x.encryptOrDectypt(encrypted,key);
    cout << "Decrypted XOR:" << decrypted << "\n";
}

void BlowfishTest(std::string& text, std::string& key){
    unsigned char blowfish_key[key.length()];
    unsigned char blowfish_text[text.length()];
    std::copy( key.begin(), key.end(), blowfish_key );
    std::copy( text.begin(), text.end(), blowfish_text );
    Blowfish blowfish;
    blowfish.SetKey(blowfish_key, sizeof(key));
    blowfish.Encrypt(blowfish_text, blowfish_text, sizeof(blowfish_text));
    cout << "       ";
    cout << "Encrypted Blowfish:" << blowfish_text << "\n";
    blowfish.Decrypt(blowfish_text, blowfish_text, sizeof(blowfish_text));
    cout << "Decrypted Blowfish:" << blowfish_text << "\n";
}

int main(int argc, const char * argv[])
{
    std::string key,text;
    getFromFiles(text,key);
    XORTest(text,key);
    BlowfishTest(text,key);
    return 0;
}
