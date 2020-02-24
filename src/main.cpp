#include <iostream>
#include "blowfish.h"
#include "xor.h"

using namespace std;

int main(int argc, const char * argv[])
{
    XOR x;
    string key = "1234r32lmweflkmewfflowkem";
    string text = "The length of a C string is determined by the terminating null-character: A C string is as long as the number of characters between the beginning of the string and the terminating null character (without including the terminating null character itself).";
    unsigned char blowfish_key[key.length()];
    unsigned char blowfish_text[text.length()];
    std::copy( key.begin(), key.end(), blowfish_key );
    std::copy( text.begin(), text.end(), blowfish_text );
    string encrypted = x.encryptOrDectypt(text,key);
    cout << "Encrypted XOR:" << encrypted << "\n";
    string decrypted = x.encryptOrDectypt(encrypted,key);
    cout << "Decrypted XOR:" << decrypted << "\n";
    Blowfish blowfish;
    blowfish.SetKey(blowfish_key, sizeof(key));
    blowfish.Encrypt(blowfish_text, blowfish_text, sizeof(blowfish_text));
    cout << "       ";
    cout << "Encrypted Blowfish:" << blowfish_text << "\n";
    blowfish.Decrypt(blowfish_text, blowfish_text, sizeof(blowfish_text));
    cout << "Decrypted Blowfish:" << blowfish_text << "\n";
    return 0;
}
