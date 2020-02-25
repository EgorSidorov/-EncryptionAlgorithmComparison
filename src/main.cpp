#include <iostream>
#include <fstream>
#include <streambuf>
#include "blowfish.h"
#include "des.h"
#include "des3.h"
#include "xor.h"
#include <vector>

using namespace std;

void getFromFiles(std::string& text, std::string& key, uint64_t& keyDes,uint64_t& key2Des,uint64_t& key3Des){
    ifstream testText("text.txt");
    ifstream keyText("key.txt");
    ifstream keyDesText("des.txt");
    string _key((std::istreambuf_iterator<char>(keyText)),
            std::istreambuf_iterator<char>());
    string _text((std::istreambuf_iterator<char>(testText)),
            std::istreambuf_iterator<char>());
    key = _key;
    text = _text;
    keyDesText >> keyDes;
    keyDesText >> key2Des;
    keyDesText >> key3Des;
}

void convertFromVectorInt(std::string& text, std::vector<uint64_t>& text_int64){
    for(int i = 0; i < text_int64.size(); i++){
        string textFrom = "        ";
        for(int j = 0; j < 8; j++){
            textFrom.at(j) = ((text_int64.at(i) >> ((7-j)*8)) <<56>>56);
        }
        text += textFrom;
    }
}

void convertToVectorInt(std::string& text, std::vector<uint64_t>& text_int64){
    bool needNull = true;
    if(text.length()/8 == text_int64.size())
        needNull =false;
    int textLenght = text.length()-7;
    for(int i = 0; i < textLenght; i=i+8){
        uint64_t number = 0;
        for(int j = 0; j < 8; j++){
            number += ((uint64_t)text.at(i+j) << (56-j*8));
        }
        text_int64.at(i/8) = number;
    }
    if(needNull){
        uint64_t number = 0;
        int count = text.length()%8;
        textLenght = text.length() - count;
        for(int j = 0; j < count; j++){
            number += ((uint64_t)text.at(textLenght+j) << (56-j*8));
        }
        text_int64.at(text.length()/8) = number;
    }

}

void XORTest(std::string& text, std::string& key){
    XOR x;
    string encrypted = x.encryptOrDectypt(text,key);
    cout << "Encrypted XOR:" << encrypted << "\n";
    string decrypted = x.encryptOrDectypt(encrypted,key);
    cout << "Decrypted XOR:" << decrypted << "\n";
}

void blowfishTest(std::string& text, std::string& key){
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

void desTest(std::string& text, uint64_t& keyDes){
    std::cout << keyDes<<endl;
    DES d(keyDes);
    std::vector<uint64_t> text_int64(text.length()/8+(text.length()%8 == 0 ? 0 : 1));
    convertToVectorInt(text, text_int64);
    text.clear();
    for(int i = 0; i < text_int64.size(); i++){
        text_int64.at(i) = d.encrypt(text_int64.at(i));
    }
    convertFromVectorInt(text, text_int64);
    std::cout<<"Encrypted Des:"<<text<<endl;
    text.clear();
    for(int i = 0; i < text_int64.size(); i++){
        text_int64.at(i) = d.decrypt(text_int64.at(i));
    }
    convertFromVectorInt(text, text_int64);
    std::cout<<"Decrypted Des:"<<text<<endl;
}

void des3Test(std::string& text, uint64_t& keyDes, uint64_t& key2Des,uint64_t& key3Des){
    std::cout << keyDes<<endl;
    std::cout << key2Des<<endl;
    std::cout << key3Des<<endl;
    DES3 d3(keyDes,key2Des,key3Des);
    std::vector<uint64_t> text_int64(text.length()/8+(text.length()%8 == 0 ? 0 : 1));
    convertToVectorInt(text, text_int64);
    text.clear();
    for(int i = 0; i < text_int64.size(); i++){
        text_int64.at(i) = d3.encrypt(text_int64.at(i));
    }
    convertFromVectorInt(text, text_int64);
    std::cout<<"Encrypted 3Des:"<<text<<endl;
    text.clear();
    for(int i = 0; i < text_int64.size(); i++){
        text_int64.at(i) = d3.decrypt(text_int64.at(i));
    }
    convertFromVectorInt(text, text_int64);
    std::cout<<"Decrypted 3Des:"<<text<<endl;
}

int main(int argc, const char * argv[])
{
    std::string key,text;
    uint64_t keyDes, key2Des, key3Des;
    getFromFiles(text,key,keyDes,key2Des,key3Des);
    XORTest(text,key);
    blowfishTest(text,key);
    desTest(text,keyDes);
    des3Test(text,keyDes,key2Des,key3Des);
    return 0;
}
