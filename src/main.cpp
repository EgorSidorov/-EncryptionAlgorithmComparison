#include <iostream>
#include <fstream>
#include <streambuf>
#include "des.h"
#include "des3.h"
#include "aes.h"
#include <vector>
#include <string.h>
#include <chrono>
#include "twofish/common/includes.h"
#include "Twofish.h"
#include <cassert>

using namespace std;
using namespace std::chrono;

bool debug = false;

enum class FILESIZE {
    gigant,
    medium,
    big
};

void getFromFiles(FILESIZE fileSize, std::string& text, std::string& key, uint64_t& keyDes,uint64_t& key2Des,uint64_t& key3Des){
    ifstream testText;
    if(fileSize == FILESIZE::gigant){
        testText.open("text100000.txt");
    }
    else if(fileSize == FILESIZE::medium){
        testText.open("text1000.txt");
    }
    else if(fileSize == FILESIZE::big){
        testText.open("text10000.txt");
    } else return;
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
    testText.close();
    keyText.close();
    keyDesText.close();
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

void checkTime(){

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

auto twofishTest(std::string& text){
    std::string key = unhexlify("9F589F5CF6122C32B6BFEC2F2AE8C35A");
    auto twofish = Twofish(key);
        for(int i = 0; i < text.length(); i=i+16){
            std::string data = text.substr(i,16);
            while(data.length() != 16)
                data += " ";
            auto cipher = twofish.encrypt(data);
            if(debug){
                std::cout<<"Encrypted Twofish path:"<<data.c_str()<<endl;
            }
            if(debug){
                std::cout<<"Decrypted Twofish path:"<<cipher.c_str()<<endl;
            }
        }
}

void desTest(std::string& text, uint64_t& keyDes){
    if(debug){
        std::cout << keyDes<<endl;
    }
    DES d(keyDes);
    std::vector<uint64_t> text_int64(text.length()/8+(text.length()%8 == 0 ? 0 : 1));
    std::string copy_text = text;
    convertToVectorInt(text, text_int64);
    text.clear();
    for(int i = 0; i < text_int64.size(); i++){
        text_int64.at(i) = d.encrypt(text_int64.at(i));
    }
    convertFromVectorInt(text, text_int64);
    if(debug){
        std::cout<<"Encrypted Des:"<<text.c_str()<<endl;
    }
    text.clear();
    for(int i = 0; i < text_int64.size(); i++){
        text_int64.at(i) = d.decrypt(text_int64.at(i));
    }
    convertFromVectorInt(text, text_int64);
    if(debug){
        std::cout<<"Decrypted Des:"<<text.c_str()<<endl;
    }
}

void des3Test(std::string& text, uint64_t& keyDes, uint64_t& key2Des,uint64_t& key3Des){
    if(debug){
        std::cout << keyDes<<endl;
        std::cout << key2Des<<endl;
        std::cout << key3Des<<endl;
    }
    DES3 d3(keyDes,key2Des,key3Des);
    std::vector<uint64_t> text_int64(text.length()/8+(text.length()%8 == 0 ? 0 : 1));
    std::string copy_text = text;
    convertToVectorInt(text, text_int64);
    text.clear();
    for(int i = 0; i < text_int64.size(); i++){
        text_int64.at(i) = d3.encrypt(text_int64.at(i));
    }
    convertFromVectorInt(text, text_int64);
    if(debug){
        std::cout<<"Encrypted 3Des:"<<text.c_str()<<endl;
    }
    text.clear();
    for(int i = 0; i < text_int64.size(); i++){
        text_int64.at(i) = d3.decrypt(text_int64.at(i));
    }
    convertFromVectorInt(text, text_int64);
    if(debug){
        std::cout<<"Decrypted 3Des:"<<text.c_str()<<endl;
    }
}

void aesTest128(std::string& text){
    AES a(128);
    unsigned char iv[16];
    unsigned int textLenght = text.length() * sizeof(unsigned char);
    textLenght += (textLenght%16);
    for(int i = 0; i < 16; i++)
        iv[i] = 0xFF;
    unsigned char* textChars = new unsigned char[text.length() + textLenght%16];
    std::copy( text.begin(), text.end(), textChars );
    unsigned char* decrypted = a.DecryptECB(textChars,textLenght,iv);
    if(debug){
        std::cout<<"Decrypted aes:"<<decrypted<<endl;
    }
    unsigned char* encrypted = a.EncryptECB(decrypted, textLenght, iv, textLenght);
    if(debug){
        std::cout<<"Encrypted aes:"<<encrypted<<endl;
    }
    delete textChars;
}

void aesTest192(std::string& text){
    AES a(192);
    unsigned char iv[24];
    unsigned int textLenght = text.length() * sizeof(unsigned char);
    textLenght += (textLenght%16);
    for(int i = 0; i < 24; i++)
        iv[i] = 0xFF;
    unsigned char* textChars = new unsigned char[text.length() + textLenght%16];
    std::copy( text.begin(), text.end(), textChars );
    unsigned char* decrypted = a.DecryptECB(textChars,textLenght,iv);
    if(debug){
        std::cout<<"Decrypted aes:"<<decrypted<<endl;
    }
    unsigned char* encrypted = a.EncryptECB(decrypted, textLenght, iv, textLenght);
    if(debug){
        std::cout<<"Encrypted aes:"<<encrypted<<endl;
    }
    delete textChars;
}

void aesTest256(std::string& text){
    AES a(256);
    unsigned char iv[32];
    unsigned int textLenght = text.length() * sizeof(unsigned char);
    textLenght += (textLenght%16);
    for(int i = 0; i < 32; i++)
        iv[i] = 0xFF;
    unsigned char* textChars = new unsigned char[text.length() + textLenght%16];
    std::copy( text.begin(), text.end(), textChars );
    unsigned char* decrypted = a.DecryptECB(textChars,textLenght,iv);
    if(debug){
        std::cout<<"Decrypted aes:"<<decrypted<<endl;
    }
    unsigned char* encrypted = a.EncryptECB(decrypted, textLenght, iv, textLenght);
    if(debug){
        std::cout<<"Encrypted aes:"<<encrypted<<endl;
    }
    delete textChars;
}

enum class ALGORITMS{
    TWOFISH,
    DES,
    DES3,
    AES128,
    AES192,
    AES256
};

class DetectTime {
public:
    DetectTime(string key,
               string text,
               uint64_t keyDes,
               uint64_t key2Des,
               uint64_t key3Des){
        this->key = key;
        this->text = text;
        this->keyDes = keyDes;
        this->key2Des = key2Des;
        this->key3Des = key3Des;
    }

    decltype(auto) detect(ALGORITMS algoritm)
    {
        using high_resolution_clock = steady_clock;
        auto start = high_resolution_clock::now();
        if(algoritm == ALGORITMS::TWOFISH){
           twofishTest(text);
        }
        else if(algoritm == ALGORITMS::DES){
            desTest(text,keyDes);
        }
        else if(algoritm == ALGORITMS::DES3){
            des3Test(text,keyDes,key2Des,key3Des);
        }
        else if(algoritm == ALGORITMS::AES128){
            aesTest128(text);
        }
        else if(algoritm == ALGORITMS::AES192){
            aesTest192(text);
        }
        else if(algoritm == ALGORITMS::AES256){
            aesTest256(text);
        }
        auto stop = high_resolution_clock::now();
        return duration_cast<microseconds>(stop - start).count();
    }
private:
    std::string key,text;
    uint64_t keyDes, key2Des, key3Des;
};

void detectForSize(FILESIZE fileSize){
    if(fileSize == FILESIZE::medium){
        cout << "Test for 1000 symbols" << endl;
    }
    if(fileSize == FILESIZE::big){
        cout << "Test for 10000 symbols" << endl;
    }
    if(fileSize == FILESIZE::gigant){
        cout << "Test for 100000 symbols" << endl;
    }
    std::string key,text;
    uint64_t keyDes, key2Des, key3Des;
    getFromFiles(fileSize,text,key,keyDes,key2Des,key3Des);
    DetectTime detector(key,text,keyDes,key2Des,key3Des);
    cout << "Duration in microseconds TwoFish is " << detector.detect(ALGORITMS::TWOFISH) << endl;
    cout << "Duration in microseconds DES is " << detector.detect(ALGORITMS::DES) << endl;
    cout << "Duration in microseconds DES3 is " << detector.detect(ALGORITMS::DES3) << endl;
    cout << "Duration in microseconds AES128 is " << detector.detect(ALGORITMS::AES128) << endl;
    cout << "Duration in microseconds AES192 is " << detector.detect(ALGORITMS::AES192) << endl;
    cout << "Duration in microseconds AES256 is " << detector.detect(ALGORITMS::AES256) << endl;
}

int main(int argc, const char * argv[])
{
    detectForSize(FILESIZE::gigant);
    detectForSize(FILESIZE::medium);
    detectForSize(FILESIZE::big);
    return 0;
}
