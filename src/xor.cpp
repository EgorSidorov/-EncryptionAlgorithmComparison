#include "xor.h"

std::string XOR::encryptOrDectypt(std::string toEncrypt, std::string key){
    std::string output = toEncrypt;
    for (int i = 0, j = 0; i < toEncrypt.size(); i++, j++){
        if(j == key.length())
            j = 0;
        output[i] = toEncrypt[i] ^ key[j];
    }
    return output;
}
