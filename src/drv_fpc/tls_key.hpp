#ifndef FPC_TLS_KEY_HPP
#define FPC_TLS_KEY_HPP
#include "crypto.hpp"
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>
#include <openssl/crypto.h>
namespace fpc {
// Windows 18001c430: authenticate the declared plaintext-length prefix,
// decrypt the padded block length, and return exactly the declared key size.
inline bool unwrap_tls_key(const unsigned char* packet, size_t size,
                           std::vector<unsigned char>& output) {
    if (!packet || size < 28) return false;
    auto word=[&](size_t i){const auto* p=packet+4*i;return uint32_t(p[0])|uint32_t(p[1])<<8|uint32_t(p[2])<<16|uint32_t(p[3])<<24;};
    const uint32_t key_offset=word(1),key_length=word(2),aad_offset=word(3),aad_length=word(4),sig_offset=word(5),sig_length=word(6);
    auto valid=[&](uint32_t offset,size_t length){return offset>=28 && offset<=size && length<=size-offset;};
    if(word(0)!=0x0dec0ded || key_length!=32 || aad_length!=13 || sig_length!=32 ||
       !valid(key_offset,48) || !valid(aad_offset,aad_length) || !valid(sig_offset,sig_length) ||
       memcmp(packet+aad_offset,"FPC TLS Keys",13) ||
       !crypto::verify_tls_key(packet+aad_offset,aad_length,const_cast<unsigned char*>(packet+key_offset),key_length,const_cast<unsigned char*>(packet+sig_offset),sig_length)) return false;
    std::array<unsigned char,32> sealing_key{};
    crypto::sha256("FPC_SEALING_KEY",16,sealing_key.data());
    std::array<unsigned char,64> plain{};
    EVP_CIPHER_CTX* context=EVP_CIPHER_CTX_new();
    int updated=0,finished=0;
    bool ok=context && EVP_DecryptInit_ex(context,EVP_aes_256_cbc(),nullptr,sealing_key.data(),nullptr)==1 &&
        EVP_DecryptUpdate(context,plain.data(),&updated,packet+key_offset,48)==1 &&
        EVP_DecryptFinal_ex(context,plain.data()+updated,&finished)==1 && updated+finished==32;
    EVP_CIPHER_CTX_free(context);
    OPENSSL_cleanse(sealing_key.data(),sealing_key.size());
    if(ok)output.assign(plain.begin(),plain.begin()+32);
    OPENSSL_cleanse(plain.data(),plain.size());
    return ok;
}
}
#endif
