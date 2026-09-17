/*
Copyright (C) 2022  pom@vro.life

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#include <cassert>
#include <cstring>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

#include "crypto.hpp"

using namespace jinx;

namespace crypto {

void sha256(const void* data, size_t size, unsigned char* output)
{
    SHA256_CTX sha256;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, size);
    unsigned int osz = 0;
    EVP_DigestFinal(ctx, output, &osz);
    assert(osz == SHA256_DIGEST_LENGTH);
}

bool verify_tls_key(const void* aad, size_t aad_len, void* key, size_t key_len, void* output, size_t md_len)
{
    unsigned char hmac_key[SHA256_DIGEST_LENGTH];
    unsigned char sig[SHA256_DIGEST_LENGTH];
    size_t sig_len = 0;

    sha256("FPC_HMAC_KEY", 13, hmac_key);

    EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX* hmac = EVP_MAC_CTX_new(mac);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_MAC_PARAM_DIGEST, const_cast<char*>("SHA256"), 0),
        OSSL_PARAM_construct_end()
    };
    EVP_MAC_init(hmac, hmac_key, sizeof(hmac_key), params);
    EVP_MAC_update(hmac, reinterpret_cast<const unsigned char*>(aad), aad_len);
    EVP_MAC_update(hmac, reinterpret_cast<const unsigned char*>(key), key_len);
    EVP_MAC_final(hmac, sig, &sig_len, sizeof(sig));
    EVP_MAC_CTX_free(hmac);
    EVP_MAC_free(mac);
    return md_len == SHA256_DIGEST_LENGTH and CRYPTO_memcmp(sig, output, SHA256_DIGEST_LENGTH) == 0;
}

bool encrypt(
    const EVP_CIPHER* cipher,
    SliceConst aad, 
    SliceConst nonce, 
    SliceConst key, 
    SliceConst data, 
    SliceMutable output, 
    SliceMutable tag
)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int res = EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, 1 /* enc */);
    OPENSSL_assert(res != 0);
    res = EVP_CIPHER_CTX_set_key_length(ctx, key._size);
    OPENSSL_assert(res != 0);
    res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce._size, NULL);
    OPENSSL_assert(res != 0);
    res = EVP_CipherInit_ex(ctx, cipher, NULL, 
        reinterpret_cast<const unsigned char*>(key.data()), 
        reinterpret_cast<const unsigned char*>(nonce.data()), 1 /* enc */);
    OPENSSL_assert(res != 0);
    int length = 0;
    res = EVP_CipherUpdate(ctx, NULL, &length, 
        reinterpret_cast<const unsigned char*>(aad.data()), aad._size);
    OPENSSL_assert(res != 0);
    int stream_len = 0;
    res = EVP_CipherUpdate(ctx, 
        reinterpret_cast<unsigned char*>(output.data()), &length, 
        reinterpret_cast<const unsigned char*>(data.data()), data._size);
    OPENSSL_assert(res != 0);
    stream_len += length;
    res = EVP_CipherFinal(ctx, 
        reinterpret_cast<unsigned char*>(output.data()) + stream_len, &length);
    OPENSSL_assert(res != 0);
    stream_len += length;
    OPENSSL_assert(stream_len <= output._size);
    res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag._size, tag.data());
    OPENSSL_assert(res != 0);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}
bool decrypt(
    const EVP_CIPHER* cipher, 
    SliceConst aad, 
    SliceConst nonce, 
    SliceConst key, 
    SliceConst data, 
    SliceMutable output, 
    SliceMutable tag
)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int res = EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, 0 /* dec */);
    OPENSSL_assert(res != 0);
    res = EVP_CIPHER_CTX_set_key_length(ctx, key._size);
    OPENSSL_assert(res != 0);
    res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce._size, NULL);
    OPENSSL_assert(res != 0);
    res = EVP_CipherInit_ex(ctx, cipher, NULL,
        reinterpret_cast<const unsigned char*>(key.data()), 
        reinterpret_cast<const unsigned char*>(nonce.data()), 0 /* dec */);
    OPENSSL_assert(res != 0);
    res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 
        static_cast<int>(tag._size), tag.data());
    OPENSSL_assert(res != 0);
    int length = 0;
    res = EVP_CipherUpdate(ctx, NULL, &length, 
        reinterpret_cast<const unsigned char*>(aad.data()), aad._size);
    OPENSSL_assert(res != 0);
    int stream_len = 0;
    res = EVP_CipherUpdate(ctx, 
        reinterpret_cast<unsigned char*>(output.data()), &length, 
        reinterpret_cast<const unsigned char*>(data.data()), data._size);
    OPENSSL_assert(res != 0);
    stream_len += length;
    res = EVP_CipherFinal(ctx, 
        reinterpret_cast<unsigned char*>(output.data()) + stream_len, &length);
    stream_len += length;
    OPENSSL_assert(stream_len <= output._size);
    EVP_CIPHER_CTX_free(ctx);
    return res != 0;
}

}
