/*
MIT License

Simple License Manager
Copyright (c) 2024 Sukesh Ashok Kumar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#include <iostream>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <cstring>

class LicenseManager {
public:
    LicenseManager(const std::string& secretKey) : secretKey_(secretKey) {
        // Use a zero-initialized IV for simplicity
        memset(iv_, 0, AES_BLOCK_SIZE);
    }

    std::string generateActivationCode(const std::string& customerName, const std::string& expirationDate) {
        std::string dataToEncrypt = customerName + expirationDate;
        std::string encryptedData = encryptData(dataToEncrypt);

        // Encode the encrypted data using Base64 for readability
        return base64Encode(encryptedData);
    }

    bool validateActivationCode(const std::string& activationCode, const std::string& customerName, const std::string& expirationDate) {
        // Decode the Base64-encoded activation code
        std::string decodedActivationCode = base64Decode(activationCode);

        std::string decryptedData = decryptData(decodedActivationCode);

        // Extract customer name and expiration date from decrypted data
        std::string decryptedCustomerName = decryptedData.substr(0, customerName.length());
        std::string decryptedExpirationDate = decryptedData.substr(customerName.length());

        return (decryptedCustomerName == customerName) && (decryptedExpirationDate == expirationDate);
    }

private:
    std::string encryptData(const std::string& data) {
        EVP_CIPHER_CTX* ctx;
        int len;  // Change from size_t to int
        int ciphertextLen;
        unsigned char* ciphertext;

        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(secretKey_.c_str()), iv_);

        ciphertext = static_cast<unsigned char*>(OPENSSL_malloc(data.length() + AES_BLOCK_SIZE));

        // Change the type of len from size_t to int
        EVP_EncryptUpdate(ctx, ciphertext, &len, reinterpret_cast<const unsigned char*>(data.c_str()), static_cast<int>(data.length()));
        ciphertextLen = len;

        // Change the type of len from size_t to int
        EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
        ciphertextLen += len;

        EVP_CIPHER_CTX_free(ctx);

        std::string encryptedData(reinterpret_cast<char*>(ciphertext), ciphertextLen);
        OPENSSL_free(ciphertext);

        return encryptedData;
    }

    std::string decryptData(const std::string& data) {
        EVP_CIPHER_CTX* ctx;
        int len;  // Change from size_t to int
        int plaintextLen;
        unsigned char* plaintext;

        ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(secretKey_.c_str()), iv_);

        plaintext = static_cast<unsigned char*>(OPENSSL_malloc(data.length()));

        // Change the type of len from size_t to int
        EVP_DecryptUpdate(ctx, plaintext, &len, reinterpret_cast<const unsigned char*>(data.c_str()), static_cast<int>(data.length()));
        plaintextLen = len;

        // Change the type of len from size_t to int
        EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
        plaintextLen += len;

        EVP_CIPHER_CTX_free(ctx);

        std::string decryptedData(reinterpret_cast<char*>(plaintext), plaintextLen);
        OPENSSL_free(plaintext);

        return decryptedData;
    }

    std::string base64Encode(const std::string& input) {
        BIO* bio, * b64;
        BUF_MEM* bufferPtr;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);

        BIO_write(bio, input.c_str(), static_cast<int>(input.length()));
        BIO_flush(bio);

        BIO_get_mem_ptr(bio, &bufferPtr);

        std::string result(bufferPtr->data, bufferPtr->length);

        BIO_free_all(bio);

        return result;
    }

    std::string base64Decode(const std::string& input) {
        BIO* bio, * b64;
        char buffer[4096];
        size_t length;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new_mem_buf(input.c_str(), static_cast<int>(input.length()));
        bio = BIO_push(b64, bio);

        length = BIO_read(bio, buffer, sizeof(buffer));

        BIO_free_all(bio);

        return std::string(buffer, length);
    }

private:
    std::string secretKey_;
    unsigned char iv_[AES_BLOCK_SIZE];
};

