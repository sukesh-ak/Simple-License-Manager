#include <iostream>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

class LicenseManager {
public:
    LicenseManager(const std::string& secretKey) : secretKey_(secretKey) {}

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
        int len;
        int ciphertextLen;
        unsigned char* ciphertext;

        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, reinterpret_cast<const unsigned char*>(secretKey_.c_str()), nullptr);

        ciphertext = static_cast<unsigned char*>(OPENSSL_malloc(data.length() + AES_BLOCK_SIZE));

        EVP_EncryptUpdate(ctx, ciphertext, &len, reinterpret_cast<const unsigned char*>(data.c_str()), data.length());
        ciphertextLen = len;

        EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
        ciphertextLen += len;

        EVP_CIPHER_CTX_free(ctx);

        std::string encryptedData(reinterpret_cast<char*>(ciphertext), ciphertextLen);
        OPENSSL_free(ciphertext);

        return encryptedData;
    }

    std::string decryptData(const std::string& data) {
        EVP_CIPHER_CTX* ctx;
        int len;
        int plaintextLen;
        unsigned char* plaintext;

        ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, reinterpret_cast<const unsigned char*>(secretKey_.c_str()), nullptr);

        plaintext = static_cast<unsigned char*>(OPENSSL_malloc(data.length()));

        EVP_DecryptUpdate(ctx, plaintext, &len, reinterpret_cast<const unsigned char*>(data.c_str()), data.length());
        plaintextLen = len;

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
        int length;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new_mem_buf(input.c_str(), static_cast<int>(input.length()));
        bio = BIO_push(b64, bio);

        length = BIO_read(bio, buffer, sizeof(buffer));

        BIO_free_all(bio);

        return std::string(buffer, length);
    }

private:
    std::string secretKey_;
};

int main() {
    // Replace "your_secret_key" with a strong secret key for encryption
    std::string secretKey = "your_secret_key";
    LicenseManager licenseManager(secretKey);

    // Customer information
    std::string customerName = "John Doe";
    std::string expirationDate = "2025-01-01";

    // Generate activation code
    std::string activationCode = licenseManager.generateActivationCode(customerName, expirationDate);
    std::cout << "Generated Activation Code: " << activationCode << std::endl;

    // Validate activation code
    if (licenseManager.validateActivationCode(activationCode, customerName, expirationDate)) {
        std::cout << "Activation Code is valid." << std::endl;
    } else {
        std::cout << "Activation Code is not valid." << std::endl;
    }

    return 0;
}
