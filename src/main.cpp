/*
MIT License

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
#include <cstring>
#include "slm.hpp"

int main() {
    // Replace "your_secret_key" with a strong secret key for encryption
    std::string secretKey = "your_secret_key";
    LicenseManager licenseManager(secretKey);

    // Customer information
    std::string customerName = "John Doe";
    std::string expirationDate = "2025-01-01";

    std::cout << "OpenSSL Version: " << OPENSSL_VERSION_TEXT << std::endl;

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
