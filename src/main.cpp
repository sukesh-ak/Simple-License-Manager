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
