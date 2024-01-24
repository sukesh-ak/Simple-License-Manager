# Simple License Manager - SLM
A Header-Only Simple License Manager implementation using OpenSSL

## Setup, Install & Compile
```bash

# On Linux - install g++ / cmake / gdb
> sudo apt update && sudo apt install build-essential gdb  
> sudo apt update && sudo apt install cmake

# Clone the repository
> git clone --recursive -j8 https://github.com/sukesh-ak/Simple-License-Manager.git
> cd Simple-License-Manager

# Install dependencies using vcpkg.json
> ./vcpkg/vcpkg install

# Compile
> mkdir build 
> cmake -B build && cmake --build build

```

## How to use - Code Snippet
```c++
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
```

```bash
# Run to see the Output
> ./build/licensemanager 
Generated Activation Code: 5ExlwWqGCFTNnTLI6lwCCgqlwZcQKQTITGnMIvZiFCY=

Activation Code is valid.
```