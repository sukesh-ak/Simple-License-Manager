# Simple License Manager
A simple license manager implementation using OpenSSL

## Setup, Install & Compile
```bash

# On Linux - install g++ / cmake / gdb
sudo apt update && sudo apt install build-essential gdb  
sudo apt update && sudo apt install cmake

# Clone the repository
git clone --recursive -j8 https://github.com/sukesh-ak/Simple-License-Manager.git
cd Simple-License-Manager

# Install dependencies using vcpkg.json
./vcpkg/vcpkg install

# Compile
mkdir build 
cmake -B build && cmake --build build

# Run
./build/licensemanager

```