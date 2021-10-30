# FTP with Encryption

## Index

  - [Overview](#overview) 
  - [Getting Started](#getting-started)

## Overview

- FTP program that provides encryption.

## Getting Started

### Dependencies

- OpenSSL install

```
## 
cd ftp-encrypt
wget https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_1_1l.tar.gz
tar -zvxf OpenSSL_1_1_1l.tar.gz

rm OpenSSL_1_1_1l.tar.gz && mv openssl-OpenSSL_1_1_1l openssl
cd openssl

## build & install
./config
make
make test
sudo make install
```
