# crypt4gh
[![Build Status](https://github.com/neicnordic/crypt4gh/workflows/Go/badge.svg)](https://github.com/neicnordic/crypt4gh/actions)
[![GoDoc](https://godoc.org/github.com/neicnordic/crypt4gh?status.svg)](https://pkg.go.dev/github.com/neicnordic/crypt4gh?tab=subdirectories)
[![Go Report Card](https://goreportcard.com/badge/github.com/neicnordic/crypt4gh)](https://goreportcard.com/report/github.com/neicnordic/crypt4gh)
[![codecov](https://codecov.io/gh/neicnordic/crypt4gh/branch/master/graph/badge.svg)](https://codecov.io/gh/neicnordic/crypt4gh)

## Overview
![](https://www.ga4gh.org/wp-content/uploads/Crypt4GH_comic.png)

## Specification
Current version of specs can be found [here](http://samtools.github.io/hts-specs/crypt4gh.pdf).

## Installation

### Linux
```
curl -fsSL https://raw.githubusercontent.com/neicnordic/crypt4gh/master/install.sh | sudo sh
```

### MacOS
```
curl -fsSL https://raw.githubusercontent.com/neicnordic/crypt4gh/master/install.sh | sudo sh
```

### Windows
Go to the [releases page](https://github.com/neicnordic/crypt4gh/releases) and download the binary manually.

## Usage
```
$ crypt4gh
crypt4gh [generate | encrypt | decrypt | reencrypt] <args>

 generate:
  -n, --name=                     Key pair name
  -f, --format=[openssl|crypt4gh] Key pair format
  -p, --password=                 Password to lock Crypt4GH private key (will be prompted afterwords if skipped)

 encrypt:
  -f, --file=FILE      File to encrypt
  -p, --pubkey=FILE    Public key to use, this parameter can be used multiple times, one key per parameter
  -s, --seckey=FILE    Secret key to use

 decrypt:
  -f, --file=FILE      File to decrypt
  -s, --seckey=FILE    Secret key to use

 reencrypt:
  -f, --file=FILE      Input File to re-encrypt
  -o, --out=FILE       Output File to after re-encrypt
  -p, --pubkey=FILE    Public key to use, this parameter can be used multiple times, one key per parameter
  -s, --seckey=FILE    Secret key to use

 Environment variables:

 C4GH_SECRET_KEY	If defined, it will be used as the secret key file if parameter not set parameter not set
```

### Examples

#### Generate Keys
```
crypt4gh generate -n=recipient-A
crypt4gh generate -n=recipient-B
crypt4gh generate -n=sender-C
```

#### Encrypt Files

```
crypt4gh encrypt -f sample.txt -s sender-C.sec.pem -p recipient-A.pub.pem
```
Multiple recipients can be added with by using the `-p` parameter multiple times
```
crypt4gh encrypt -f sample.txt -s sender-C.sec.pem -p recipient-A.pub.pem -p recipient-B.pub.pem
```
#### Decrypt Files

```
crypt4gh decrypt -f sample.txt.c4gh -s recipient-A.sec.pem
```

#### Re-Encrypt Files
Re-encrypting a file will completely replace the old header with a new one. If the file is intended to be decrypted by multiple recipients, all relevant public keys must be given again on re-encryption.
```
crypt4gh encrypt -f sample.txt -s sender-C.sec.pem -p recipient-A.pub.pem
crypt4gh reencrypt -f sample.txt.c4gh -s recipient-A.sec.pem -p recipient-B.pub.pem  -p recipient-A.pub.pem -o cool.c4gh
crypt4gh decrypt -f cool.c4gh -s recipient-A.sec.pem
crypt4gh decrypt -f cool.c4gh -s recipient-B.sec.pem
```
