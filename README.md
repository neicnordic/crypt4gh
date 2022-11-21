# crypt4gh
[![Build Status](https://github.com/neicnordic/crypt4gh/workflows/Go/badge.svg)](https://github.com/neicnordic/crypt4gh/actions)
[![GoDoc](https://godoc.org/github.com/neicnordic/crypt4gh?status.svg)](https://pkg.go.dev/github.com/neicnordic/crypt4gh?tab=subdirectories)
[![Go Report Card](https://goreportcard.com/badge/github.com/neicnordic/crypt4gh)](https://goreportcard.com/report/github.com/neicnordic/crypt4gh)
[![codecov](https://codecov.io/gh/neicnordic/crypt4gh/branch/master/graph/badge.svg)](https://codecov.io/gh/neicnordic/crypt4gh)

## Overview
![](https://www.ga4gh.org/wp-content/uploads/Crypt4GH_comic.png)

## File structure
![](https://habrastorage.org/webt/yn/y2/pk/yny2pkp68sccx1vbvmodz-hfpzm.png)

## Specification
Current version of specs can be found [here](http://samtools.github.io/hts-specs/crypt4gh.pdf).

## Installation

### Linux
```
curl -fsSL https://raw.githubusercontent.com/neicnordic/crypt4gh/master/install.sh | sudo sh
```

### MacOS
```
curl -fsSL https://raw.githubusercontent.com/neicnordic/crypt4gh/master/install.sh | sh
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
  -p, --pubkey=FILE    Public key(s) to use
  -s, --seckey=FILE    Secret key to use

 decrypt:
  -f, --file=FILE      File to decrypt
  -s, --seckey=FILE    Secret key to use

 reencrypt:
  -f, --file=FILE      Input File to re-encrypt
  -o, --out=FILE       Output File to after re-encrypt
  -p, --pubkey=FILE    Public key(s) to use
  -s, --seckey=FILE    Secret key to use

 Environment variables:

 C4GH_SECRET_KEY        If defined, it will be used as the secret key file if parameter not set
```
