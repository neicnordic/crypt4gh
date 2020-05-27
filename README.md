# crypt4gh
[![Build Status](https://github.com/elixir-oslo/crypt4gh/workflows/Go/badge.svg)](https://github.com/elixir-oslo/crypt4gh/actions)
[![GoDoc](https://godoc.org/github.com/elixir-oslo/crypt4gh?status.svg)](https://pkg.go.dev/github.com/elixir-oslo/crypt4gh?tab=subdirectories)
[![CodeFactor](https://www.codefactor.io/repository/github/elixir-oslo/crypt4gh/badge)](https://www.codefactor.io/repository/github/elixir-oslo/crypt4gh)
[![Go Report Card](https://goreportcard.com/badge/github.com/elixir-oslo/crypt4gh)](https://goreportcard.com/report/github.com/elixir-oslo/crypt4gh)
[![codecov](https://codecov.io/gh/elixir-oslo/crypt4gh/branch/master/graph/badge.svg)](https://codecov.io/gh/elixir-oslo/crypt4gh)
[![Dependabot Status](https://api.dependabot.com/badges/status?host=github&repo=elixir-oslo/crypt4gh)](https://dependabot.com)

[![DeepSource](https://static.deepsource.io/deepsource-badge-light.svg)](https://deepsource.io/gh/elixir-oslo/crypt4gh/?ref=repository-badge)
## Overview
![](https://www.ga4gh.org/wp-content/uploads/Crypt4GH_comic.png)

## File structure
![](https://habrastorage.org/webt/yn/y2/pk/yny2pkp68sccx1vbvmodz-hfpzm.png)

## Specification
Current version of specs can be found [here](http://samtools.github.io/hts-specs/crypt4gh.pdf).

## Installation

### Linux
```
curl -fsSL https://raw.githubusercontent.com/elixir-oslo/crypt4gh/master/install.sh | sudo sh
```

### MacOS
```
curl -fsSL https://raw.githubusercontent.com/elixir-oslo/crypt4gh/master/install.sh | sh
```

### Windows
Go to the [releases page](https://github.com/elixir-oslo/crypt4gh/releases) and download the binary manually.

## Usage
```
$ crypt4gh
crypt4gh [generate | encrypt | decrypt] <args>

 generate:
  -n, --name=                     Key pair name
  -f, --format=[openssl|crypt4gh] Key pair format
  -p, --password=                 Password to lock Crypt4GH private key (will be prompted afterwords if skipped)

 encrypt:
  -f, --file=FILE      File to encrypt
  -s, --seckey=FILE    Secret key to use
  -p, --pubkey=FILE    Public key to use

 decrypt:
  -f, --file=FILE      File to decrypt
  -s, --seckey=FILE    Secret key to use
```
