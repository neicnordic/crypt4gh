# crypt4gh
[![Build Status](https://github.com/elixir-oslo/crypt4gh/workflows/Go/badge.svg)](https://github.com/uio-bmi/lega-uploader/actions)
[![GoDoc](https://godoc.org/github.com/elixir-oslo/crypt4gh?status.svg)](https://godoc.org/github.com/elixir-oslo/crypt4gh)
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
To install the latest version of the console app you can use the following one-liner (assuming you are using `bash`):
```
curl -fsSL https://raw.githubusercontent.com/elixir-oslo/crypt4gh/master/install.sh | sh
```

Alternatively, go to the [releases page](https://github.com/elixir-oslo/crypt4gh/releases) and download the desired binary manually (for example, `.exe` file for Windows).

## Usage
```
$ crypt4gh
crypt4gh [generate | encrypt | decrypt] <args>

 generate:
  -n, --name= Key pair name

 encrypt:
  -f, --file=FILE      File to encrypt
  -s, --seckey=FILE    Secret key to use
  -p, --pubkey=FILE    Public key to use

 decrypt:
  -f, --file=FILE      File to decrypt
  -s, --seckey=FILE    Secret key to use
```
