# CloudChain RKSync CA

[![Build Status](https://travis-ci.org/rkcloudchain/rksync-ca.svg?branch=master)](https://travis-ci.org/rkcloudchain/rksync-ca)
[![codecov](https://codecov.io/gh/rkcloudchain/rksync-ca/branch/master/graph/badge.svg)](https://codecov.io/gh/rkcloudchain/rksync-ca)
[![Go Report Card](https://goreportcard.com/badge/github.com/rkcloudchain/rksync-ca)](https://goreportcard.com/report/github.com/rkcloudchain/rksync-ca)

The CloudChain RKSync CA is a Certificate Authority(CA) for CloudChain RKSync. It issuance of X.509 digital certificate as digital identity for [RKSync](https://github.com/rkcloudchain/rksync) members.

## Getting Started

### Prerequisites

* Go 1.12+
* make

### Build

The following command builds the rksync-ca server binaries in `path/to/your/repository/bin`:

```shell
make release
```

Or you can use the following command to generate a docker image of rksync-ca server:

```shell
make docker
```

### Start Server Natively

The following starts the rksync-ca serve with default settings:

```shell
rksync-ca start -H /path/to/workdir --db.type mariadb --db.datasource datasource
```

**Note:**

* The `-H` flag specifies the working directory of the program.A default configuration file named rksync-ca-config.yaml is created in that directory which can be customized.
* The `--db.type` flag specifies the database type. Currently only supports two types of database: MariaDB or PostgreSQL
* The `--db.datasource` flag specifies the DSN(Data Source Name)

### Start Server via Docker

Navigate to /path/to/your/repository/docker and open up docker-compose.yml in an editor. Change the image line to reflect the tag you found previously. The file may look like this:

```yaml
version: '3'

services:
  db:
    image: mariadb:latest
    container_name: mariadb
    environment:
      - MYSQL_ROOT_PASSWORD=rootpw
    networks:
      - rksyncca
    ports:
      - 3306:3306

  rksync-ca:
    image: cloudchain/rksync-ca:latest
    container_name: rksync-ca
    ports:
      - 8054:8054
    links:
      - db
    volumes:
      - ./wait-for.sh:/etc/cloudchain/rksync-ca-server/wait-for.sh
    environment:
      - RKSYNC_CA_HOME=/etc/hyperledger/rksync-ca
      - RKSYNC_CA_DB_TYPE=mariadb
      - RKSYNC_CA_DB_DATASOURCE=root:rootpw@tcp(db:3306)/rksync_ca?parseTime=true&tls=false
    networks:
      - rksyncca
    command: sh -c '/etc/cloudchain/rksync-ca-server/wait-for.sh db:3306 -- rksync-ca start'
    depends_on:
      - db

networks:
  rksyncca:
    driver: bridge
```

Open up a terminal in the same directory as the docker-compose.yml file and execute the following:

```shell
docker-compose up -d
```

This will start an instance of the rksync-ca server.

## RKSync CA Client

The client package is the SDK that interacts with the rksync-ca server.

### Install

```shell
go get -u github.com/rkcloudchain/rksync-ca/client
```

### Example

```go
package main

import (
    "github.com/cloudflare/cfssl/csr"
    "github.com/rkcloudchain/rksync-ca/api"
    "github.com/rkcloudchain/rksync-ca/client"
    "github.com/rkcloudchain/rksync-ca/config"
)

func main() {
    c := &client.Client{
        HomeDir: "/path/to/your/workdir",
        Config: &config.ClientConfig{
            URL: "http://host:port",
        },
    }

    // register a user
    resp, err := c.Register(&api.RegistrationRequest{Name: "name1"})
    if err != nil {
        panic(err)
    }

    // Enroll a x.509 certificate
    _, err = c.Enroll(&api.EnrollmentRequest{
        Name:   "name1",
        Secret: resp.Secret,
        CSR: &api.CSRInfo{CN: "Rockontrol", Names: []csr.Name{
            csr.Name{C: "CN", ST: "Sichuan", L: "Chengdu", O: "CloudChain", OU: "Dep"},
        }},
    }, true)

    if err != nil {
        panic(err)
    }
}
```

## Thanks to

This project was modified based on the [Hyperledger fabric-ca](https://github.com/hyperledger/fabric-ca) project, we removed some of the unwanted features and added what we needed. Thanks to the excellent work of the hyperledger team.

## License

RKSync-ca is under the Apache 2.0 license. See the [LICENSE](https://github.com/rkcloudchain/rksync-ca/blob/master/LICENSE) file for details.