DISCONTINUATION OF PROJECT

This project will no longer be maintained by Intel.

Intel has ceased development and contributions including, but not limited to, maintenance, bug fixes, new releases, or updates, to this project.  

Intel no longer accepts patches to this project.

If you have an ongoing need to use this project, are interested in independently developing it, or would like to maintain patches for the open source software community, please create your own fork of this project.  
# Intel<sup>®</sup> Security Libraries for Data Center  - Privacy CA
#### This project provides an implementation of privacy certificate authority that is managed by the verification service. Each of the registered hosts for attestation provide the TPM measurements signed by the host's TPM generated Attestation Identity Key (AIK). The Privacy CA key is used as part of the certificate chain for the host AIK during Trust Agent provisioning and registration to the verification service.

## Key features
- Provides implementation of `Privacy CA` which can be utilized to certify keys

## System Requirements
- RHEL 7.5/7.6
- Epel 7 Repo
- Proxy settings if applicable

## Software requirements
- git
- maven (v3.3.1)
- ant (v1.9.10 or more)

# Step By Step Build Instructions
## Install required shell commands
Please make sure that you have the right `http proxy` settings if you are behind a proxy
```shell
export HTTP_PROXY=http://<proxy>:<port>
export HTTPS_PROXY=https://<proxy>:<port>
```
### Install tools from `yum`
```shell
$ sudo yum install -y wget git zip unzip ant gcc patch gcc-c++ trousers-devel openssl-devel makeself
```

## Direct dependencies
Following repositories needs to be build before building this repository,

| Name                       | Repo URL                                                 |
| -------------------------- | -------------------------------------------------------- |
| common-java                | https://github.com/intel-secl/common-java                |
| lib-common                 | https://github.com/intel-secl/lib-common                 |
| lib-privacyca              | https://github.com/intel-secl/lib-privacyca              |

## Build Privacy CA

- Git clone the `Privacy CA`
- Run scripts to build the `Privacy CA`

```shell
$ git clone https://github.com/intel-secl/privacyca.git
$ cd privacyca
$ ant
```

# Links
 - Use [Automated Build Steps](https://01.org/intel-secl/documentation/build-installation-scripts) to build all repositories in one go, this will also provide provision to install prerequisites and would handle order and version of dependent repositories.

***Note:** Automated script would install a specific version of the build tools, which might be different than the one you are currently using*
 - [Product Documentation](https://01.org/intel-secl/documentation/intel%C2%AE-secl-dc-product-guide)
