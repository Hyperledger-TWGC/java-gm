# java-gm

基于BouncyCastle实现国密算法SM2、SM3、SM4的操作类，并验证与其他语言（NodeJS、Go）实现的国密库的互操作性。

[![Build Status](https://dev.azure.com/Hyperledger/TWGC/_apis/build/status/Hyperledger-TWGC.java-gm?branchName=master)](https://dev.azure.com/Hyperledger/TWGC/_build/latest?definitionId=129&branchName=master)

## Feature 功能支持列表

|  SM2功能   | 支持范围  | 
|  ----  | ----  |
| Generate KeyPair  | `是` |
| Derive public key from private key  | `是` |
| Sign  | `是` |
| Verify | `是` |
| PEM格式导出 | `私钥/公钥/CSR`|
| PEM文件加密 | RFC5958 |
| PEM格式导入 | `私钥/公钥/CSR` |
 
 备注：
 
 C1C3C2和SM2SM3作为默认的加密和Hash算法，同时接口层面保留C1C2C3和其他Hash方式的支持。

|  SM4功能   | 支持范围  | 
|  ----  | ----  |
| Generate Key |  |
| Encrypt, Decrypt | `是` |
| PEM格式导出 |   |
| PEM文件加密 | |
| 分组模式 | ECB/CBC/CFB/OFB/CTR |


|  SM3功能   | 支持范围  | 
|  ----  | ----  |
| 当前语言Hash接口兼容 | `是` |

## Terminology 术语
- SM2: 国密椭圆曲线算法库
- SM3: 国密hash算法库
- SM4: 国密分组密码算法库

## How to Contribute 贡献须知
We welcome contributions to Hyperledger in many forms, and there's always plenty to do!

Please visit the [contributors guide](CONTRIBUTING.md) in the
docs to learn how to make contributions to this exciting project.

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.

## License 许可证
Hyperledger Project source code files are made available under the Apache License, Version 2.0 (Apache-2.0), located in the [LICENSE](LICENSE) file.
