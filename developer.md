# 开发者文档

## [checkstyle](https://checkstyle.sourceforge.io/)
项目使用`checkstyle`作为lint工具。格式参考`./config/checkstyle/checkstyle.xml`
如果遇到lint错误，可以参考该目录进行修复或者参考命令行提示。
`./java-gm/build/reports/checkstyle/checkstyle.html`

## gradle
项目使用gradle，请通过`gradle clean test`来进行单元测试。目前的流程：
```shell script
gradle clean test --dry-run
:clean SKIPPED
:compileJava SKIPPED
:processResources SKIPPED
:classes SKIPPED
:compileTestJava SKIPPED
:processTestResources SKIPPED
:testClasses SKIPPED
:test SKIPPED
```

## 互操作测试
请大家尽量在提交代码前在本地进行互操作认证，步骤如下：

- gradle build 
- cd ${workdir}
- git clone https://github.com/Hyperledger-TWGC/fabric-gm-plugins
- cp -f java-gm/*.pem ${workdir}/fabric-gm-plugins/interop/testdata 
- cd ${workdir}fabric-gm-plugins/interop
- go test tjjavaImport_test.go