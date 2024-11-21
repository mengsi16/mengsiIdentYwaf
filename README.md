# superIdentYwaf
## 项目简介

本项目是基于 idnetYwaf(https://github.com/stamparm/identYwaf) 进行改进和优化的版本，感谢 stamparm等多位开发者 的卓越工作。

## 改进内容

- 优化了性能：
  - superIdentYwaf将45个测试案例优化为并行测试，极大增快了identYwaf在这部分的运行效率。
- 添加了新功能：
  - 现在，superIdentYwaf可以自己选择是否重定向了。
  - superIdentYwaf添加了并行化的批量测试功能，用户可以提供一个待测试网站文件(.csv、.txt)路径，superIdentYwaf将读取文件内的网站然后进行批量测试。

## 更进一步的改进方向

superIdentYwaf更进一步改进方向：
1. 应该添加JS、CSS等处理模块
2. 应该对一些不在data.json记录的waf进行探测

## 致谢

特别感谢原作者的贡献。
