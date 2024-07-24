# wget-for-windows

This is a fork of the [GNU wget](README). It is aiming to use *native* Windows certificate store and APIs to reduce dependencies.

GNU wget had closed the window for new features.

## Features

Small! The smallest ever file size ~500K.

New features:
* Originally writen wrapper of native Windows TLS (WinTLS) for https, ftps, ntlm and metalink, instead of OpenSSL and GNU hashes dependencies;
* New URL transcoding model;
* Windows IDN API instead of libidn.

## Cautions

WinTLS version: with the same capability of the OS. It fails if IE can't open the https URL! The old system may not have the lowest Cipher Suites that the server requests! Win10+ is recommended.

OpenSSL version: with openssl v1.1.1 latest, for legacy OS.

## Release

[Lite binaries](https://github.com/lifenjoiner/wget-for-windows/releases) have the most used features, but not all.

Try `wget -V`.

## Fork site

Issues/feedback for this fork: https://github.com/lifenjoiner/wget-for-windows


# wget-for-windows

这是 [GNU wget](README) 的一个分支。它是目标是用 Windows 的*原生* 证书库和 APIs 来减少依赖。

GNU wget 已经不再接收新特性。

## 特性

小！目前最小编译 ~500K。

新特性：
* 原创的原生 Windows TLS (WinTLS) 适配，支持 https、ftps、ntlm 和 metalink，摆脱依赖 OpenSSL 和 GNU hashes；
* 新 URL 转码模型；
* Windows IDN API 替代 libidn。

## 注意

WinTLS 版: 下载不了 IE 打不开的 https 地址，能力和操作系统一致！老系统可能连服务器要求的最低加密算法也不支持。推荐 Win10+。

OpenSSL 版: 包含 openssl v1.1.1 最后版本，专为老系统的。

## 发布

[轻便版](https://github.com/lifenjoiner/wget-for-windows/releases) 包含最常用的特性，而不是全部。

可查看 `wget -V`.

## 本分支

问题/反馈：https://github.com/lifenjoiner/wget-for-windows
