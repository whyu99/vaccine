# Vaccine

This is for process regulation in the paper 'Vaccine: Injection Vulnerabilities Mitigation via Process Analysis and Regulation'.

## Instructions

### Installation Dependencies

In Debian/Ubuntu:

```c
apt install clang libelf1 libelf-dev zlib1g-dev cmake
```

In CentOS/Fedora:

```c
dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel cmake
```

### Project Construction

```c
cd vaccine
git submodule update --init --recursive # 初始化依赖库
mkdir build && cd build
cmake ../src
make
./se
```

## Examples

The input (subject object syscall) can be divided into three fields, separated by spaces.

**subject:** PID of process. Attention,  it is not the PID of attack process, but the PPID of its parent process.

**object:** sensitive resources

**syscall:** the permissions to be regulated. 

- 'r' - read.
- 'w' - write.
- 'x' - execute.



For example,

```
8774 /etc/passwd r
```

It means that the child process of shell with PID 8774 cannot read password file.

