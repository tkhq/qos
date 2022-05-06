# Quorum OS

This is in a very rough state...

### Development

Ensure that the location of the socket is r/w:

```shell
make shell
> chmod 777 /var/run/qos
```

Run the enclave:
```shell
make enclave
```

Run the client:
```shell
make client
```