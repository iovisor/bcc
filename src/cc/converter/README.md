# converter

1. put bcc source at source.bcc.c
2. run `make`

    ```sh
    make build
    ```

3. get libbpf source at output.bpf.c

## How to convert bcc to libbpf

```txt
1. bcc source -> libbpf source
source code -> bcc-front-end AST -> rewrited source code
rewrited source code -> preprocessor -> libbpf source code
(may be multi pass)

2. bcc runtime -> libbpf runtime
libbpf source -> ecc -> libbpf CO-RE ELF + meta data (JSON or YAML)
bcc runtime attach -> meta data (Preserve the bcc runtime attach point and other state)
libbpf CO-RE ELF + modified meta data -> auto load by libbpf CO-RE runtime base on config
```
