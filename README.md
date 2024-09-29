# Digital Certificate Tools

# How to install
```bash
go install github.com/suryatresna/certools@latest
```

# How to use

## Generate Key Pair
```bash
certools key -o tmp/priv1
```

## Generate CSR
```bash
certools csr -o tmp/csr.pem -k tmp/priv1
```

## Generate Self-Signed Certificate
```bash
certools certificate -r tmp/csr.pem -k tmp/priv1 -p root -o tmp/certficate.crt
```

