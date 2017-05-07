A thin CGO wrapper around MIT libkrb5

The wrapper follows the MIT API, making the primary C objects into Go objects.

http://web.mit.edu/kerberos/krb5-current/doc/appldev/refs/api/index.html

For now, this is only capable of validating AP_REQ authentications, ... adding the rest should be trivial.

Tests needs to be run with faketime:

```shell
go test -v -exec 'faketime "2008-12-24 08:15:42"'
```

