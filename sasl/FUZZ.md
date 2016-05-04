# fuzzy-testing of encodings

Request and response encoding/decoding has been tested using go-fuzz. The test functions
used can be found in: fuzz.go. This code will only be built when using go-fuzz-build.
The following needs to be done to run fuzzy tests:

```
$ go get github.com/dvyukov/go-fuzz/go-fuzz
$ go get github.com/dvyukov/go-fuzz/go-fuzz-build
```

## Requests

```
$ go-fuzz-build -func FuzzRequest -o request-fuzz.zip github.com/whawty/auth/sasl
$ go-fuzz -bin=request-fuzz.zip -workdir request-fuzzd/
```

## Responses

```
$ go-fuzz-build -func FuzzResponse -o response-fuzz.zip github.com/whawty/auth/sasl
$ go-fuzz -bin=response-fuzz.zip -workdir response-fuzzd/
```
