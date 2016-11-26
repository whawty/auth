# whawty.auth app

## How To Install

### Package Manager

The easiest way to install the *whawty.auth app* is by installing one of the packages. For example, Debian packages can be found in the [spreadspace APT Repository](https://build.spreadspace.org/).


### go get

You can install & build the latest development version using `go get`:

```
$ mkdir whawty-auth
$ cd whawty-auth
$ GOPATH=`pwd` go get github.com/whawty/auth/app
$ ./bin/app --help
```

This will create a `app` binary in the `bin` folder, which corresponds to the `whawty-auth` binary.

Since *go get* won't copy static files, you need to specify their location in case you want to run the web app:

```
./bin/app --web-static-dir ./src/github.com/whawty/auth/app/html --store ./auth-store-config.yaml run --web-addr :4242
```


## How To Use

For up to date usage instructions, call the app's binary with the `--help` flag.

Next, you need to create a store, for example by using [init-store.sh](init-store.sh).
