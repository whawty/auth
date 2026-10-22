# whawty.auth app

## How To Install

### Package Manager

The easiest way to install the *whawty.auth app* is by installing one of the packages. For example, Debian packages can be found in the [spreadspace APT Repository](https://build.spreadspace.org/).


### go get

You can install & build the latest development version using `go get`:

```
go get github.com/whawty/auth/cmd/whawty-auth
```

You can run the app like this (assuming you also downloaded `../../contrib/store-cfg.yml`
and `../../contrib/listener-cfg.yml` and adapted them to your needs):

```
whawty-auth --store ./store-cfg.yml run --listener ./listener-cfg.yml
```


## How To Use

For up to date usage instructions, call the app's binary with the `--help` flag.

Next, you need to create a store, for example by using [../../contrib/init-store.sh](init-store.sh).
