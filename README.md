# passcheck

`passcheck` is a package and CLI tool to check passwords against the Pwned Password API.

## Usage

### Package

First, install the package:

```sh
go get -u github.com/dbarbuzzi/passcheck
```

The simplest use-case is to create a new API client using `NewPwnedPasswords` and then pass a password and the client to `Check` to get the pwnage results for that password:

```go
// main.go
package main

import (
	"fmt"

	"github.com/dbarbuzzi/passcheck"
)

func main() {
	client, err := passcheck.NewPwnedPasswords("https://api.pwnedpasswords.com")
	if err != nil {
		panic(err)
	}

	count, err := passcheck.Check("password", client)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Password has been pwned %d times.\n", count)
}
```

```
$ go run main.go
Password has been pwned 3730471 times.
```

A few other functions are available to check a hash instead of a password (so you don’t need to give the password to this package) or to check multiple passwords/hashes.

### CLI

Coming soon!
