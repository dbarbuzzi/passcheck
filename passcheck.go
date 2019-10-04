package passcheck

import (
	"crypto/sha1"
	"fmt"
	"io"
	"time"
)

const version = "dev"

// Check accepts a password string and checks it against the Pwned Passwords API
// returning a count of how many times it has been ‘pwned’.
func Check(pw string, client API) (int, error) {
	pwHash := getSha1Hash(pw)
	return CheckHash(pwHash, client)
}

// CheckHash accepts a string SHA1 hash of a password and checks it against the
// Pwned Passwords API returning a count of how many times the represented
// password has been ‘pwned’.
//
// This is a nearly identical to the `Check` method except it allows the
// consumer to do its own hashing so it does not need to provide the actual
// password to this package.
func CheckHash(pwHash string, client API) (int, error) {
	prefix, suffix := pwHash[:5], pwHash[5:]
	rm, err := client.Range(prefix)
	if err != nil {
		return 0, err
	}

	return rm[suffix], nil
}

// CheckMultiple checks multiple passwords against the Pwned Password API and
// returns a map with the passwords as the keys and their ‘pwned’ counts as the
// values.
// It is advised to de-duplicate the list of passwords before passing it to this
// function. A rate limite of 8 requests/second is imposed.
func CheckMultiple(pws []string, client API) (map[string]int, error) {
	hashes := make([]string, 0, len(pws))
	pwMap := make(map[string]string, len(pws))
	for _, pw := range pws {
		pwHash := getSha1Hash(pw)
		hashes = append(hashes, pwHash)
		pwMap[pwHash] = pw
	}
	results, err := CheckMultipleHashes(hashes, client)
	if err != nil {
		return nil, err
	}
	countMap := make(map[string]int, len(results))
	for hash, count := range results {
		pw := pwMap[hash]
		countMap[pw] = count
	}
	return countMap, nil
}

// CheckMultipleHashes checks multiple string SHA1 hashes against the Pwned
// Password API and returns a map with the passwords as the keys and their
// ‘pwned’ counts as the values.
// It is advised to de-duplicate the list of hashes before passing it to this
// function. A rate limite of 8 requests/second is imposed.
//
// This is nearly identical to the `CheckMultple` method except it allows the
// consumer to do its own hashing so it does not need to provide the actual
// password to this package.
func CheckMultipleHashes(pwHashes []string, client API) (map[string]int, error) {
	results := make(map[string]int, len(pwHashes))

	rate := time.Second / 8
	throttle := time.Tick(rate)
	for _, pwHash := range pwHashes {
		<-throttle
		count, err := CheckHash(pwHash, client)
		if err != nil {
			return nil, err
		}
		results[pwHash] = count
	}

	return results, nil
}

func getSha1Hash(pw string) string {
	hash := sha1.New()
	io.WriteString(hash, pw)
	return fmt.Sprintf("%X", hash.Sum(nil))
}
