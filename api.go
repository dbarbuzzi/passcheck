package passcheck

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"

	"github.com/pkg/errors"
)

// API is an interface representing a thin wrapper of the Pwned Passwords API
type API interface {
	Range(string) (RangeMap, error)
}

// NewPwnedPasswords creates a new PwnedPasswords with the given base URL or
// throws an error if the given base URL is invalid.
func NewPwnedPasswords(baseURL string) (*PwnedPasswords, error) {
	uri, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	ua := fmt.Sprintf("%s/passcheck-%s (%s/%s)", runtime.Version(), version, runtime.GOOS, runtime.GOARCH)
	return &PwnedPasswords{BaseURL: uri, userAgent: ua}, nil
}

// PwnedPasswords is a thin wrapper for the Pwned Passwords API
type PwnedPasswords struct {
	BaseURL   *url.URL
	userAgent string
}

func (pp PwnedPasswords) get(path string) (io.ReadCloser, error) {
	parsedPath, err := url.Parse(path)
	if err != nil {
		return nil, err
	}
	uri := pp.BaseURL.ResolveReference(parsedPath)

	resp, err := http.Get(uri.String())
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		return nil, fmt.Errorf("received status code %d; body: <%s>", resp.StatusCode, buf)
	}

	return resp.Body, nil
}

// RangeMap represents a parsed response object from the PwnedPassword API’s
// `/range` endpoint. The keys are suffixes of password hashes with int values
// representing the count of ‘pwnage’s of the specific password represented by
// the combined hash prefix + suffix
type RangeMap map[string]int

// Range calls the PwnedPassword API’s `/range` endpoint and returns a parsed
// version of that endpoint’s response
func (pp PwnedPasswords) Range(prefix string) (RangeMap, error) {
	path := fmt.Sprintf("/range/%s", prefix)
	rspBody, err := pp.get(path)
	if err != nil {
		return nil, err
	}
	defer rspBody.Close()

	return parseRangeResponse(rspBody)
}

func parseRangeResponse(r io.Reader) (RangeMap, error) {
	rm := make(map[string]int)
	scanner := bufio.NewScanner(r)
	var key string
	var count int
	for scanner.Scan() {
		line := strings.ReplaceAll(scanner.Text(), ":", " ")
		// fmt.Printf("line: <%s>\n", line)
		fmt.Sscanf(line, "%s %d", &key, &count)
		rm[key] = count
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.Wrap(err, "error parsing /range response")
	}

	return rm, nil
}
