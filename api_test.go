package passcheck

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseRangeResponse(t *testing.T) {
	tcs := []struct {
		name  string
		input string
		want  RangeMap
	}{
		{
			"SingleLine",
			"CB127D6CC0B46A334BC1F5BEA141A1C216B:1",
			RangeMap{"CB127D6CC0B46A334BC1F5BEA141A1C216B": 1},
		},
		{
			"SingleLineTrailingNewline",
			"CB127D6CC0B46A334BC1F5BEA141A1C216B:1\r\n",
			RangeMap{"CB127D6CC0B46A334BC1F5BEA141A1C216B": 1},
		},
		{
			"TwoLines",
			"CB127D6CC0B46A334BC1F5BEA141A1C216B:1\r\n4B4E8E4535D07E060DBCD1471EA8D657C84:2",
			RangeMap{"CB127D6CC0B46A334BC1F5BEA141A1C216B": 1, "4B4E8E4535D07E060DBCD1471EA8D657C84": 2},
		},
		{
			"MultipleLines",
			"0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n011053FD0102E94D6AE2F8B83D76FAF94F6:1\r\n012A7CA357541F0AC487871FEEC1891C49C:2\r\n0136E006E24E7D152139815FB0FC6A50B15:2",
			RangeMap{"0018A45C4D1DEF81644B54AB7F969B88D65": 1,
				"00D4F6E8FA6EECAD2A3AA415EEC418D38EC": 2,
				"011053FD0102E94D6AE2F8B83D76FAF94F6": 1,
				"012A7CA357541F0AC487871FEEC1891C49C": 2,
				"0136E006E24E7D152139815FB0FC6A50B15": 2},
		},
	}

	for _, tc := range tcs {
		caseName := fmt.Sprintf("parseRangeTest:%s", tc.name)
		t.Run(caseName, func(t *testing.T) {
			input := strings.NewReader(tc.input)
			got, err := parseRangeResponse(input)
			if err != nil {
				t.Fatalf("error parsing test input: %+v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("%s mismatch (-want +got):\n%s", caseName, diff)
			}
		})
	}
}
