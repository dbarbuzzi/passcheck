package passcheck

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type MockAPI struct {
	BaseURL string
}

func (m MockAPI) Range(prefix string) (RangeMap, error) {
	predefinedResponses := map[string]RangeMap{
		"5BAA6": RangeMap{ // "password"
			"003D68EB55068C33ACE09247EE4C639306B": 3,
			"012C192B2F16F82EA0EB9EF18D9D539B0DD": 1,
			"01330C689E5D64F660D6947A93AD634EF8F": 1,
			"19E0061EB9188471E381E9893736CF16EC4": 2,
			"1B9A9E0B079726677FDF4383AA7FFD2C23E": 1,
			"1C12D46C02461550809D10EF62DDEE99F75": 2,
			"1CB7055517A54D1B0F1847EB84904E69438": 2,
			"1CC93AEF7B58A1B631CB55BF3A3A3750285": 3,
			"1D2DA4053E34E76F6576ED1DA63134B5E2A": 2,
			"1D72CD07550416C216D8AD296BF5C0AE8E0": 10,
			"1E2AAA439972480CEC7F16C795BBB429372": 1,
			"1E3687A61BFCE35F69B7408158101C8E414": 1,
			"1E4C9B93F3F0682250B6CF8331B7EE68FD8": 3730471,
			"1F2B668E8AABEF1C59E9EC6F82E3F3CD786": 1,
			"20597F5AC10A2F67701B4AD1D3A09F72250": 3,
			"20AEBCE40E55EDA1CE07D175EC293150A7E": 1,
			"20FFB975547F6A33C2882CFF8CE2BC49720": 1,
			"21901C19C92442A5B1C45419F7887722FCF": 1,
			"9A64187BCC48B58951D257C52B14FB4BFAA": 1,
			"9B169DAF7CE65D21740C98E86BDBA060394": 3,
			"9B2910F2CFDDD75FFD3F8A66D2A7C94EA4C": 2,
			"9B3D0A0D720CD19E1666D436209FE225A84": 2,
			"9B4810BF7A2AA36C1A69C7BB389C0AB468A": 3,
			"9BDF0C480B0D0A11709B21CBE3817FF543D": 1,
			"9C259745113253B31DD49E1134660E97821": 2,
			"9C5B0CFF0631BB55FC80F2D3E3B01297405": 1,
			"9C809290E171DB37854E47232494435EDF5": 1,
			"9D782CA5C8B5FAEDE9CB53F6FF59C525A46": 5,
			"9D8FBE84AD481A6A714C8F9F902B6D22602": 3,
			"A3AB5611237C03DAA93FA05FF59788C6420": 2,
			"CD2ED30371EA8A8BB14FEF8BDEF5AC56824": 1,
			"CD8BE68452C665F7400DE9DAD5485D2F315": 1,
			"CDE902213D3FDD1237BF0BE02F05F44A820": 3,
			"CF2F87E596758D031C0006D1827C9908E5C": 34,
			"CFF6AFD2AB482897C76BCD2D19CACEC3B55": 2,
			"D021616E53238BF0DE66516613F1DE72C2F": 6,
			"FFCDFF228BE98F296C0CA4CE1FC8815A30E": 5,
		},
		"23C33": RangeMap{"970E5BE3F9768766CCF1307D32875074FD0": 1}, // "electric slide"
		"0906D": RangeMap{},                                         // "k3@nu r33v3s"
	}
	if val, ok := predefinedResponses[prefix]; ok {
		return val, nil
	}
	return nil, errors.New("unknown input")
}

func TestCheck(t *testing.T) {
	mockAPI := MockAPI{}
	tcs := []struct {
		input string
		want  int
	}{
		{"password", 3730471},
		{"electric slide", 1},
		{"k3@nu r33v3s", 0},
	}

	for _, tc := range tcs {
		got, err := Check(tc.input, mockAPI)
		if err != nil {
			t.Fatalf("error checking test input %s: %+v", tc.input, err)
		}
		if diff := cmp.Diff(tc.want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	}
}

func TestCheckHash(t *testing.T) {
	mockAPI := MockAPI{}
	tcs := []struct {
		input string
		want  int
	}{
		{"5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", 3730471},
		{"23C33970E5BE3F9768766CCF1307D32875074FD0", 1},
		{"0906D319318CC63DD6CE8B2751E3D26C34A5995E", 0},
	}

	for _, tc := range tcs {
		got, err := CheckHash(tc.input, mockAPI)
		if err != nil {
			t.Fatalf("error checking test input %s: %+v", tc.input, err)
		}
		if diff := cmp.Diff(tc.want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	}
}

func TestGetSha1Hash(t *testing.T) {
	tcs := []struct {
		name  string
		input string
		want  string
	}{
		{"MiscText", "This page intentionally left blank.", "AF064923BBF2301596AAC4C273BA32178EBC4A96"},
		{"MultilineText", "Woah Black Betty\nBam-ba-Lam", "3DEE0B36CCBE39817875E4EC07870FFC28D5BCA9"},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := getSha1Hash(tc.input)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("%s mismatch (-want +got):\n%s", tc.name, diff)
			}
		})
	}
}
