package scanner

type Pattern struct {
	Name  string
	Bytes []byte
}

var DefaultPatterns = []Pattern{
	{
		Name:  "meterpreter",
		Bytes: []byte{0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8},
	},
	{
		Name:  "cobalt_strike",
		Bytes: []byte{0x2e, 0x2f, 0x2e, 0x2f, 0x2e, 0x2f, 0x2e, 0x2f},
	},
	{
		Name:  "shellcode_exec",
		Bytes: []byte{0x90, 0x90, 0x90, 0x90, 0x0f, 0x05},
	},
	{
		Name:  "bin_sh",
		Bytes: []byte{0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00},
	},
}

func SelectPatterns(names []string) []Pattern {
	if len(names) == 0 {
		return DefaultPatterns
	}
	byName := make(map[string]Pattern, len(DefaultPatterns))
	for _, p := range DefaultPatterns {
		byName[p.Name] = p
	}
	out := make([]Pattern, 0, len(names))
	for _, name := range names {
		if p, ok := byName[name]; ok {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return DefaultPatterns
	}
	return out
}
