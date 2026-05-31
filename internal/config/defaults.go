package config

const (
	DefaultMode           = "asm"
	DefaultRingBufferSize = 65536
)

var DefaultPatterns = []string{
	"meterpreter",
	"cobalt_strike",
	"shellcode_exec",
	"bin_sh",
}
