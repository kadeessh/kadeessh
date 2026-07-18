package authentication

import "strings"

// ParseAuthorizedKeyOptions splits the option list returned by
// ssh.ParseAuthorizedKey into an SSH-certificate-style pair of maps:
//
//   - criticalOptions receives every "key=value" option; the value is
//     stripped of a single matching pair of surrounding double quotes so
//     that command="ls -la" yields criticalOptions["command"] == "ls -la".
//   - extensions receives every bare option (no "=") as key with an empty
//     value, e.g. "no-port-forwarding".
//
// If the same key appears more than once (e.g. multiple permitopen= or
// environment= entries) the values are joined with commas, matching how
// the SSH protocol serializes multi-valued critical options.
//
// The caller is responsible for further interpreting option semantics.
func ParseAuthorizedKeyOptions(opts []string) (criticalOptions, extensions map[string]string) {
	criticalOptions = map[string]string{}
	extensions = map[string]string{}
	for _, opt := range opts {
		k, v, hasValue := strings.Cut(opt, "=")
		if !hasValue {
			extensions[k] = ""
			continue
		}
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		if existing, ok := criticalOptions[k]; ok {
			criticalOptions[k] = existing + "," + v
			continue
		}
		criticalOptions[k] = v
	}
	return criticalOptions, extensions
}
