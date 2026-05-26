package intel

import (
	"strconv"
	"strings"
	"unicode"
)

// IsExactPEP440 reports whether raw parses as a single PEP 440 version
// (no range operators, no wildcards). Used by package-manager parsers
// that need to decide whether a manifest version string is an exact
// pin or a constraint expression. One canonical implementation —
// callers must not re-derive their own predicate.
func IsExactPEP440(raw string) bool {
	_, ok := parsePEP440Version(raw)
	return ok
}

type pep440Version struct {
	epoch   int
	release []int
	pre     pep440Pre
	post    *int
	dev     *int
	local   string
}

type pep440Pre struct {
	kind string
	num  int
}

func parsePEP440Version(raw string) (pep440Version, bool) {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" {
		return pep440Version{}, false
	}
	s = strings.TrimPrefix(s, "v")
	s = strings.ReplaceAll(s, "_", ".")
	s = strings.ReplaceAll(s, "-", ".")

	var v pep440Version
	if bang := strings.IndexByte(s, '!'); bang >= 0 {
		epoch, ok := parsePEP440Int(s[:bang])
		if !ok {
			return pep440Version{}, false
		}
		v.epoch = epoch
		s = s[bang+1:]
	}

	if plus := strings.IndexByte(s, '+'); plus >= 0 {
		local := s[plus+1:]
		if local == "" || !validPEP440Local(local) {
			return pep440Version{}, false
		}
		v.local = local
		s = s[:plus]
	}

	release, rest, ok := parsePEP440Release(s)
	if !ok {
		return pep440Version{}, false
	}
	v.release = release

	for rest != "" {
		if strings.HasPrefix(rest, ".") {
			rest = rest[1:]
			if rest == "" {
				return pep440Version{}, false
			}
		}
		switch {
		case hasPEP440PrePrefix(rest):
			if v.pre.kind != "" {
				return pep440Version{}, false
			}
			pre, next, ok := parsePEP440Pre(rest)
			if !ok {
				return pep440Version{}, false
			}
			v.pre = pre
			rest = next
		case strings.HasPrefix(rest, "post") || strings.HasPrefix(rest, "rev") || strings.HasPrefix(rest, "r"):
			if v.post != nil {
				return pep440Version{}, false
			}
			n, next, ok := parsePEP440SuffixNumber(rest, []string{"post", "rev", "r"}, 0)
			if !ok {
				return pep440Version{}, false
			}
			v.post = &n
			rest = next
		case strings.HasPrefix(rest, "dev"):
			if v.dev != nil {
				return pep440Version{}, false
			}
			n, next, ok := parsePEP440SuffixNumber(rest, []string{"dev"}, 0)
			if !ok {
				return pep440Version{}, false
			}
			v.dev = &n
			rest = next
		default:
			return pep440Version{}, false
		}
	}
	return v, true
}

func parsePEP440Release(s string) ([]int, string, bool) {
	var release []int
	idx := 0
	for idx < len(s) {
		start := idx
		for idx < len(s) && isASCIIDigit(s[idx]) {
			idx++
		}
		if start == idx {
			break
		}
		n, ok := parsePEP440Int(s[start:idx])
		if !ok {
			return nil, "", false
		}
		release = append(release, n)
		if idx >= len(s) || s[idx] != '.' {
			break
		}
		if idx+1 >= len(s) || !isASCIIDigit(s[idx+1]) {
			break
		}
		idx++
	}
	if len(release) == 0 {
		return nil, "", false
	}
	return release, s[idx:], true
}

func hasPEP440PrePrefix(s string) bool {
	for _, p := range []string{"alpha", "beta", "preview", "pre", "a", "b", "c", "rc"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func parsePEP440Pre(s string) (pep440Pre, string, bool) {
	for _, p := range []string{"alpha", "beta", "preview", "pre", "rc", "a", "b", "c"} {
		if !strings.HasPrefix(s, p) {
			continue
		}
		kind := p
		switch p {
		case "alpha":
			kind = "a"
		case "beta":
			kind = "b"
		case "preview", "pre", "c":
			kind = "rc"
		}
		n, rest, ok := parsePEP440SuffixNumber(s, []string{p}, 0)
		if !ok {
			return pep440Pre{}, "", false
		}
		return pep440Pre{kind: kind, num: n}, rest, true
	}
	return pep440Pre{}, "", false
}

func parsePEP440SuffixNumber(s string, prefixes []string, defaultNum int) (int, string, bool) {
	for _, p := range prefixes {
		if !strings.HasPrefix(s, p) {
			continue
		}
		rest := s[len(p):]
		if strings.HasPrefix(rest, ".") {
			rest = rest[1:]
		}
		start := 0
		for start < len(rest) && isASCIIDigit(rest[start]) {
			start++
		}
		if start == 0 {
			return defaultNum, rest, true
		}
		n, ok := parsePEP440Int(rest[:start])
		if !ok {
			return 0, "", false
		}
		return n, rest[start:], true
	}
	return 0, "", false
}

func parsePEP440Int(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

func validPEP440Local(s string) bool {
	for _, r := range s {
		if r == '.' || r == '-' || r == '_' || unicode.IsDigit(r) || (r >= 'a' && r <= 'z') {
			continue
		}
		return false
	}
	return true
}

func comparePEP440(a, b pep440Version) int {
	if c := cmpInt(a.epoch, b.epoch); c != 0 {
		return c
	}
	if c := compareIntSlicesZeroPadded(a.release, b.release); c != 0 {
		return c
	}
	if c := comparePEP440Stage(a, b); c != 0 {
		return c
	}
	return comparePEP440Local(a.local, b.local)
}

func comparePEP440Stage(a, b pep440Version) int {
	as := pep440StageOf(a)
	bs := pep440StageOf(b)
	if c := cmpInt(as.category, bs.category); c != 0 {
		return c
	}
	if c := cmpInt(as.preKind, bs.preKind); c != 0 {
		return c
	}
	if c := cmpInt(as.preNum, bs.preNum); c != 0 {
		return c
	}
	if c := cmpInt(as.postNum, bs.postNum); c != 0 {
		return c
	}
	if as.hasDev != bs.hasDev {
		if as.hasDev {
			return -1
		}
		return 1
	}
	if as.hasDev {
		return cmpInt(as.devNum, bs.devNum)
	}
	return 0
}

type pep440Stage struct {
	category int
	preKind  int
	preNum   int
	postNum  int
	hasDev   bool
	devNum   int
}

func pep440StageOf(v pep440Version) pep440Stage {
	stage := pep440Stage{category: 2}
	if v.dev != nil {
		stage.hasDev = true
		stage.devNum = *v.dev
	}
	if v.pre.kind != "" {
		stage.category = 1
		stage.preKind = map[string]int{"a": 1, "b": 2, "rc": 3}[v.pre.kind]
		stage.preNum = v.pre.num
		return stage
	}
	if v.post != nil {
		stage.category = 3
		stage.postNum = *v.post
		return stage
	}
	if v.dev != nil {
		stage.category = 0
	}
	return stage
}

func compareIntSlicesZeroPadded(a, b []int) int {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	for i := 0; i < maxLen; i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if c := cmpInt(av, bv); c != 0 {
			return c
		}
	}
	return 0
}

// comparePEP440Local sorts local labels segment-by-segment per PEP 440:
// numeric segments compare numerically (so "10" > "9"), alphanumeric
// segments compare lexically, and numeric segments outrank alphanumeric.
// The prior strings.Compare gave the wrong answer for multi-digit
// numeric segments (e.g. "10" < "9" lexicographically).
func comparePEP440Local(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return -1
	}
	if b == "" {
		return 1
	}
	aSeg := strings.FieldsFunc(a, func(r rune) bool { return r == '.' })
	bSeg := strings.FieldsFunc(b, func(r rune) bool { return r == '.' })
	for i := 0; i < len(aSeg) && i < len(bSeg); i++ {
		ai, aErr := strconv.Atoi(aSeg[i])
		bi, bErr := strconv.Atoi(bSeg[i])
		aIsNum := aErr == nil
		bIsNum := bErr == nil
		switch {
		case aIsNum && bIsNum:
			if c := cmpInt(ai, bi); c != 0 {
				return c
			}
		case aIsNum && !bIsNum:
			return 1
		case !aIsNum && bIsNum:
			return -1
		default:
			if c := strings.Compare(aSeg[i], bSeg[i]); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(aSeg), len(bSeg))
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func isASCIIDigit(b byte) bool {
	return b >= '0' && b <= '9'
}
