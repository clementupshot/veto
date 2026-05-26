package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"
)

const (
	shellMarkerStart = "# >>> veto shell integration (managed) >>>"
	shellMarkerEnd   = "# <<< veto shell integration (managed) <<<"
)

type shellOpts struct {
	shellRC string
	autoRC  bool
	print   bool
}

type shellRCTarget struct {
	path string
	kind shellKind
}

// runInstallShell writes veto's shell-level integration block: PATH pinning
// plus package-age quarantine wrappers for package managers whose native
// rolling age gates are unavailable or awkward to configure globally.
func runInstallShell(logger zerolog.Logger, args []string) int {
	opts, err := parseShellFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto install-shell: %v\n", err)
		return exitUsage
	}

	shimDir, err := defaultShellShimDir()
	if err != nil {
		logger.Error().Err(err).Msg("resolve shim dir")
		return exitInternal
	}
	vetoPath, err := resolveVetoBinary()
	if err != nil {
		logger.Error().Err(err).Msg("locate veto binary")
		return exitInternal
	}

	if opts.print {
		kind, err := shellKindForOptions(opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "veto install-shell: %v\n", err)
			return exitUsage
		}
		block := renderShellIntegrationBlock(shimDir, vetoPath, kind)
		fmt.Print(block)
		return exitOK
	}

	targets, err := shellIntegrationTargets(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto install-shell: %v\n", err)
		fmt.Fprintln(os.Stderr, "Pass --shell-rc PATH explicitly, or use --print to dump the managed block.")
		return exitUsage
	}

	for _, target := range targets {
		block := renderShellIntegrationBlock(shimDir, vetoPath, target.kind)
		if err := upsertShellIntegrationBlock(target.path, block); err != nil {
			logger.Error().Err(err).Str("rc", target.path).Msg("update shell integration")
			return exitInternal
		}
		fmt.Printf("veto: wrote shell integration block to %s\n", target.path)
	}
	fmt.Println("         Open a new terminal (or source your shell rc), then run `veto doctor`.")
	return exitOK
}

// runUninstallShell removes veto's shell-level integration block.
func runUninstallShell(logger zerolog.Logger, args []string) int {
	opts, err := parseShellFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto uninstall-shell: %v\n", err)
		return exitUsage
	}

	targets, err := shellIntegrationTargets(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto uninstall-shell: %v\n", err)
		return exitUsage
	}
	for _, target := range targets {
		if removed, err := removeShellIntegrationBlock(target.path); err != nil {
			logger.Error().Err(err).Str("rc", target.path).Msg("remove shell integration")
			return exitInternal
		} else if removed {
			fmt.Printf("veto: removed shell integration block from %s\n", target.path)
		} else {
			fmt.Printf("veto: no managed shell integration block found in %s\n", target.path)
		}
	}
	return exitOK
}

func parseShellFlags(args []string) (shellOpts, error) {
	opts := shellOpts{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--shell-rc":
			if i+1 >= len(args) {
				return opts, errors.New("--shell-rc requires a path argument (or 'auto')")
			}
			v := args[i+1]
			if v == "auto" {
				opts.autoRC = true
			} else {
				opts.shellRC = v
			}
			i++
		case strings.HasPrefix(a, "--shell-rc="):
			v := strings.TrimPrefix(a, "--shell-rc=")
			if v == "auto" {
				opts.autoRC = true
			} else {
				opts.shellRC = v
			}
		case a == "--print":
			opts.print = true
		default:
			return opts, errors.WithNew("unknown argument").Set("arg", a)
		}
	}
	return opts, nil
}

func shellKindForOptions(opts shellOpts) (shellKind, error) {
	if opts.shellRC != "" {
		return shellKindForRC(opts.shellRC), nil
	}
	if rcPath, err := autoDetectShellRC(); err == nil {
		return shellKindForRC(rcPath), nil
	}
	if bashDetected() {
		return shellKindBash, nil
	}
	return "", errors.New("could not detect shell rc from $SHELL and bash was not found")
}

func shellIntegrationTargets(opts shellOpts) ([]shellRCTarget, error) {
	if opts.shellRC != "" {
		return []shellRCTarget{{path: opts.shellRC, kind: shellKindForRC(opts.shellRC)}}, nil
	}
	return defaultShellIntegrationTargets()
}

func defaultShellIntegrationTargets() ([]shellRCTarget, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, errors.With(err, "resolve home")
	}

	var targets []shellRCTarget
	seen := map[string]struct{}{}
	if rcPath, err := autoDetectShellRC(); err == nil {
		targets = appendShellRCTarget(targets, seen, rcPath, shellKindForRC(rcPath))
	}

	if bashDetected() {
		targets = appendShellRCTarget(targets, seen, filepath.Join(home, ".bashrc"), shellKindBash)
		targets = appendShellRCTarget(targets, seen, filepath.Join(home, ".bash_profile"), shellKindBash)
		targets = appendShellRCTarget(targets, seen, filepath.Join(home, ".profile"), shellKindProfile)
	}

	if len(targets) == 0 {
		return nil, errors.New("could not detect shell rc from $SHELL and bash was not found")
	}
	return targets, nil
}

func appendShellRCTarget(targets []shellRCTarget, seen map[string]struct{}, path string, kind shellKind) []shellRCTarget {
	key := filepath.Clean(path)
	if _, ok := seen[key]; ok {
		return targets
	}
	seen[key] = struct{}{}
	return append(targets, shellRCTarget{path: path, kind: kind})
}

func bashDetected() bool {
	if path, err := exec.LookPath("bash"); err == nil && executableFile(path) {
		return true
	}
	for _, path := range []string{"/bin/bash", "/usr/bin/bash", "/usr/local/bin/bash", "/opt/homebrew/bin/bash"} {
		if executableFile(path) {
			return true
		}
	}
	return false
}

func executableFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

func defaultShellShimDir() (string, error) {
	dir := defaultShimDir()
	if dir == "" {
		return "", errors.New("shim dir resolved empty")
	}
	return filepath.Abs(dir)
}

type shellKind string

const (
	shellKindZsh     shellKind = "zsh"
	shellKindBash    shellKind = "bash"
	shellKindProfile shellKind = "profile"
	shellKindFish    shellKind = "fish"
)

func shellKindForRC(rcPath string) shellKind {
	slashPath := filepath.ToSlash(rcPath)
	if strings.HasSuffix(rcPath, ".fish") || strings.HasSuffix(slashPath, "/config.fish") || strings.Contains(slashPath, "/fish/") {
		return shellKindFish
	}
	base := filepath.Base(rcPath)
	switch base {
	case ".zshrc", ".zprofile":
		return shellKindZsh
	case ".bashrc", ".bash_profile", ".bash_login":
		return shellKindBash
	case ".profile":
		return shellKindProfile
	default:
		return shellKindBash
	}
}

func renderShellIntegrationBlock(shimDir, vetoPath string, kind shellKind) string {
	switch kind {
	case shellKindFish:
		return renderFishShellIntegrationBlock(shimDir, vetoPath)
	case shellKindProfile:
		return renderProfileShellIntegrationBlock(shimDir, vetoPath)
	case shellKindZsh:
		return renderZshShellIntegrationBlock(shimDir, vetoPath)
	default:
		return renderBashShellIntegrationBlock(shimDir, vetoPath)
	}
}

func renderZshShellIntegrationBlock(shimDir, vetoPath string) string {
	var b strings.Builder
	writeShellBlockHeader(&b, shimDir, vetoPath)
	writeFastPinPathFunction(&b)
	b.WriteString("if [ -n \"${ZSH_VERSION:-}\" ]; then\n")
	b.WriteString("  typeset -U path PATH\n")
	b.WriteString("  case \" ${precmd_functions[*]} \" in\n")
	b.WriteString("    *\" _veto_pin_path \"*) ;;\n")
	b.WriteString("    *) precmd_functions+=(_veto_pin_path) ;;\n")
	b.WriteString("  esac\n")
	b.WriteString("fi\n")
	b.WriteString("_veto_pin_path\n")
	writePackageAgeFunctions(&b)
	b.WriteString(shellMarkerEnd + "\n")
	return b.String()
}

func renderBashShellIntegrationBlock(shimDir, vetoPath string) string {
	var b strings.Builder
	writeShellBlockHeader(&b, shimDir, vetoPath)
	writeFastPinPathFunction(&b)
	b.WriteString("if [ -n \"${BASH_VERSION:-}\" ]; then\n")
	b.WriteString("  case \";${PROMPT_COMMAND:-};\" in\n")
	b.WriteString("    *\";_veto_pin_path;\"*) ;;\n")
	b.WriteString("    *) PROMPT_COMMAND=\"_veto_pin_path${PROMPT_COMMAND:+;$PROMPT_COMMAND}\" ;;\n")
	b.WriteString("  esac\n")
	b.WriteString("fi\n")
	b.WriteString("_veto_pin_path\n")
	writePackageAgeFunctions(&b)
	b.WriteString(shellMarkerEnd + "\n")
	return b.String()
}

func renderProfileShellIntegrationBlock(shimDir, vetoPath string) string {
	var b strings.Builder
	writeShellBlockHeader(&b, shimDir, vetoPath)
	writePortablePinPathFunction(&b)
	b.WriteString("if [ -n \"${BASH_VERSION:-}\" ]; then\n")
	b.WriteString("  case \";${PROMPT_COMMAND:-};\" in\n")
	b.WriteString("    *\";_veto_pin_path;\"*) ;;\n")
	b.WriteString("    *) PROMPT_COMMAND=\"_veto_pin_path${PROMPT_COMMAND:+;$PROMPT_COMMAND}\" ;;\n")
	b.WriteString("  esac\n")
	b.WriteString("fi\n")
	b.WriteString("_veto_pin_path\n")
	writePackageAgeFunctions(&b)
	b.WriteString(shellMarkerEnd + "\n")
	return b.String()
}

func writeShellBlockHeader(b *strings.Builder, shimDir, vetoPath string) {
	b.WriteString(shellMarkerStart + "\n")
	b.WriteString("# Keep veto's PATH shims ahead of mise/asdf/pyenv/nvm/bun/pnpm dirs.\n")
	b.WriteString("# Use the veto binary directly in package-age wrappers so they work before\n")
	b.WriteString("# shims are installed and do not recurse through shell functions.\n")
	b.WriteString("# This block is intentionally safe to source repeatedly.\n")
	fmt.Fprintf(b, "_veto_shim_dir=%s\n", shellWord(shimDir))
	fmt.Fprintf(b, "_veto_bin=%s\n", shellWord(vetoPath))
	b.WriteString("export PATH=\"$_veto_shim_dir:$PATH\"\n")
}

func writeFastPinPathFunction(b *strings.Builder) {
	b.WriteString("_veto_pin_path() {\n")
	b.WriteString("  case \":$PATH:\" in \":$_veto_shim_dir:\"*) ;; *) PATH=\"$_veto_shim_dir:${PATH//$_veto_shim_dir:/}\" ;; esac\n")
	b.WriteString("}\n")
}

func writePortablePinPathFunction(b *strings.Builder) {
	b.WriteString("_veto_pin_path() {\n")
	b.WriteString("  _veto_new_path=$_veto_shim_dir\n")
	b.WriteString("  _veto_old_ifs=$IFS\n")
	b.WriteString("  IFS=:\n")
	b.WriteString("  for _veto_path_part in $PATH; do\n")
	b.WriteString("    if [ -n \"$_veto_path_part\" ] && [ \"$_veto_path_part\" != \"$_veto_shim_dir\" ]; then\n")
	b.WriteString("      _veto_new_path=\"$_veto_new_path:$_veto_path_part\"\n")
	b.WriteString("    fi\n")
	b.WriteString("  done\n")
	b.WriteString("  IFS=$_veto_old_ifs\n")
	b.WriteString("  PATH=$_veto_new_path\n")
	b.WriteString("  export PATH\n")
	b.WriteString("  unset _veto_new_path _veto_old_ifs _veto_path_part\n")
	b.WriteString("}\n")
}

func writePackageAgeFunctions(b *strings.Builder) {
	b.WriteString("_veto_pkg_age_cutoff_3d_utc() {\n")
	if runtime.GOOS == "darwin" {
		b.WriteString("  date -u -v-3d +%Y-%m-%dT%H:%M:%SZ\n")
	} else {
		b.WriteString("  date -u -d '3 days ago' +%Y-%m-%dT%H:%M:%SZ\n")
	}
	b.WriteString("}\n")
	// User-set PIP_UPLOADED_PRIOR_TO / UV_EXCLUDE_NEWER win over the
	// 3-day default — the wrapper only supplies a cutoff when the
	// caller did not. Avoids silently clobbering CI / .envrc overrides.
	b.WriteString("pip() { PIP_UPLOADED_PRIOR_TO=\"${PIP_UPLOADED_PRIOR_TO:-$(_veto_pkg_age_cutoff_3d_utc)}\" \"$_veto_bin\" pip \"$@\"; }\n")
	b.WriteString("pip3() { PIP_UPLOADED_PRIOR_TO=\"${PIP_UPLOADED_PRIOR_TO:-$(_veto_pkg_age_cutoff_3d_utc)}\" \"$_veto_bin\" pip3 \"$@\"; }\n")
	b.WriteString("uv() { UV_EXCLUDE_NEWER=\"${UV_EXCLUDE_NEWER:-$(_veto_pkg_age_cutoff_3d_utc)}\" \"$_veto_bin\" uv \"$@\"; }\n")
	b.WriteString("uvx() { UV_EXCLUDE_NEWER=\"${UV_EXCLUDE_NEWER:-$(_veto_pkg_age_cutoff_3d_utc)}\" \"$_veto_bin\" uvx \"$@\"; }\n")
}

func renderFishShellIntegrationBlock(shimDir, vetoPath string) string {
	var b strings.Builder
	b.WriteString(shellMarkerStart + "\n")
	b.WriteString("# Keep veto's PATH shims ahead of mise/asdf/pyenv/nvm/bun/pnpm dirs.\n")
	fmt.Fprintf(&b, "fish_add_path --move --prepend %q\n", shimDir)
	fmt.Fprintf(&b, "set -gx _veto_bin %q\n", vetoPath)
	b.WriteString("function _veto_pin_path --on-event fish_prompt\n")
	fmt.Fprintf(&b, "  fish_add_path --move --prepend %q\n", shimDir)
	b.WriteString("end\n")
	b.WriteString("function _veto_pkg_age_cutoff_3d_utc\n")
	if runtime.GOOS == "darwin" {
		b.WriteString("  date -u -v-3d +%Y-%m-%dT%H:%M:%SZ\n")
	} else {
		b.WriteString("  date -u -d '3 days ago' +%Y-%m-%dT%H:%M:%SZ\n")
	}
	b.WriteString("end\n")
	// Fish: `set -q` tests whether the var is already set. Mirrors the
	// bash/zsh ${VAR:-default} pattern — user-set values win.
	b.WriteString("function pip\n  set -q PIP_UPLOADED_PRIOR_TO; or set -gx PIP_UPLOADED_PRIOR_TO (_veto_pkg_age_cutoff_3d_utc)\n  $_veto_bin pip $argv\nend\n")
	b.WriteString("function pip3\n  set -q PIP_UPLOADED_PRIOR_TO; or set -gx PIP_UPLOADED_PRIOR_TO (_veto_pkg_age_cutoff_3d_utc)\n  $_veto_bin pip3 $argv\nend\n")
	b.WriteString("function uv\n  set -q UV_EXCLUDE_NEWER; or set -gx UV_EXCLUDE_NEWER (_veto_pkg_age_cutoff_3d_utc)\n  $_veto_bin uv $argv\nend\n")
	b.WriteString("function uvx\n  set -q UV_EXCLUDE_NEWER; or set -gx UV_EXCLUDE_NEWER (_veto_pkg_age_cutoff_3d_utc)\n  $_veto_bin uvx $argv\nend\n")
	b.WriteString(shellMarkerEnd + "\n")
	return b.String()
}

func upsertShellIntegrationBlock(rcPath, block string) error {
	existing, err := os.ReadFile(rcPath)
	if err != nil && !os.IsNotExist(err) {
		return errors.With(err, "read rc")
	}
	rewritten := upsertManagedBlockWithMarkers(string(existing), block, shellMarkerStart, shellMarkerEnd)
	return atomicWrite(rcPath, []byte(rewritten), 0o644)
}

func removeShellIntegrationBlock(rcPath string) (bool, error) {
	return removeShellRCBlockWithMarkers(rcPath, shellMarkerStart, shellMarkerEnd)
}

func printShellBlockHint(w io.Writer) {
	fmt.Fprintln(w, "Run `veto install-shell` to install the managed PATH pinning + age-quarantine block.")
}

func shellWord(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
