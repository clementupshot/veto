package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"
)

type installAllOpts struct {
	libPath      string
	shellRC      string
	autoRC       bool
	force        bool
	skipInterpos bool
}

// runInstallAll installs every veto protection layer in one guided command.
func runInstallAll(logger zerolog.Logger, cfg config, args []string) int {
	opts, err := parseInstallAllFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto install-all: %v\n", err)
		return exitUsage
	}
	if opts.shellRC == "" && !opts.autoRC {
		opts.autoRC = true
	}

	var libPath string
	if !opts.skipInterpos {
		libPath, err = ensureInterposerArtifact(logger, opts.libPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "veto install-all: %v\n", err)
			fmt.Fprintln(os.Stderr, "Run from the veto repo so `make interposer` can build the library, pass `--lib /path/to/libveto_interpose.*`, or use `--skip-interposer`.")
			return exitUsage
		}
	}

	steps := []struct {
		name string
		run  func() int
	}{
		{name: "install shims", run: func() int {
			shimArgs := []string{}
			if opts.force {
				shimArgs = append(shimArgs, "--force")
			}
			return runInstallShims(logger, shimArgs)
		}},
		{name: "install shell integration", run: func() int {
			return runInstallShell(logger, shellRCArgs(opts))
		}},
		{name: "install Claude Code hook", run: func() int {
			return runInstallClaudeHook(logger, nil)
		}},
	}
	if !opts.skipInterpos {
		steps = append(steps, struct {
			name string
			run  func() int
		}{name: "install preload interposer", run: func() int {
			preloadArgs := append([]string{"--lib", libPath}, shellRCArgs(opts)...)
			return runInstallPreload(logger, preloadArgs)
		}})
	}
	steps = append(steps, []struct {
		name string
		run  func() int
	}{
		{name: "install real-binary wrappers", run: func() int {
			wrapperArgs := []string{}
			if opts.force {
				wrapperArgs = append(wrapperArgs, "--force")
			}
			return runInstallWrappers(logger, cfg, wrapperArgs)
		}},
		{name: "sync intel", run: func() int {
			return runSync(logger, cfg)
		}},
		{name: "doctor", run: func() int {
			prepareInstallAllDoctorEnv(logger, opts)
			return runDoctor(logger, cfg, nil)
		}},
	}...)

	for _, step := range steps {
		fmt.Printf("\n==> veto: %s\n", step.name)
		if rc := step.run(); rc != exitOK {
			fmt.Fprintf(os.Stderr, "veto install-all: step failed: %s\n", step.name)
			return rc
		}
	}
	return exitOK
}

func parseInstallAllFlags(args []string) (installAllOpts, error) {
	opts := installAllOpts{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--lib":
			if i+1 >= len(args) {
				return opts, errors.New("--lib requires a path argument")
			}
			opts.libPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--lib="):
			opts.libPath = strings.TrimPrefix(a, "--lib=")
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
		case a == "--force":
			opts.force = true
		case a == "--skip-interposer":
			opts.skipInterpos = true
		default:
			return opts, errors.WithNew("unknown argument").Set("arg", a)
		}
	}
	return opts, nil
}

func ensureInterposerArtifact(logger zerolog.Logger, explicit string) (string, error) {
	path, err := findInterposerArtifact(explicit)
	if err == nil || explicit != "" {
		return path, err
	}

	if !repoMakefileExists() {
		return "", err
	}
	fmt.Println("veto: interposer artifact not found; building it with `make interposer`...")
	cmd := exec.Command("make", "interposer")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if runErr := cmd.Run(); runErr != nil {
		logger.Error().Err(runErr).Msg("build interposer")
		return "", errors.With(runErr, "make interposer")
	}
	return findInterposerArtifact("")
}

func repoMakefileExists() bool {
	info, err := os.Stat("Makefile")
	return err == nil && !info.IsDir()
}

func shellRCArgs(opts installAllOpts) []string {
	if opts.shellRC != "" {
		return []string{"--shell-rc", opts.shellRC}
	}
	if opts.autoRC {
		return []string{"--shell-rc", "auto"}
	}
	return nil
}

func prepareInstallAllDoctorEnv(logger zerolog.Logger, opts installAllOpts) {
	shimDir, err := defaultShellShimDir()
	if err != nil {
		logger.Warn().Err(err).Msg("resolve shim dir for install-all doctor")
	} else {
		_ = os.Setenv("PATH", pinPathEnv(os.Getenv("PATH"), shimDir))
	}

	if opts.skipInterpos {
		return
	}
	installedLib := installedInterposerPath("")
	if _, err := os.Stat(installedLib); err != nil {
		logger.Warn().Err(err).Str("path", installedLib).Msg("stat installed interposer for install-all doctor")
		return
	}
	envVar := "DYLD_INSERT_LIBRARIES"
	if runtime.GOOS != "darwin" {
		envVar = "LD_PRELOAD"
	}
	_ = os.Setenv(envVar, installedLib)
	if vetoPath, err := resolveVetoBinary(); err != nil {
		logger.Warn().Err(err).Msg("resolve veto binary for install-all doctor")
	} else {
		_ = os.Setenv("VETO_PATH", vetoPath)
	}
}

func pinPathEnv(pathEnv, shimDir string) string {
	parts := filepath.SplitList(pathEnv)
	out := []string{shimDir}
	for _, p := range parts {
		if p != "" && absEqual(p, shimDir) {
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, string(os.PathListSeparator))
}

func findInterposerArtifact(explicit string) (string, error) {
	if explicit != "" {
		if err := assertInterposerArtifact(explicit); err != nil {
			return "", err
		}
		return explicit, nil
	}

	name := "libveto_interpose.dylib"
	if runtime.GOOS != "darwin" {
		name = "libveto_interpose.so"
	}

	var candidates []string
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, name))
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), name))
	}
	candidates = append(candidates, installedInterposerPath(""))

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			if err := assertInterposerArtifact(c); err != nil {
				return "", err
			}
			return c, nil
		}
	}
	return "", errors.WithNew("interposer artifact not found").Set("searched", candidates)
}
