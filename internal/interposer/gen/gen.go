// Package gen hosts the go:generate directive and the consistency
// test for the C interposer's PM-name header. It lives one directory
// down from veto_interpose.c so that internal/interposer/ itself
// stays Go-free — a Go package cannot mix .go and .c files without
// using cgo, and we do not want cgo in this tree (the C library is
// built standalone by the Makefile and loaded via
// DYLD_INSERT_LIBRARIES / LD_PRELOAD at runtime).
//
// The generator emits ../pm_names.h, which veto_interpose.c #includes.
// `go generate ./internal/interposer/gen/...` and the corresponding
// Makefile recipe both write to that absolute path.
package gen

//go:generate go run ../cmd/genpmlist -o ../pm_names.h
