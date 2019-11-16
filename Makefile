GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=iso-strict --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v1.0.0)

# KWT
# Pass the '-w' flag to the linker to omit the debug information (for example, go build -ldflags=-w prog.go).
# see https://golang.org/doc/gdb
tpmprovider:
	go test -c -o out/tpmprovider.test -gcflags=all="-N -l" -tags=unit_test

all: tpmprovider

clean:
	rm -f cover.*
	rm -rf out/
	rm -rf builds/