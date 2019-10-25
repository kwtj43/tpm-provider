GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=iso-strict --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v1.0.0)

tpmprovider:
#	env GOOS=linux go build -gcflags=all="-N -l" -ldflags "-X intel/isecl/go-trust-agent/version.Version=$(VERSION) -X intel/isecl/go-trust-agent/version.GitHash=$(GITCOMMIT) -X intel/isecl/go-trust-agent/version.CommitDate=$(GITCOMMITDATE)" -o out/tagent
	go test -c -o out/tpmprovider.test -gcflags=all="-N -l"

# KWT
# Pass the '-w' flag to the linker to omit the debug information (for example, go build -ldflags=-w prog.go).
# https://golang.org/doc/gdb



#build_test: tpmprovider
#	go test -c -o ../out/tpmprovider.test

all: tpmprovider

clean:
	rm -f cover.*
	rm -rf out/
	rm -rf builds/