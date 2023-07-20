SETS := set1 set2 set3 set4 set5 set6 set8 setx
EXAMPLES := $(patsubst set%, example%, $(SETS))
FLAMEGRAPHS := $(patsubst set%, flamefraph%, $(SETS))

.PHONY: $(SETS)

echo:
	@echo make test: run tests
	@echo make examplex: get ouput for set x
	@echo make flamegraphx: make flamegraph for set x

test:
	cargo test -r

example%: set%
	cargo run -r --example $?

flamegraph%: set%
	CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --example $? --deterministic
