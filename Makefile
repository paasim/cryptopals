SETS := set1 set2 set3 set4 setx
EXAMPLES := $(patsubst set%, example%, $(SETS))
FLAMEGRAPHS := $(patsubst set%, flamefraph%, $(SETS))

.PHONY: $(SETS)

echo:
	@echo make test: run tests
	@echo make setx: get ouput for set x
	@echo make flamegraph2: make flamegraph set3

test:
	cargo test -r

example%: set%
	cargo run -r --example $?

flamegraph%: set%
	CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --example $? --deterministic
