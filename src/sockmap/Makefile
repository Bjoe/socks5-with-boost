all: venv/.ok
	clang -Wall -Wextra -O2 -fno-stack-protector  -emit-llvm -c sockmap-kern.c -S -o - \
	| llc -march=bpf -filetype=obj -o - \
	| ./venv/bin/python3 tbpf-decode-elf.py /dev/stdin prog_parser prog_verdict > sockmap-ebpf.c

#	clang -g -Wall -Wextra -O2 \
#		tbpf.c \
#		net.c \
#		sockmap-ebpf.c \
#		sockmap.c \
#		-l elf \
#		-o sockmap

venv/.ok:
	virtualenv venv --python=python3
	./venv/bin/pip3 install pyelftools
	touch $@

.PHONY: format
format:
	clang-format -i *.c *.h
	@grep -n "TODO" *.[ch] || true
