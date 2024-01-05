SOURCES=$(wildcard *.py)

.PHONY: all
all: fmt mypy

.PHONY: fmt
fmt: $(SOURCES)
	autopep8 -i -aa $(SOURCES)

.PHONY: mypy
mypy: $(SOURCES)
	mypy .
