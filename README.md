# ELFbac ARM

This repository is (currently) split into two components. The modified kernel
lives in linux/, and is a git subtree tracking the main linux repository on
github.

Companion tools for working with ELFbac policies live in elfbac-tools/. The main
tool now is elfbac-ld, which is a wrapper around the GNU linker to lay out
sections properly and to link in an ELFbac policy as described by a JSON file.

A sample program exists in elfbac-tools/sample/ to see how this works.
