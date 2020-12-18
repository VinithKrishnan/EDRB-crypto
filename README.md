# EDRB-crypto
My contributions:
* Folder ed25519 contains curve25519's definition (group, filed elements and operations on them).
* pvss.go containes essential functions for proof generation, verification etc.
* pvss_test.go contains unit tests.
Run:
 Unit tests: go test pvss.go pvss_test.go
 Benchmarks: go test -bench=. pvss.go pvss_test.go
