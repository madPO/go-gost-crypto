module github.com/madpo/go-gost-crypto

go 1.20

require github.com/madpo/go-gost-crypto/pkg/wrapper v1.0.0
replace github.com/madpo/go-gost-crypto/pkg/wrapper => ./pkg/wrapper

require github.com/madpo/go-gost-crypto/pkg/cryptography v1.0.0
replace github.com/madpo/go-gost-crypto/pkg/cryptography => ./pkg/cryptography