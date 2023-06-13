package cryptography

import (
	"github.com/madpo/go-gost-crypto/pkg/wrapper"
)

// Фабрика провайдеров криптографии
func CreateCSP(cspType wrapper.CSPType) (release func(), createHashMethod func(wrapper.HashType) (*wrapper.CryptoHash, error), exception error) {
	cryptoProvider, exception := wrapper.TakeCSP(cspType)

	if exception != nil {
		return nil, nil, exception
	}

	createHashMethod = func (hashType wrapper.HashType) (*wrapper.CryptoHash, error) {
		cryptoHash, exception := wrapper.TakeHashMethod(cryptoProvider, hashType)

		if exception != nil {
			return nil, exception
		}

		return cryptoHash, nil
	}

	release = func() {
		wrapper.ReleaseCSP(cryptoProvider)
	}

	return release, createHashMethod, nil
}

func CreateGOST3411HashMethod() (release func(), calculateHash func(*[]byte) (*[]byte, error), exception error) {
	releaseCSP, createHashMethod, exception := CreateCSP(wrapper.GOST2012_512)

	if exception != nil {
		return nil, nil, exception
	}

	hashMethod, exception := createHashMethod(wrapper.GOST3411)

	if exception != nil {
		return nil, nil, exception
	}

	return 
}