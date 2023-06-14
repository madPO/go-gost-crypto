package cryptography

import (
	"errors"

	"github.com/madpo/go-gost-crypto/pkg/wrapper"
)

// Фабрика провайдеров криптографии
func CreateCSP(cspType wrapper.CSPType) (release func(), createHashMethod func(wrapper.HashType) (*wrapper.CryptoHash, error), exception error) {
	cryptoProvider, exception := wrapper.TakeCSP(cspType)

	if exception != nil {
		return nil, nil, exception
	}

	createHashMethod = func(hashType wrapper.HashType) (*wrapper.CryptoHash, error) {
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

// фабрика методов хэширования
func CreateHashMethod(hashType wrapper.HashType) (release func(), calculateHash func(*[]byte) (*[]byte, error), exception error) {
	switch hashType {
	case wrapper.GOST3411:
		return CreateGOST3411HashMethod()
	case wrapper.GOST3411_2012_256:
		return CreateGOST3411_2012_256HashMethod()
	case wrapper.GOST3411_2012_512:
		return CreateGOST3411_2012_512HashMethod()
	}

	return nil, nil, errors.New("Не найден тип хэширования")
}

// получить метод вычисления хэша по ГОСТ 3411
func CreateGOST3411HashMethod() (release func(), calculateHash func(*[]byte) (*[]byte, error), exception error) {
	releaseCSP, createHashMethod, exception := CreateCSP(wrapper.GOST2012_512)

	if exception != nil {
		return nil, nil, exception
	}

	hashMethod, exception := createHashMethod(wrapper.GOST3411)

	if exception != nil {
		return nil, nil, exception
	}

	return func() {
			wrapper.ReleaseHashMethod(hashMethod)

			releaseCSP()
		}, func(data *[]byte) (*[]byte, error) {
			return wrapper.CalculateHashValue(hashMethod, wrapper.Size256, data)
		}, nil
}

// получить метод вычисления хэша по ГОСТ 3411-2012-256
func CreateGOST3411_2012_256HashMethod() (release func(), calculateHash func(*[]byte) (*[]byte, error), exception error) {
	releaseCSP, createHashMethod, exception := CreateCSP(wrapper.GOST2012_512)

	if exception != nil {
		return nil, nil, exception
	}

	hashMethod, exception := createHashMethod(wrapper.GOST3411_2012_256)

	if exception != nil {
		return nil, nil, exception
	}

	return func() {
			wrapper.ReleaseHashMethod(hashMethod)

			releaseCSP()
		}, func(data *[]byte) (*[]byte, error) {
			return wrapper.CalculateHashValue(hashMethod, wrapper.Size256, data)
		}, nil
}

// получить метод вычисления хэша по ГОСТ 3411-2012-512
func CreateGOST3411_2012_512HashMethod() (release func(), calculateHash func(*[]byte) (*[]byte, error), exception error) {
	releaseCSP, createHashMethod, exception := CreateCSP(wrapper.GOST2012_512)

	if exception != nil {
		return nil, nil, exception
	}

	hashMethod, exception := createHashMethod(wrapper.GOST3411_2012_512)

	if exception != nil {
		return nil, nil, exception
	}

	return func() {
			wrapper.ReleaseHashMethod(hashMethod)

			releaseCSP()
		}, func(data *[]byte) (*[]byte, error) {
			return wrapper.CalculateHashValue(hashMethod, wrapper.Size512, data)
		}, nil
}
