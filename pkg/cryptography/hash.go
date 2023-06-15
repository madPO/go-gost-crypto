package cryptography

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"io"

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
func CreateHashMethod(hashType wrapper.HashType) (release func(), calculateHash func(io.Reader) (io.Reader, error), exception error) {
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
func CreateGOST3411HashMethod() (release func(), calculateHash func(io.Reader) (io.Reader, error), exception error) {
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
		}, func(reader io.Reader) (io.Reader, error) {
			buffer := make([]byte, 256)
			count, error := reader.Read(buffer)

			for error == nil {
				value := buffer[:count]
				error = wrapper.ApplyHash(hashMethod, &value)

				if error != nil {
					return nil, error
				}

				count, error = reader.Read(buffer)
			}

			result, error := wrapper.CalculateHashValue(hashMethod, wrapper.Size256)

			if error != nil {
				return nil, error
			}

			return bytes.NewReader(*result), nil
		}, nil
}

// получить метод вычисления хэша по ГОСТ 3411-2012-256
func CreateGOST3411_2012_256HashMethod() (release func(), calculateHash func(io.Reader) (io.Reader, error), exception error) {
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
		}, func(reader io.Reader) (io.Reader, error) {
			buffer := make([]byte, 256)
			count, error := reader.Read(buffer)

			for error == nil {
				value := buffer[:count]
				error = wrapper.ApplyHash(hashMethod, &value)

				if error != nil {
					return nil, error
				}

				count, error = reader.Read(buffer)
			}

			result, error := wrapper.CalculateHashValue(hashMethod, wrapper.Size256)

			if error != nil {
				return nil, error
			}

			return bytes.NewReader(*result), nil
		}, nil
}

// получить метод вычисления хэша по ГОСТ 3411-2012-512
func CreateGOST3411_2012_512HashMethod() (release func(), calculateHash func(io.Reader) (io.Reader, error), exception error) {
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
		}, func(reader io.Reader) (io.Reader, error) {
			buffer := make([]byte, 256)
			count, error := reader.Read(buffer)

			for error == nil {
				value := buffer[:count]
				error = wrapper.ApplyHash(hashMethod, &value)

				if error != nil {
					return nil, error
				}

				count, error = reader.Read(buffer)
			}

			result, error := wrapper.CalculateHashValue(hashMethod, wrapper.Size512)

			if error != nil {
				return nil, error
			}

			return bytes.NewReader(*result), nil
		}, nil
}

func CreateMD5HashMethod() (release func(), calculateHash func(io.Reader) (io.Reader, error), exception error) {
	return func() {},
		func(reader io.Reader) (io.Reader, error) {
			hashMethod := md5.New()

			buffer := make([]byte, 256)
			count, error := reader.Read(buffer)
			for error == nil {
				hashMethod.Write(buffer[:count])

				count, error = reader.Read(buffer)
			}

			if error != io.EOF {
				return nil, error
			}

			result := hashMethod.Sum(nil)

			return bytes.NewReader(result), nil
		}, nil
}

func CreateSha256HashMethod() (release func(), calculateHash func(io.Reader) (io.Reader, error), exception error) {
	return func() {},
		func(reader io.Reader) (io.Reader, error) {
			hashMethod := sha256.New()

			buffer := make([]byte, 256)
			count, error := reader.Read(buffer)
			for error == nil {
				hashMethod.Write(buffer[:count])

				count, error = reader.Read(buffer)
			}

			if error != io.EOF {
				return nil, error
			}

			result := hashMethod.Sum(nil)

			return bytes.NewReader(result), nil
		}, nil
}

func CreateSha384HashMethod() (release func(), calculateHash func(io.Reader) (io.Reader, error), exception error) {
	return func() {},
		func(reader io.Reader) (io.Reader, error) {
			hashMethod := sha512.New384()

			buffer := make([]byte, 256)
			count, error := reader.Read(buffer)
			for error == nil {
				hashMethod.Write(buffer[:count])

				count, error = reader.Read(buffer)
			}

			if error != io.EOF {
				return nil, error
			}

			result := hashMethod.Sum(nil)

			return bytes.NewReader(result), nil
		}, nil
}

func CreateSha512HashMethod() (release func(), calculateHash func(io.Reader) (io.Reader, error), exception error) {
	return func() {},
		func(reader io.Reader) (io.Reader, error) {
			hashMethod := sha512.New()

			buffer := make([]byte, 256)
			count, error := reader.Read(buffer)
			for error == nil {
				hashMethod.Write(buffer[:count])

				count, error = reader.Read(buffer)
			}

			if error != io.EOF {
				return nil, error
			}

			result := hashMethod.Sum(nil)

			return bytes.NewReader(result), nil
		}, nil
}
