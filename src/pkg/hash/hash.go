package hash

import (
	"errors"

	"github.com/madpo/go-gost-crypto/pkg/common"
)

func takeHashMethod(cryptoProvider *C.HCRYPTPROV, hashType HashType) (*C.HCRYPTHASH, error) {
	var hashMethod C.HCRYPTHASH

	result := C.CryptCreateHash(*cryptoProvider, C.uint(hashType), 0, 0, &hashMethod)

	if result == common.Failure {
		// [ ] TODO: добавить обработку всех ошибок https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptcreatehash#return-value
		return nil, errors.New("Не удается получить метод кэширования")
	}

	return &hashMethod, nil
}

func ReleaseHashMethod(hashMethod *C.HCRYPTHASH) {
	if hashMethod == nil {
		return
	}

	result := C.CryptDestroyHash(*hashMethod)

	if result == Failure {
		// обработать все возможные ошибки https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdestroyhash#return-value
		panic("Ошибка освобождения хэш метода")
	}
}

type HSize C.ulong

var (
	Size256 HSize = 32
	Size512 HSize = 64
)

func ReadHashValue(hashMethod *C.HCRYPTHASH, size HSize) (*[]byte, error) {
	cbToBeSigned := make([]byte, size)

	result := C.CryptGetHashParam(*hashMethod, C.HP_HASHVAL, (*C.uchar)(&cbToBeSigned[0]), (*C.ulong)(&size), 0)

	// [ ] TODO: обработать возможные ошибки https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgethashparam#return-value
	if result == Failure {
		return nil, errors.New("Не удалось получить значение хэша")
	}
	return &cbToBeSigned, nil
}

func CalculateHashGOST3411_2012_256(cryptoProvider *C.HCRYPTPROV, data []byte) (*[]byte, error) {
	hashMethod, error := TakeHashMethod(cryptoProvider, GOST3411_2012_256)

	if error != nil {
		return nil, error
	}

	defer ReleaseHashMethod(hashMethod)

	result := C.CryptHashData(*hashMethod, (*C.uchar)(&data[0]), (C.ulong)(len(data)), 0)

	// [ ] TODO: обработать варианты ошибок https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-crypthashdata#return-value
	if result == Failure {
		return nil, errors.New("Не удалось сформировать данные для хэширования")
	}

	cbToBeSigned, error := ReadHashValue(hashMethod, Size256)

	if error != nil {
		return nil, error
	}

	return cbToBeSigned, nil
}
