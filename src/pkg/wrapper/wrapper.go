package wrapper

// нужно подключить все заголовки, чтобы C код тоже сбилдился
// [ ] TODO: тут могут быть зависимые от платформы аргументы
// https://pkg.go.dev/cmd/cgo

/*
#cgo LDFLAGS: -Wl,--allow-multiple-definition
#cgo linux,amd64 CFLAGS: -I/opt/cprocsp/include/cpcsp -DUNIX -DLINUX -DSIZEOF_VOID_P=8
#cgo linux,386 CFLAGS: -I/opt/cprocsp/include/cpcsp -DUNIX -DLINUX -DSIZEOF_VOID_P=4
#cgo linux,amd64 LDFLAGS: -L/opt/cprocsp/lib/amd64/ -lcapi10 -lcapi20 -lrdrsup -lssp
#cgo linux,386 LDFLAGS: -L/opt/cprocsp/lib/ia32/ -lcapi10 -lcapi20 -lrdrsup -lssp
#cgo windows CFLAGS: -I"D:/cprosdk/include"
#cgo windows LDFLAGS: -lcrypt32 -lpthread
#include <windows.h>
#include <wincrypt.h>
#include <winerror.h>
#include <prsht.h>
#include <ades-core.h>
*/
import "C"
import (
	"errors"
)

/*
Тип CSP
*/
type CSPType int64

/*
Тип хэша
*/
type HashType uint

/*
Криптопровайдер
*/
type CryptoProvider C.HCRYPTPROV

/*
Хэш
*/
type CryptoHash C.HCRYPTHASH

/*
Размер хэша
*/
type HSize C.ulong

var (
	Size256 HSize = 32
	Size512 HSize = 64
)

const (
	GOST2001     CSPType = C.PROV_GOST_2001_DH
	GOST2012_256 CSPType = C.PROV_GOST_2012_256
	GOST2012_512 CSPType = C.PROV_GOST_2012_512
)

var (
	Success C.int = C.int(1)
	Failure C.int = C.int(0)
)

const (
	GOST3411          HashType = C.CALG_GR3411
	GOST3411_2012_256 HashType = C.CALG_GR3411_2012_256
	GOST3411_2012_512 HashType = C.CALG_GR3411_2012_512
)

// получить экземпляр крипто провайдера
func TakeCSP(cspType CSPType) (*CryptoProvider, error) {

	// PROV_GOST_2001_DH - это тип криптопровайдера. https://ru.wikipedia.org/wiki/%D0%9A%D1%80%D0%B8%D0%BF%D1%82%D0%BE%D0%BF%D1%80%D0%BE%D0%B2%D0%B0%D0%B9%D0%B4%D0%B5%D1%80
	// CRYPT_VERIFYCONTEXT - признак того, что операций с закрытым ключом не будет
	var cryptoProvider_CType C.HCRYPTPROV
	cspType_CType := C.ulong(cspType)

	result := C.CryptAcquireContext(&cryptoProvider_CType, nil, nil, cspType_CType, C.CRYPT_VERIFYCONTEXT)

	if result == Failure {
		// [ ] TODO: добавить обработку всех ошибок https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta#return-value
		return nil, errors.New("Не удается получить csp")
	}

	cryptoProvider := (CryptoProvider)(cryptoProvider_CType)
	return &cryptoProvider, nil
}

// освободить экземпляр криптопровайдера
func ReleaseCSP(cryptoProvider *CryptoProvider) {
	if cryptoProvider == nil {
		return
	}

	cryptoProvider_CType := (*C.HCRYPTPROV)(cryptoProvider)
	flag_CType := C.ulong(0)

	result := C.CryptReleaseContext(*cryptoProvider_CType, flag_CType)

	if result == Failure {
		// обработать все возможные ошибки https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptreleasecontext#return-value
		panic("Ошибка освобождения csp")
	}
}

// получить метод хэширования
func TakeHashMethod(cryptoProvider *CryptoProvider, hashType HashType) (*CryptoHash, error) {
	var hashMethod_CType C.HCRYPTHASH
	var hashMethod CryptoHash

	cryptoProvider_CType := (*C.HCRYPTPROV)(cryptoProvider)
	hashType_CType := C.uint(hashType)

	result := C.CryptCreateHash(*cryptoProvider_CType, hashType_CType, 0, 0, &hashMethod_CType)

	if result == Failure {
		// [ ] TODO: добавить обработку всех ошибок https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptcreatehash#return-value
		return nil, errors.New("Не удается получить метод хэширования")
	}

	hashMethod = (CryptoHash)(hashMethod_CType)

	return &hashMethod, nil
}

// освободить метод хэширования
func ReleaseHashMethod(hashMethod *CryptoHash) {
	if hashMethod == nil {
		return
	}

	hashMethod_CType := (*C.HCRYPTHASH)(hashMethod)

	result := C.CryptDestroyHash(*hashMethod_CType)

	if result == Failure {
		// обработать все возможные ошибки https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdestroyhash#return-value
		panic("Ошибка освобождения хэш метода")
	}
}

// вычислить хэш
func CalculateHashValue(hashMethod *CryptoHash, size HSize, data *[]byte) (*[]byte, error) {
	hashMethod_CType := (*C.HCRYPTHASH)(hashMethod)

	value := *data
	result := C.CryptHashData(*hashMethod_CType, (*C.uchar)(&value[0]), (C.ulong)(len(value)), 0)

	// [ ] TODO: обработать варианты ошибок https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-crypthashdata#return-value
	if result == Failure {
		return nil, errors.New("Не удалось сформировать данные для хэширования")
	}

	cbToBeSigned := make([]byte, size)

	result = C.CryptGetHashParam(*hashMethod_CType, C.HP_HASHVAL, (*C.uchar)(&cbToBeSigned[0]), (*C.ulong)(&size), 0)

	// [ ] TODO: обработать возможные ошибки https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgethashparam#return-value
	if result == Failure {
		return nil, errors.New("Не удалось получить значение хэша")
	}

	return &cbToBeSigned, nil
}
