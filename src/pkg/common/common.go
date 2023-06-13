package common

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

type CSPType int64

type test C.HCRYPTPROV

const (
	GOST2001     CSPType = C.PROV_GOST_2001_DH
	GOST2012_256 CSPType = C.PROV_GOST_2012_256
	GOST2012_512 CSPType = C.PROV_GOST_2012_512
)

var (
	Success C.int = C.int(1)
	Failure C.int = C.int(0)
)

type HashType uint

const (
	GOST3411          HashType = C.CALG_GR3411
	GOST3411_2012_256 HashType = C.CALG_GR3411_2012_256
	GOST3411_2012_512 HashType = C.CALG_GR3411_2012_512
)

func TakeCSP(cspType CSPType) (*C.HCRYPTPROV, error) {
	// ссылка на криптопровайдер
	var cryptoProvider C.HCRYPTPROV

	// PROV_GOST_2001_DH - это тип криптопровайдера. https://ru.wikipedia.org/wiki/%D0%9A%D1%80%D0%B8%D0%BF%D1%82%D0%BE%D0%BF%D1%80%D0%BE%D0%B2%D0%B0%D0%B9%D0%B4%D0%B5%D1%80
	// CRYPT_VERIFYCONTEXT - признак того, что операций с закрытым ключом не будет
	result := C.CryptAcquireContext(&cryptoProvider, nil, nil, C.ulong(cspType), C.CRYPT_VERIFYCONTEXT)

	if result == Failure {
		// [ ] TODO: добавить обработку всех ошибок https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta#return-value
		return nil, errors.New("Не удается получить csp")
	}

	return &cryptoProvider, nil
}

func ReleaseCSP(cryptoProvider *C.HCRYPTPROV) {
	if cryptoProvider == nil {
		return
	}

	result := C.CryptReleaseContext(*cryptoProvider, C.ulong(0))

	if result == Failure {
		// обработать все возможные ошибки https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptreleasecontext#return-value
		panic("Ошибка освобождения csp")
	}
}
