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

// Исключение работы с csp
type CSPException struct {
	code int64
}

// Исключение получения метода хэширования
type HashMethodException struct {
	code int64
}

// Исключение вычисления хэша
type CalculateHashException struct {
	code int64
}

// исключение получения параметра хэша
type GetHashException struct {
	code int64
}

func (exception *CSPException) Error() string {
	switch exception.code {
	case C.ERROR_BUSY:
		return "ERROR_BUSY. Some CSPs set this error if the CRYPT_DELETEKEYSET flag value is set and another thread or process is using this key container."
	case C.ERROR_FILE_NOT_FOUND:
		return "ERROR_FILE_NOT_FOUND. The profile of the user is not loaded and cannot be found. This happens when the application impersonates a user, for example, the IUSR_ComputerName account."
	case C.ERROR_INVALID_PARAMETER:
		return "ERROR_INVALID_PARAMETER. One of the parameters contains a value that is not valid. This is most often a pointer that is not valid."
	case C.ERROR_NOT_ENOUGH_MEMORY:
		return "ERROR_NOT_ENOUGH_MEMORY. The operating system ran out of memory during the operation."
	case C.NTE_BAD_FLAGS:
		return "NTE_BAD_FLAGS. The dwFlags parameter has a value that is not valid."
	case C.NTE_BAD_KEY_STATE:
		return "NTE_BAD_KEY_STATE. The user password has changed since the private keys were encrypted."
	case C.NTE_BAD_KEYSET:
		return "NTE_BAD_KEYSET. The key container could not be opened. A common cause of this error is that the key container does not exist. To create a key container, call CryptAcquireContext using the CRYPT_NEWKEYSET flag. This error code can also indicate that access to an existing key container is denied. Access rights to the container can be granted by the key set creator by using CryptSetProvParam."
	case C.NTE_BAD_KEYSET_PARAM:
		return "NTE_BAD_KEYSET_PARAM. The pszContainer or pszProvider parameter is set to a value that is not valid."
	case C.NTE_BAD_PROV_TYPE:
		return "NTE_BAD_PROV_TYPE. The value of the dwProvType parameter is out of range. All provider types must be from 1 through 999, inclusive."
	case C.NTE_BAD_SIGNATURE:
		return "NTE_BAD_SIGNATURE. The provider DLL signature could not be verified. Either the DLL or the digital signature has been tampered with."
	case C.NTE_EXISTS:
		return "NTE_EXISTS. The dwFlags parameter is CRYPT_NEWKEYSET, but the key container already exists."
	case C.NTE_KEYSET_ENTRY_BAD:
		return "NTE_KEYSET_ENTRY_BAD. The pszContainer key container was found but is corrupt."
	case C.NTE_KEYSET_NOT_DEF:
		return "NTE_KEYSET_NOT_DEF. The requested provider does not exist."
	case C.NTE_NO_MEMORY:
		return "NTE_NO_MEMORY. The CSP ran out of memory during the operation."
	case C.NTE_PROV_DLL_NOT_FOUND:
		return "NTE_PROV_DLL_NOT_FOUND. The provider DLL file does not exist or is not on the current path."
	case C.NTE_PROV_TYPE_ENTRY_BAD:
		return "NTE_PROV_TYPE_ENTRY_BAD. The provider type specified by dwProvType is corrupt. This error can relate to either the user default CSP list or the computer default CSP list."
	case C.NTE_PROV_TYPE_NO_MATCH:
		return "NTE_PROV_TYPE_NO_MATCH. The provider type specified by dwProvType does not match the provider type found. Note that this error can only occur when pszProvider specifies an actual CSP name."
	case C.NTE_PROV_TYPE_NOT_DEF:
		return "NTE_PROV_TYPE_NOT_DEF. No entry exists for the provider type specified by dwProvType."
	case C.NTE_PROVIDER_DLL_FAIL:
		return "NTE_PROVIDER_DLL_FAIL. The provider DLL file could not be loaded or failed to initialize."
	case C.NTE_SIGNATURE_FILE_BAD:
		return "NTE_SIGNATURE_FILE_BAD. An error occurred while loading the DLL file image, prior to verifying its signature."
	case C.ERROR_INVALID_HANDLE:
		return "ERROR_INVALID_HANDLE. One of the parameters specifies a handle that is not valid."
	case C.NTE_BAD_UID:
		return "NTE_BAD_UID. The hProv parameter does not contain a valid context handle."
	}

	return "Undefined CSP Error"
}

func (exception *HashMethodException) Error() string {
	switch exception.code {
	case C.ERROR_INVALID_HANDLE:
		return "ERROR_INVALID_HANDLE. One of the parameters specifies a handle that is not valid."
	case C.ERROR_INVALID_PARAMETER:
		return "ERROR_INVALID_PARAMETER. One of the parameters contains a value that is not valid. This is most often a pointer that is not valid."
	case C.ERROR_NOT_ENOUGH_MEMORY:
		return "ERROR_NOT_ENOUGH_MEMORY. The operating system ran out of memory during the operation."
	case C.NTE_BAD_ALGID:
		return "NTE_BAD_ALGID. The Algid parameter specifies an algorithm that this CSP does not support."
	case C.NTE_BAD_FLAGS:
		return "NTE_BAD_FLAGS. The dwFlags parameter is nonzero."
	case C.NTE_BAD_KEY:
		return "NTE_BAD_KEY. A keyed hash algorithm, such as CALG_MAC, is specified by Algid, and the hKey parameter is either zero or it specifies a key handle that is not valid. This error code is also returned if the key is to a stream cipher or if the cipher mode is anything other than CBC."
	case C.NTE_NO_MEMORY:
		return "NTE_NO_MEMORY. The CSP ran out of memory during the operation."
	case C.ERROR_BUSY:
		return "ERROR_BUSY. The hash object specified by hHash is currently being used and cannot be destroyed."
	case C.NTE_BAD_HASH:
		return "NTE_BAD_HASH. The hash object specified by the hHash parameter is not valid."
	case C.NTE_BAD_UID:
		return "NTE_BAD_UID. The CSP context that was specified when the hash object was created cannot be found."
	}

	return "Undefined HashMethod Error"
}

func (exception *CalculateHashException) Error() string {
	switch exception.code {
	case C.ERROR_INVALID_HANDLE:
		return "ERROR_INVALID_HANDLE. One of the parameters specifies a handle that is not valid."
	case C.ERROR_INVALID_PARAMETER:
		return "ERROR_INVALID_PARAMETER. One of the parameters contains a value that is not valid. This is most often a pointer that is not valid."
	case C.NTE_BAD_ALGID:
		return "NTE_BAD_ALGID. The hHash handle specifies an algorithm that this CSP does not support."
	case C.NTE_BAD_FLAGS:
		return "NTE_BAD_FLAGS. The dwFlags parameter contains a value that is not valid."
	case C.NTE_BAD_HASH:
		return "NTE_BAD_HASH. The hash object specified by the hHash parameter is not valid."
	case C.NTE_BAD_HASH_STATE:
		return "NTE_BAD_HASH_STATE. An attempt was made to add data to a hash object that is already marked \"finished.\""
	case C.NTE_BAD_KEY:
		return "NTE_BAD_KEY. A keyed hash algorithm is being used, but the session key is no longer valid. This error is generated if the session key is destroyed before the hashing operation is complete."
	case C.NTE_BAD_LEN:
		return "NTE_BAD_LEN. The CSP does not ignore the CRYPT_USERDATA flag, the flag is set, and the dwDataLen parameter has a nonzero value."
	case C.NTE_BAD_UID:
		return "NTE_BAD_UID. The CSP context that was specified when the hash object was created cannot be found."
	case C.NTE_FAIL:
		return "NTE_FAIL. The function failed in some unexpected way."
	case C.NTE_NO_MEMORY:
		return "NTE_NO_MEMORY. The CSP ran out of memory during the operation."
	}

	return "Undefined CalculateHash Error"
}

func (exception *GetHashException) Error() string {
	switch exception.code {
	case C.ERROR_INVALID_HANDLE:
		return "ERROR_INVALID_HANDLE. One of the parameters specifies a handle that is not valid."
	case C.ERROR_INVALID_PARAMETER:
		return "ERROR_INVALID_PARAMETER. One of the parameters contains a value that is not valid. This is most often a pointer that is not valid."
	case C.ERROR_MORE_DATA:
		return "ERROR_MORE_DATA. If the buffer specified by the pbData parameter is not large enough to hold the returned data, the function sets the ERROR_MORE_DATA code and stores the required buffer size, in bytes, in the variable pointed to by pdwDataLen."
	case C.NTE_BAD_FLAGS:
		return "NTE_BAD_FLAGS. The dwFlags parameter is nonzero."
	case C.NTE_BAD_HASH:
		return "NTE_BAD_HASH. The hash object specified by the hHash parameter is not valid."
	case C.NTE_BAD_TYPE:
		return "NTE_BAD_TYPE. The dwParam parameter specifies an unknown value number."
	case C.NTE_BAD_UID:
		return "NTE_BAD_UID. The CSP context that was specified when the hash was created cannot be found."
	}

	return "Undefined GetHashParam Error"
}

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
		errorCode := C.GetLastError()
		return nil, &CSPException{code: (int64)(errorCode)}
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
		errorCode := C.GetLastError()
		panic(&CSPException{code: (int64)(errorCode)})
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
		errorCode := C.GetLastError()
		return nil, &HashMethodException{code: (int64)(errorCode)}
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
		errorCode := C.GetLastError()
		panic(&HashMethodException{code: (int64)(errorCode)})
	}
}

// вычислить хэш
func ApplyHash(hashObject *CryptoHash, data *[]byte) error {
	hashObject_CType := (*C.HCRYPTHASH)(hashObject)

	value := *data
	result := C.CryptHashData(*hashObject_CType, (*C.uchar)(&value[0]), (C.ulong)(len(value)), 0)

	if result == Failure {
		errorCode := C.GetLastError()
		return &CalculateHashException{code: (int64)(errorCode)}
	}

	return nil
}

// вычислить хэш
func CalculateHashValue(hashObject *CryptoHash, size HSize) (*[]byte, error) {
	hashObject_CType := (*C.HCRYPTHASH)(hashObject)
	hashBuffer := make([]byte, size)

	result := C.CryptGetHashParam(*hashObject_CType, C.HP_HASHVAL, (*C.uchar)(&hashBuffer[0]), (*C.ulong)(&size), 0)

	if result == Failure {
		errorCode := C.GetLastError()
		return nil, &GetHashException{code: (int64)(errorCode)}
	}

	return &hashBuffer, nil
}
