package cryptography

import (
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

func Test_MD5Hash_Success(t *testing.T) {
	release, calculateHash, error := CreateMD5HashMethod()

	if error != nil {
		t.Error(error)
	}

	defer release()

	var reader = strings.NewReader("Hello world")

	hash, error := calculateHash(reader)

	if error != nil {
		t.Error(error)
	}

	data, error := io.ReadAll(hash)

	if error != nil {
		t.Error(error)
	}

	result := hex.EncodeToString(data)
	want := "3e25960a79dbc69b674cd4ec67a72c62"

	if result != want {
		t.Errorf("Ожидался md5 хэш %s. Получен %s", want, result)
	}
}

func Test_Sha256Hash_Success(t *testing.T) {
	release, calculateHash, error := CreateSha256HashMethod()

	if error != nil {
		t.Error(error)
	}

	defer release()

	var reader = strings.NewReader("Hello world")

	hash, error := calculateHash(reader)

	if error != nil {
		t.Error(error)
	}

	data, error := io.ReadAll(hash)

	if error != nil {
		t.Error(error)
	}

	result := hex.EncodeToString(data)
	want := "64ec88ca00b268e5ba1a35678a1b5316d212f4f366b2477232534a8aeca37f3c"

	if result != want {
		t.Errorf("Ожидался sha256 хэш %s. Получен %s", want, result)
	}
}

func Test_Sha384Hash_Success(t *testing.T) {
	release, calculateHash, error := CreateSha384HashMethod()

	if error != nil {
		t.Error(error)
	}

	defer release()

	var reader = strings.NewReader("Hello world")

	hash, error := calculateHash(reader)

	if error != nil {
		t.Error(error)
	}

	data, error := io.ReadAll(hash)

	if error != nil {
		t.Error(error)
	}

	want := "9203b0c4439fd1e6ae5878866337b7c532acd6d9260150c80318e8ab8c27ce330189f8df94fb890df1d298ff360627e1"
	result := hex.EncodeToString(data)

	if result != want {
		t.Errorf("Ожидался sha384 хэш %s. Получен %s", want, result)
	}
}

func Test_Sha512Hash_Success(t *testing.T) {
	release, calculateHash, error := CreateSha512HashMethod()

	if error != nil {
		t.Error(error)
	}

	defer release()

	var reader = strings.NewReader("Hello world")

	hash, error := calculateHash(reader)

	if error != nil {
		t.Error(error)
	}

	data, error := io.ReadAll(hash)

	if error != nil {
		t.Error(error)
	}

	want := "b7f783baed8297f0db917462184ff4f08e69c2d5e5f79a942600f9725f58ce1f29c18139bf80b06c0fff2bdd34738452ecf40c488c22a7e3d80cdf6f9c1c0d47"
	result := hex.EncodeToString(data)

	if result != want {
		t.Errorf("Ожидался sha512 хэш %s. Получен %s", want, result)
	}
}

func Test_GOST3411_Success(t *testing.T) {
	release, calculateHash, error := CreateGOST3411HashMethod()

	if error != nil {
		t.Error(error)
	}

	defer release()

	var reader = strings.NewReader("Hello world")

	hash, error := calculateHash(reader)

	if error != nil {
		t.Error(error)
	}

	data, error := io.ReadAll(hash)

	if error != nil {
		t.Error(error)
	}

	want := "83b95631f380a2af583915f565a28055e348df1b9ffa7b246f4cbdae5ee63a73"
	result := hex.EncodeToString(data)

	if result != want {
		t.Errorf("Ожидался ГОСТ 3411 хэш %s. Получен %s", want, result)
	}
}

func Test_GOST3411_2012_256_Success(t *testing.T) {
	release, calculateHash, error := CreateGOST3411_2012_256HashMethod()

	if error != nil {
		t.Error(error)
	}

	defer release()

	var reader = strings.NewReader("Hello world")

	hash, error := calculateHash(reader)

	if error != nil {
		t.Error(error)
	}

	data, error := io.ReadAll(hash)

	if error != nil {
		t.Error(error)
	}

	result := hex.EncodeToString(data)
	want := "6960df2aa2b21015836a81446662b55e4c11c8f5289ea8ac9ed01cb172975dbf"

	if result != want {
		t.Errorf("Ожидался ГОСТ 3411-2012-256 хэш %s. Получен %s", want, result)
	}
}

func Test_GOST3411_2012_512_Success(t *testing.T) {
	release, calculateHash, error := CreateGOST3411_2012_512HashMethod()

	if error != nil {
		t.Error(error)
	}

	defer release()

	var reader = strings.NewReader("Hello world")

	hash, error := calculateHash(reader)

	if error != nil {
		t.Error(error)
	}

	data, error := io.ReadAll(hash)

	if error != nil {
		t.Error(error)
	}

	result := hex.EncodeToString(data)
	want := "5c175af4bf26f229b865f754d71b2dd4ca3a35c2a27e017ad48fc3cd3064087bf49190dbd35dc84e25abea30b223a9eb3130cb567c7f523178be46a9f6b5e50e"

	if result != want {
		t.Errorf("Ожидался ГОСТ 3411-2012-512 хэш %s. Получен %s", want, result)
	}
}
