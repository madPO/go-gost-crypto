package main

import (
	"fmt"

	"github.com/madpo/go-gost-crypto/pkg/cryptography"
)

func main() {
	release, calculateHash, error := cryptography.CreateGOST3411_2012_256HashMethod()

	if error != nil {
		panic(error)
	}

	defer release()

	var data = []byte{10, 25}

	hash, error := calculateHash(&data)

	if error != nil {
		panic(error)
	}

	fmt.Println(hash)
}
