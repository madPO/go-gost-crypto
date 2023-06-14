# Пакет криптографии
Пакет golang для работы с криптографией, в том числе и ГОСТ. 

## Установка
Добавить в `go.mod` зависимости: 

```golang
require github.com/madpo/go-gost-crypto/pkg/wrapper v1.0.0
require github.com/madpo/go-gost-crypto/pkg/cryptography v1.0.0
```

Загрузить зависимости:

```shell
go mod tidy
```

## Использование

В `.go` файл добавить импорт

```golang
import "github.com/madpo/go-gost-crypto/pkg/cryptography"
```

### Хэширование
Пример вычисления хэша по ГОСТ
```golang
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
```

Функции `Create***HashMethod` возвращают 3 значения
- `release` -- функция для освобождения ресурсов
- `calculateHash` -- функция для вычисления хэша
- `error` -- ошибка при попытке сформировать функцию вычисления хэша

**ГОСТ 3411**
```golang
release, calculateHash, error := cryptography.CreateGOST3411HashMethod()

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
```

**ГОСТ 3411-2012-256**
```golang
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
```

**ГОСТ 3411-2012-512**
```golang
release, calculateHash, error := cryptography.CreateGOST3411_2012_512HashMethod()

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
```
