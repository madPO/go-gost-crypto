# Пакет криптографии
Пакет golang для работы с криптографией, в том числе и ГОСТ. 

## Установка
Добавить в `go.mod` зависимости: 

```go
require github.com/madpo/go-gost-crypto/pkg/wrapper v1.0.0
require github.com/madpo/go-gost-crypto/pkg/cryptography v1.0.0
```

Загрузить зависимости:

```shell
go mod tidy
```

## Использование

В `.go` файл добавить импорт

```go
import "github.com/madpo/go-gost-crypto/pkg/cryptography"
```

### Хэширование
Пример вычисления хэша по ГОСТ
```go
release, calculateHash, error := cryptography.CreateGOST3411_2012_256HashMethod()

if error != nil {
    panic(error)
}

defer release()

var reader = strings.NewReader("Hello world")

hash, error := calculateHash(reader)

if error != nil {
    panic(error)
}
```

Функции `Create***HashMethod` возвращают 3 значения
- `release` -- функция для освобождения ресурсов
- `calculateHash` -- функция для вычисления хэша
- `error` -- ошибка при попытке сформировать функцию вычисления хэша

**ГОСТ 3411**
```go
release, calculateHash, error := cryptography.CreateGOST3411HashMethod()

if error != nil {
    panic(error)
}

defer release()

var reader = strings.NewReader("Hello world")

hash, error := calculateHash(reader)

if error != nil {
    panic(error)
}
```

**ГОСТ 3411-2012-256**
```go
release, calculateHash, error := cryptography.CreateGOST3411_2012_256HashMethod()

if error != nil {
    panic(error)
}

defer release()

var reader = strings.NewReader("Hello world")

hash, error := calculateHash(reader)

if error != nil {
    panic(error)
}
```

**ГОСТ 3411-2012-512**
```go
release, calculateHash, error := cryptography.CreateGOST3411_2012_512HashMethod()

if error != nil {
    panic(error)
}

defer release()

var reader = strings.NewReader("Hello world")

hash, error := calculateHash(reader)

if error != nil {
    panic(error)
}
```

**MD5**
```go
release, calculateHash, error := cryptography.CreateMD5HashMethod()

if error != nil {
    panic(error)
}

defer release()

var reader = strings.NewReader("Hello world")

hash, error := calculateHash(reader)

if error != nil {
    panic(error)
}
```

**SHA256**
```go
release, calculateHash, error := cryptography.CreateSha256HashMethod()

if error != nil {
    panic(error)
}

defer release()

var reader = strings.NewReader("Hello world")

hash, error := calculateHash(reader)

if error != nil {
    panic(error)
}
```

**SHA384**
```go
release, calculateHash, error := cryptography.CreateSha384HashMethod()

if error != nil {
    panic(error)
}

defer release()

var reader = strings.NewReader("Hello world")

hash, error := calculateHash(reader)

if error != nil {
    panic(error)
}
```

**SHA512**
```go
release, calculateHash, error := cryptography.CreateSha512HashMethod()

if error != nil {
    panic(error)
}

defer release()

var reader = strings.NewReader("Hello world")

hash, error := calculateHash(reader)

if error != nil {
    panic(error)
}
```
