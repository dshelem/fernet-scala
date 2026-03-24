# fernet-scala

Pure Scala implementation of [Fernet]([https://github.com/fernet/spec](https://github.com/fernet/spec/blob/master/Spec.md)) symmetric encryption.
No external dependencies — only Java 8 standard library.

## Usage

```scala  
val key = Fernet.FernetKey.generate()  
val token = Fernet.encrypt(key, "Hello, world!")  

println("Decrypted text:" + Fernet.decrypt(key, token))
```

## Requirements
- Java 8+
- Scala 2.13+
- Maven 3.x

## Build
```bash
mvn compile
mvn exec:java
```
