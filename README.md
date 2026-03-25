# fernet-scala

Pure Scala implementation of [Fernet]([https://github.com/fernet/spec](https://github.com/fernet/spec/blob/master/Spec.md)) symmetric encryption.
No external dependencies - only Java 8 standard library.

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

## License
Copyright 2026 Denis Shelemekh

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
