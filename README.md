# IDPass for Java

[![CircleCI](https://circleci.com/gh/newlogic42/lab_idpass-lite-java.svg?style=svg&circle-token=8d3b9b9fe5cd3ffc0884b5fac81bc9e779e9f1a9)](https://circleci.com/gh/newlogic42/lab_idpass-lite-java)

This is a Java wrapper over the [libidpasslite](https://github.com/newlogic42/lab_idpass_lite) library that provides developers with an API to interact with ID PASS cards.

## Building
```bash
./gradlew build
./gradlew test
```

## Features
- create card with face
- verify card with face
- verify card with pin
- sign with card
- encrypt with card
- generate QR Code
- read QR Code

## Quick start
Sample usage....

### 1. Install
Install by adding the bintray repository and the dependency. For Maven users, please see ...

```groovy
// Top level build file
repositories {
    jcenter()
}

// Add to dependencies section
dependencies {
    implementation "org.idpass:idpass:0.0.1"
}
```

### 2. Usage

```java
IDPassReader reader = new IDPassReader(encryptionkey, signaturekey);

Card card = new Card(reader,
        "John",
        "Doe",
        new Date(),
        "Aubusson, France",
        null,
        null,
        Files.readAllBytes(Paths.get("testdata/manny1.bmp")),
        "1234");

BufferedImage qrCode = card.asQRCode();

Card readCard = reader.open(qrCode);
card.authenticateWithFace(Files.readAllBytes(Paths.get("testdata/manny4.jpg")));

readCard.getGivenName();

```
