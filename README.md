# IDPass for Java

[![CircleCI](https://circleci.com/gh/idpass/idpass-lite-java.svg?style=svg&circle-token=4fb5cc4cfe96b754d1842c2443ee638608bc4755)](https://circleci.com/gh/newlogic42/lab_idpass-lite-java)

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
- add/revoke/verify certificates
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
KeySet keySet = KeySet.newBuilder()
	.setEncryptionKey(ByteString.copyFrom(encryptionKey))
	.setSignatureKey(ByteString.copyFrom(signatureKey))
	.build();

IDPassReader reader = new IDPassReader(keySet, rootCerts);

byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
Ident ident = Ident.newBuilder()
	.setGivenName("John")
	.setSurName("Doe")
	.setPin("1234")
	.setPlaceOfBirth("Aubusson, France")
	.setDateOfBirth(Dat.newBuilder().setYear(1980).setMonth(12).setDay(17))
	.setPhoto(ByteString.copyFrom(photo))
	.addPubExtra(KV.newBuilder().setKey("gender").setValue("male").setKey("height").setValue("5.5ft"))
	.addPrivExtra(KV.newBuilder().setKey("blood type").setValue("A"))
	.build();

Card card = reader.newCard(ident, intermedCerts);

BufferedImage qrCode = card.asQRCode();
Card readCard = reader.open(qrCode);
card.authenticateWithFace(photo);
readCard.getGivenName();
```
