/*
 * Copyright (C) 2020 Newlogic Pte. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 *
 */

package org.idpass.lite.test;

import com.google.protobuf.ByteString;
import com.google.zxing.*;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import org.api.proto.Certificates;
import org.api.proto.Ident;
import org.api.proto.KeySet;
import org.api.proto.byteArray;
import org.idpass.lite.Card;
import org.idpass.lite.IDPassHelper;
import org.idpass.lite.IDPassReader;
import org.idpass.lite.exceptions.CardVerificationException;
import org.idpass.lite.exceptions.IDPassException;
import org.idpass.lite.exceptions.InvalidCardException;
import org.idpass.lite.exceptions.NotVerifiedException;
import org.idpass.lite.proto.Date;
import org.idpass.lite.proto.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The QRCodeImageScanner externalizes the zxing dependency outside
 * of idpass-lite-java jar library.
 */

class QRCodeImageScanner implements Function<BufferedImage, byte[]> {
    @Override
    public byte[] apply(BufferedImage img) {

        LuminanceSource source = new BufferedImageLuminanceSource(img);
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));

        byte[] card;

        try {
            Result result = new MultiFormatReader().decode(bitmap);
            Map m = result.getResultMetadata();

            if (m.containsKey(ResultMetadataType.BYTE_SEGMENTS)) {
                List L = (List) m.get(ResultMetadataType.BYTE_SEGMENTS);
                card = (byte[]) L.get(0);
            } else {
                card = result.getText().getBytes();
            }
        } catch (com.google.zxing.NotFoundException e) {
            return null;
        }

        return card;
    }
}

public class TestCases {
    // QR code scanner with zxing dependency in test cases only
    Function<BufferedImage, byte[]> qrImageScanner = new QRCodeImageScanner();

    byte[] encryptionkey    = IDPassHelper.generateEncryptionKey();
    byte[] signaturekey     = IDPassHelper.generateSecretSignatureKey();
    byte[] publicVerificationKey = Arrays.copyOfRange(signaturekey, 32, 64);

    KeySet m_keyset = KeySet.newBuilder()
            .setEncryptionKey(ByteString.copyFrom(encryptionkey))
            .setSignatureKey(ByteString.copyFrom(signaturekey))
            .addVerificationKeys(byteArray.newBuilder()
                    .setTyp(byteArray.Typ.ED25519PUBKEY)
                    .setVal(ByteString.copyFrom(publicVerificationKey)).build())
            .build();

    byte[] encryptionkey2    = IDPassHelper.generateEncryptionKey();
    byte[] signaturekey2     = IDPassHelper.generateSecretSignatureKey();
    byte[] publicVerificationKey2 = Arrays.copyOfRange(signaturekey2, 32, 64);
    KeySet m_keyset2 = KeySet.newBuilder()
            .setEncryptionKey(ByteString.copyFrom(encryptionkey2))
            .setSignatureKey(ByteString.copyFrom(signaturekey2))
            .addVerificationKeys(byteArray.newBuilder()
                    .setTyp(byteArray.Typ.ED25519PUBKEY)
                    .setVal(ByteString.copyFrom(publicVerificationKey2)).build())
            .build();

    // Setup useful root certificate and intermediate certificate for test cases
    byte[] m_rootkey = IDPassHelper.generateSecretSignatureKey();
    Certificate m_rootcert = IDPassReader.generateRootCertificate(m_rootkey);
    Certificates m_rootcerts = Certificates.newBuilder().addCert(m_rootcert).build();
    Certificate m_childcert = IDPassReader.generateChildCertificate(m_rootkey, publicVerificationKey);
    Certificates m_certchain = Certificates.newBuilder().addCert(m_childcert).build();

    @BeforeEach
	void setup() {

	}

    @AfterEach
	void teardown() {

	}

    public TestCases() throws IDPassException {
    }

    private Ident.Builder newIdentBuilder() {
        return Ident.newBuilder()
                .setGivenName("John")
                .setSurName("Doe")
                .setPin("1234")
                .setPlaceOfBirth("Aubusson, France")
                .setDateOfBirth(Date.newBuilder().setYear(1980).setMonth(12).setDay(17))
                .addPubExtra(Pair.newBuilder().setKey("gender").setValue("male").setKey("height").setValue("5.4ft"))
                .addPrivExtra(Pair.newBuilder().setKey("blood type").setValue("A"));
    }

    private Card newTestCard(IDPassReader reader, Certificates certchain) throws IDPassException, IOException {
        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));

        Ident ident = newIdentBuilder().setPhoto(ByteString.copyFrom(photo))
                .addPubExtra(Pair.newBuilder().setKey("sports").setValue("boxing").setKey("game").setValue("cards"))
                .addPrivExtra(Pair.newBuilder().setKey("age").setValue("35").setKey("address").setValue("16th Elm Street"))
                .build();

        Card card = reader.newCard(ident,certchain);
        return card;
    }

    private Card newTestCard(IDPassReader reader) throws IDPassException, IOException {
        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));

        Ident ident = newIdentBuilder().setPhoto(ByteString.copyFrom(photo))
                .addPubExtra(Pair.newBuilder().setKey("sports").setValue("boxing").setKey("game").setValue("cards"))
                .addPrivExtra(Pair.newBuilder().setKey("age").setValue("35").setKey("address").setValue("16th Elm Street"))
                .build();

        Card card = reader.newCard(ident,null);
        return card;
    }


    @Test
    public void testcreateCard2WithCertificates()
            throws IOException, IDPassException {
        byte[] rootKey = IDPassReader.generateSecretSignatureKey();

        Certificate rootCert = IDPassReader.generateRootCertificate(rootKey);
        Certificate signerFromRootCert = IDPassReader.generateChildCertificate(rootKey, publicVerificationKey); // very important

        Certificates rootCertificates = Certificates.newBuilder().addCert(rootCert).build();

        IDPassReader reader = new IDPassReader(m_keyset, rootCertificates);

        //IDPassReader.addRevokedKey(Arrays.copyOfRange(signer0,32,64));
        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
        Ident ident = newIdentBuilder().setPhoto(ByteString.copyFrom(photo)).build();

        Certificates certs = Certificates.newBuilder().addCert(signerFromRootCert).build();
        Card card = reader.newCard(ident, certs);

        Card cardOK = reader.open(card.asBytes());
        assertNotNull(cardOK);

        assertTrue(card.verifyCertificate());

        card.authenticateWithPIN("1234");
        assertTrue(card.verifyCertificate());

        byte[] signer1 = IDPassReader.generateSecretSignatureKey();
        Certificate signer1RootCert = IDPassReader.generateRootCertificate(signer1);

        Certificates rootCertificates1 = Certificates.newBuilder().addCert(signer1RootCert).build();

        IDPassReader reader2 = new IDPassReader(m_keyset, rootCertificates1);

        try {
            reader2.open(card.asBytes());
            assertTrue(false);
        } catch (InvalidCardException ignored) {}

        Card card2 = reader2.open(card.asBytes(), true);

    }

    @Test
    public void testOpenCardWithNoVerificationKey() throws IOException, IDPassException {
        byte[] signer0 = IDPassReader.generateSecretSignatureKey();

        Certificate signer0RootCert = IDPassReader.generateRootCertificate(signer0);
        Certificate signerFromSigner0Cert = IDPassReader.generateChildCertificate(signer0, publicVerificationKey); // very important

        Certificates rootcertificates  = Certificates.newBuilder().addCert(signer0RootCert).build();

        IDPassReader reader = new IDPassReader(m_keyset, rootcertificates);

        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
        Ident ident = newIdentBuilder().setPhoto(ByteString.copyFrom(photo)).build();

        Certificates certificateChainToRoot = Certificates.newBuilder().addCert(signerFromSigner0Cert).build();

        Card card = reader.newCard(ident, certificateChainToRoot);
        Card cardOK = reader.open(card.asBytes());
        assertNotNull(cardOK);


        byte[] newSignatureKey = IDPassHelper.generateSecretSignatureKey();

        KeySet keyset = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(encryptionkey))
                .setSignatureKey(ByteString.copyFrom(newSignatureKey))
                .build();
        IDPassReader reader2 = new IDPassReader(keyset, rootcertificates);
        Card card2 = reader2.open(card.asBytes());
        assertNotNull(card2);
    }

    @Test
    public void testOpenCardWithUnkownVerificationKey() throws IOException, IDPassException {
        byte[] signer0 = IDPassReader.generateSecretSignatureKey();

        Certificate signer0RootCert = IDPassReader.generateRootCertificate(signer0);
        Certificate signerFromSigner0Cert = IDPassReader.generateChildCertificate(signer0, publicVerificationKey); // very important

        Certificates rootCertificates = Certificates.newBuilder().addCert(signer0RootCert).build();

        IDPassReader reader = new IDPassReader(m_keyset, rootCertificates);

        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
        Ident ident = newIdentBuilder().setPhoto(ByteString.copyFrom(photo)).build();


        Certificates certs = Certificates.newBuilder().addCert(signerFromSigner0Cert).build();

        Card card = reader.newCard(ident, certs);
        Card cardOK = reader.open(card.asBytes());
        assertNotNull(cardOK);

        byte[] newSignatureKey = new byte[64];
        byte[] newVerificationKey = new byte[32];
        IDPassReader.generateSecretSignatureKeypair(newVerificationKey, newSignatureKey);

        KeySet keyset2 = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(encryptionkey))
                .setSignatureKey(ByteString.copyFrom(newSignatureKey))
                .addVerificationKeys(byteArray.newBuilder()
                        .setTyp(byteArray.Typ.ED25519PUBKEY)
                        .setVal(ByteString.copyFrom(newVerificationKey)).build())
                .build();

        IDPassReader reader2 = new IDPassReader(keyset2, rootCertificates);
        Card card2 = reader2.open(card.asBytes());
        assertNotNull(card2);
        //TODO open the private part

        try {
            card2.authenticateWithPIN("1234");
            assertTrue(false);
        } catch (CardVerificationException ignored) {}
    }



    @Test
    public void testOpenCardWithAnotherEncryptionKey() throws IOException, IDPassException {
        byte[] signer0 = IDPassReader.generateSecretSignatureKey();

        Certificate signer0RootCert = IDPassReader.generateRootCertificate(signer0);
        Certificate signerFromSigner0Cert = IDPassReader.generateChildCertificate(signer0, publicVerificationKey); // very important

        Certificates rootcertificates = Certificates.newBuilder().addCert(signer0RootCert).build();

        IDPassReader reader = new IDPassReader(m_keyset, rootcertificates);

        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
        Ident ident = newIdentBuilder().setPhoto(ByteString.copyFrom(photo)).build();

        Certificates certs = Certificates.newBuilder().addCert(signerFromSigner0Cert).build();

        Card card = reader.newCard(ident, certs);
        Card cardOK = reader.open(card.asBytes());
        assertNotNull(cardOK);

        byte[] newEncryptionkey = IDPassHelper.generateEncryptionKey();
        byte[] newSignatureKey = new byte[64];
        byte[] newVerificationKey = new byte[32];
        IDPassReader.generateSecretSignatureKeypair(newVerificationKey, newSignatureKey);

        KeySet newKeyset = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(newEncryptionkey))
                .setSignatureKey(ByteString.copyFrom(newSignatureKey))
                .addVerificationKeys(byteArray.newBuilder()
                        .setTyp(byteArray.Typ.ED25519PUBKEY)
                        .setVal(ByteString.copyFrom(newVerificationKey)).build())
                .build();

        IDPassReader reader2 = new IDPassReader(newKeyset, rootcertificates);
        Card card2 = reader2.open(card.asBytes());
        assertNotNull(card2);

        try {
            card2.authenticateWithPIN("1234");
            assertTrue(false);
        } catch (CardVerificationException ignored) {}
    }


    @Test
    public void testcreateCardWithCertificates()
            throws IOException, IDPassException
    {
        byte[] signer0 = IDPassReader.generateSecretSignatureKey();
        byte[] signer1 = IDPassReader.generateSecretSignatureKey();
        byte[] signer2 = IDPassReader.generateSecretSignatureKey();
        byte[] signer3 = IDPassReader.generateSecretSignatureKey();
        byte[] signer4 = IDPassReader.generateSecretSignatureKey();
        byte[] signer9 = IDPassReader.generateSecretSignatureKey();

        Certificate signer0RootCert = IDPassReader.generateRootCertificate(signer0);
        Certificate signer1RootCert = IDPassReader.generateRootCertificate(signer1);

        Certificate signer2From1Cert = IDPassReader.generateChildCertificate(signer1, Arrays.copyOfRange(signer2,32,64));
        Certificate signer3From2Cert = IDPassReader.generateChildCertificate(signer2, Arrays.copyOfRange(signer3,32,64));

        Certificate signer4From3Cert = IDPassReader.generateChildCertificate(signer3, Arrays.copyOfRange(signer4,32,64));
        Certificate signer4From0Cert = IDPassReader.generateChildCertificate(signer0, publicVerificationKey); // very important

        Certificates rootcertificates = Certificates.newBuilder()
                .addCert(signer0RootCert)
                .addCert(signer1RootCert)
                .build();

        IDPassReader reader = new IDPassReader(m_keyset, rootcertificates);

        Certificates certs = Certificates.newBuilder()
                .addCert(signer0RootCert)
                .addCert(signer1RootCert)
                .addCert(signer2From1Cert)
                .addCert(signer3From2Cert)
                .addCert(signer4From3Cert)
                .addCert(signer4From0Cert)
                .build();

        //IDPassReader.addRevokedKey(Arrays.copyOfRange(signer0,32,64));
        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
        Ident ident = newIdentBuilder().setPhoto(ByteString.copyFrom(photo)).build();

        Card card = reader.newCard(ident,certs);

        try {
            card.authenticateWithPIN("1234");
        } catch (CardVerificationException ignored) {
        }
        assertTrue(card.verifyCertificate());
        assertNotNull(card);
        assertTrue(card.asBytes().length > 0);
        reader.open(card.asBytes());

        IDPassReader reader2 = new IDPassReader(m_keyset, rootcertificates);
        Card card2 = reader2.open(card.asBytes());
        card2.authenticateWithPIN(("1234"));
        assertTrue(card2.verifyCertificate());

        card2 = reader2.open(card.asBytes());
        assertTrue(card2.verifyCertificate());

        Certificates rootcertificates2 = Certificates.newBuilder()
                .addCert(IDPassReader.generateRootCertificate(signer9))
                .build();

        IDPassReader reader3 = new IDPassReader(m_keyset, rootcertificates2);

        try {
            reader3.open(card.asBytes());
            assertTrue(false);
        } catch (InvalidCardException ignored) {}

        card2 = reader3.open(card.asBytes(), true);
        assertFalse(card2.verifyCertificate());

        try {
            card2.authenticateWithPIN(("1234"));
            assertTrue(false);
        } catch (CardVerificationException ignored) {
            // should go here, because root certificates of reader3
            // cannot anchor the certificate chain in the  QR code ID
        }
    }

    @Test
    public void testcreateCardWithNoCertificates()
            throws IOException, IDPassException {

        IDPassReader reader = new IDPassReader(m_keyset, null);

        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
        Ident ident = newIdentBuilder().setPhoto(ByteString.copyFrom(photo)).build();

        Card card = reader.newCard(ident, null);

        assertNotNull(card);
        assertTrue(card.asBytes().length > 0);

        reader.open(card.asBytes(), true);


        byte[] newEncryptionkey = IDPassHelper.generateEncryptionKey();
        byte[] newSignatureKey = IDPassHelper.generateSecretSignatureKey();
        byte[] newVerificationKey = Arrays.copyOfRange(newSignatureKey, 32, 64);

        //Test with new keys for everything
        KeySet newKeyset = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(newEncryptionkey))
                .setSignatureKey(ByteString.copyFrom(newSignatureKey))
                .addVerificationKeys(byteArray.newBuilder()
                        .setTyp(byteArray.Typ.ED25519PUBKEY)
                        .setVal(ByteString.copyFrom(newVerificationKey)).build())
                .build();

        IDPassReader reader2 = new IDPassReader(newKeyset, null);


        try {
            reader2.open(card.asBytes(), true);
            assertTrue(false);
        } catch (InvalidCardException ignored) {}


        // Test with the same signature key, but all the other keys are different
        newKeyset = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(newEncryptionkey))
                .setSignatureKey(ByteString.copyFrom(newSignatureKey))
                .addVerificationKeys(byteArray.newBuilder()
                        .setTyp(byteArray.Typ.ED25519PUBKEY)
                        .setVal(ByteString.copyFrom(publicVerificationKey)).build())
                .build();

        reader2 = new IDPassReader(newKeyset, null);

        reader2.open(card.asBytes(), true);
    }

    @Test
    public void testPinCode() throws IOException, IDPassException {
        IDPassReader reader = new IDPassReader(m_keyset, null);
        Card card = newTestCard(reader);

        try {
            card.authenticateWithPIN("0000");
            assertTrue(false);
        } catch (CardVerificationException e) {}

        try {
            card.authenticateWithPIN("1234");
        } catch (CardVerificationException e) {
            assertTrue(false);
        }
    }

    @Test
    public void testDataVisibility() throws IOException, IDPassException {
        IDPassReader reader = new IDPassReader(m_keyset, null);
        Card card = newTestCard(reader);

        assertEquals(0, card.getGivenName().length());
        assertEquals(0, card.getSurname().length());
        assertNull(card.getDateOfBirth());
        assertEquals(0, card.getPlaceOfBirth().length());

        try {
            card.authenticateWithPIN("1234");
        } catch (CardVerificationException e) {
            assertTrue(false);
        }
        assertEquals("John", card.getGivenName());
        assertEquals("Doe", card.getSurname());
        assertEquals("Aubusson, France", card.getPlaceOfBirth());
        assertNotNull(card.getDateOfBirth());
    }

    @Test
    public void testDataVisibility2() throws IOException, IDPassException {
        IDPassReader reader = new IDPassReader(m_keyset, null);

        reader.setDetailsVisible(
                IDPassReader.DETAIL_GIVENNAME |
                        IDPassReader.DETAIL_PLACEOFBIRTH);

        Card card = newTestCard(reader);

        assertEquals("John", card.getGivenName());
        assertEquals(0, card.getSurname().length());
        assertNull(card.getDateOfBirth());
        assertEquals("Aubusson, France", card.getPlaceOfBirth());


        try {
            card.authenticateWithPIN("1234");
        } catch (CardVerificationException e) {
            assertTrue(false);
        }
        assertEquals("John", card.getGivenName());
        assertEquals("Doe", card.getSurname());
        assertEquals("Aubusson, France", card.getPlaceOfBirth());
        assertEquals(17, card.getDateOfBirth().getDate());
        assertEquals(12, card.getDateOfBirth().getMonth() + 1);
        assertEquals(1980, card.getDateOfBirth().getYear() + 1900);
    }

    @Test
    public void testFace() throws IOException, IDPassException {
        IDPassReader reader = new IDPassReader(m_keyset, null);

        Card card = newTestCard(reader);
        try {
            byte[] photo = Files.readAllBytes(Paths.get("testdata/brad.jpg"));
            card.authenticateWithFace(photo);
            assertTrue(false);
        } catch (CardVerificationException e) {}

        try {
            byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
            card.authenticateWithFace(photo);
        } catch (CardVerificationException e) {
            assertTrue(false);
        }

        //reset the card
        card = newTestCard(reader);
        try {
            byte[] photo = Files.readAllBytes(Paths.get("testdata/manny4.jpg"));
            card.authenticateWithFace(photo);
        } catch (CardVerificationException e) {
            assertTrue(false);
        }
    }

    @Test
    public void testFaceStrictThreshold() throws IOException, IDPassException {
        IDPassReader reader = new IDPassReader(m_keyset, null);
        //try with a very strict threshold, so even Manny does not match with Manny
        Card card = newTestCard(reader);
        reader.setFaceDiffThreshold(0.1f);
        assertEquals(reader.getFaceDiffThreshold(), 0.1f);

        try {
            byte[] photo = Files.readAllBytes(Paths.get("testdata/manny4.jpg"));
            card.authenticateWithFace(photo);
            assertTrue(false);
        } catch (CardVerificationException e) {
        }

    }

    @Test
    public void testFaceRelaxedThreshold() throws IOException, IDPassException {
        IDPassReader reader = new IDPassReader(m_keyset, null);
        //reset the card
        //try with a very relaxed threshold so it confuse brad with Manny
        Card card = newTestCard(reader);
        reader.setFaceDiffThreshold(0.9f);
        try {
            byte[] photo = Files.readAllBytes(Paths.get("testdata/brad.jpg"));
            card.authenticateWithFace(photo);
        } catch (CardVerificationException e) {
            assertTrue(false);
        }

    }

    @Test
    public void testPublicKey() throws IOException, IDPassException {
        IDPassReader reader = new IDPassReader(m_keyset, null);
        Card card = newTestCard(reader);

        try {
            card.getPublicKey();
            assertTrue(false);
        } catch (NotVerifiedException e) {
        }

        card.authenticateWithPIN("1234");

        try {
            byte[] key = card.getPublicKey();
            assertEquals(32, key.length);
        } catch (NotVerifiedException e) {
            assertTrue(false);
        }
    }

    @Test
    public void testGetQRCode() throws IOException, IDPassException, NotFoundException {
        IDPassReader reader = new IDPassReader(m_keyset, null);
        reader.setQrImageScanner(qrImageScanner);
        Card card = newTestCard(reader);

        BufferedImage qrCode = card.asQRCode();
        assertTrue(qrCode.getHeight() > 50);
        assertTrue(qrCode.getWidth() > 50);

        Card readCard = reader.open(qrCode, true); // HERE
        assertNotNull(readCard);
        assertArrayEquals(card.asBytes(), readCard.asBytes());
    }

    @Test
    public void testCardWrongPublicSignatureVerification()
            throws IOException,  IDPassException {
        byte[] encryptionkey    = IDPassHelper.generateEncryptionKey();
        byte[] signaturekey     = IDPassHelper.generateSecretSignatureKey();
        byte[] wrongVerificationkey = Arrays.copyOfRange(IDPassHelper.generateSecretSignatureKey(),32,64);

        IDPassReader reader = new IDPassReader(m_keyset, m_rootcerts);

        Card card = newTestCard(reader, m_certchain);

        KeySet ks2 = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(encryptionkey))
                .setSignatureKey(ByteString.copyFrom(signaturekey))
                .addVerificationKeys(byteArray.newBuilder()
                        .setTyp(byteArray.Typ.ED25519PUBKEY)
                        .setVal(ByteString.copyFrom(wrongVerificationkey)).build())
                .build();

        IDPassReader reader2 = new IDPassReader(ks2, m_rootcerts);

        try {
            Card card2 = reader2.open(card.asBytes());
        } catch (IDPassException e) {
            assertTrue(false); // HERE
        }
    }

    //TODO: Modify manually a card to make this test work
//    @Test
//    public void testCardWrongPrivateSignatureVerification()
//            throws IOException, IDPassException {
//        byte[] encryptionkey    = IDPassHelper.generateEncryptionKey();
//        byte[] signaturekey     = IDPassHelper.generateSecretSignatureKey();
//        byte[] wrongVerificationkey = Arrays.copyOfRange(IDPassHelper.generateSecretSignatureKey(),32,64);
//
//        IDPassReader reader = new IDPassReader(encryptionkey, signaturekey);
//
//        Card card = newTestCard(reader);
//
//        byte[][] wrongVerificationkeys = new byte[1][];
//        wrongVerificationkeys[0] = wrongVerificationkey;
//        reader = new IDPassReader(encryptionkey, signaturekey, wrongVerificationkeys);
//
//        Card newCard = reader.open(card.asBytes());
//
//        try {
//            newCard.authenticateWithPIN("1234");
//            assertTrue(false);
//        } catch (CardVerificationException e) {
//        }
//    }

    @Test
    public void testCardSignatureVerification()
            throws IOException, IDPassException {
        byte[] encryptionkey    = IDPassHelper.generateEncryptionKey();
        byte[] signaturekey     = IDPassHelper.generateSecretSignatureKey();
        byte[] otherVerificationkey = Arrays.copyOfRange(IDPassHelper.generateSecretSignatureKey(),32,64);

        KeySet.Builder ksBuilder = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(encryptionkey))
                .setSignatureKey(ByteString.copyFrom(signaturekey));

        KeySet ks = ksBuilder.addVerificationKeys(byteArray.newBuilder()
                .setTyp(byteArray.Typ.ED25519PUBKEY)
                .setVal(ByteString.copyFrom(otherVerificationkey)))
                .build();

        // reader is created with rootcerts
        IDPassReader reader = new IDPassReader(m_keyset, m_rootcerts);

        // card is created with intermedcerts
        Card card = newTestCard(reader, m_certchain);

        KeySet ks1 = ksBuilder.addVerificationKeys(byteArray.newBuilder()
                        .setTyp(byteArray.Typ.ED25519PUBKEY)
                        .setVal(ByteString.copyFrom(otherVerificationkey))).build();

        // reader2 created with different keyset from reader1
        IDPassReader reader2 = new IDPassReader(ks1, m_rootcerts);

        Card newCard = null;

        try {
            // card created in reader1 can be open by reader2 even if
            // they don't have same keyset.
            newCard = reader2.open(card.asBytes());
        } catch (IDPassException e) {
            assertFalse(true); // HERE
        }
    }

    @Test
    public void testCardEncryptDecrypt()
            throws IDPassException, IOException, NotVerifiedException
    {
        IDPassReader reader = new IDPassReader(m_keyset, null);
        Card card = newTestCard(reader);
        String msg = "attack at dawn!";
        byte[] encrypted = new byte[0];

        try {
            encrypted = card.encrypt(msg.getBytes());
            assertFalse(true);
        } catch (NotVerifiedException e) {

        }

        card.authenticateWithPIN("1234");

        try {
            encrypted = card.encrypt(msg.getBytes());
            assertTrue(encrypted.length > 1);
        } catch (NotVerifiedException e) {
            assertFalse(true);
        }

        String decrypted = new String(card.decrypt(encrypted));
        assertEquals(decrypted, msg);
    }

    @Test
    public void testBasicFlow()
            throws IOException, IDPassException
    {
        byte[] encryptionKey = IDPassReader.generateEncryptionKey();
        byte[] signatureKey = IDPassReader.generateSecretSignatureKey();

        /* Initialize a key set */

        KeySet keySet = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(encryptionKey))
                .setSignatureKey(ByteString.copyFrom(signatureKey))
                .build();

        /* Optional: Prepare list of root certificates */

        byte[] rootKey1 = IDPassReader.generateSecretSignatureKey();
        byte[] rootKey2 = IDPassReader.generateSecretSignatureKey();

        Certificate rootCert1 = IDPassReader.generateRootCertificate(rootKey1);
        Certificate rootCert2 = IDPassReader.generateRootCertificate(rootKey2);

        Certificates rootCerts = Certificates.newBuilder()
                .addCert(rootCert1)
                .addCert(rootCert2)
                .build();

        /*
        Optional: Prepare list of intermediate certificates. The leaf certificate's
        public key should be of the signature key from key set
         */

        byte[] intermedKey1 = IDPassReader.generateSecretSignatureKey();
        Certificate intermedCert1 = IDPassReader.generateChildCertificate(rootKey1,
                Arrays.copyOfRange(intermedKey1, 32, 64));

        Certificate intermedCert2 = IDPassReader.generateChildCertificate(intermedKey1,
                Arrays.copyOfRange(signatureKey, 32, 64));

        Certificates intermedCerts = Certificates.newBuilder()
                .addCert(intermedCert1)
                .addCert(intermedCert2)
                .build();

        /*
        Initialize the library via an IDPassReader instance with mandatory key set and an
        optional root certificates
         */

        IDPassReader reader = new IDPassReader(keySet, rootCerts);

        /* Fill-up personal details of an identity to register */

        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
        Ident ident = Ident.newBuilder()
                .setGivenName("John")
                .setSurName("Doe")
                .setPin("1234")
                .setPlaceOfBirth("Aubusson, France")
                .setDateOfBirth(Date.newBuilder().setYear(1980).setMonth(12).setDay(17))
                .setPhoto(ByteString.copyFrom(photo))
                .addPubExtra(Pair.newBuilder().setKey("gender").setValue("male").setKey("height").setValue("5.4ft"))
                .addPrivExtra(Pair.newBuilder().setKey("blood type").setValue("A"))
                .build();

        /*
        Create an identity card for ident with intermediate certificates. This ID card can be
        rendered as a QR code.
         */

        Card card = reader.newCard(ident, intermedCerts);
        assertTrue(card.verifyCertificate());
    }

    @Test
    public void testMinimalCompleteFlow()
            throws IOException, IDPassException, NotFoundException
    {
        byte[] encryptionKey = IDPassReader.generateEncryptionKey();
        byte[] signatureKey = IDPassReader.generateSecretSignatureKey();

        /* Initialize a key set */

        KeySet keySet = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(encryptionKey))
                .setSignatureKey(ByteString.copyFrom(signatureKey))
                .build();

        /* Initialize the library via an IDPassReader instance with mandatory key set */

        IDPassReader reader = new IDPassReader(keySet, null);
        reader.setQrImageScanner(qrImageScanner);

        /* Fill-up personal details of an identity to register */

        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
        Ident ident = Ident.newBuilder()
                .setGivenName("John")
                .setSurName("Doe")
                .setPin("1234")
                .setPlaceOfBirth("Aubusson, France")
                .setDateOfBirth(Date.newBuilder().setYear(1980).setMonth(12).setDay(17))
                .setPhoto(ByteString.copyFrom(photo))
                .addPubExtra(Pair.newBuilder().setKey("gender").setValue("male").setKey("height").setValue("5.4ft"))
                .addPrivExtra(Pair.newBuilder().setKey("blood type").setValue("A").setKey("place").setValue("Shell Beach"))
                .build();

        /*
        Create an identity card for ident with intermediate certificates. This ID card can be
        rendered as a QR code.
         */

        Card card = reader.newCard(ident, null);

        /* Render the identity card as a QR code image */

        BufferedImage qrCode = card.asQRCode();

        /* Read the QR code image as an identity card */

        Card c = reader.open(qrCode, true); // HERE

        /* Authenticate identity card with somebody else photo should fail */
        byte[] photo_brad = Files.readAllBytes(Paths.get("testdata/brad.jpg"));

        try {
            c.authenticateWithFace(photo_brad);
            assertFalse(true);
        } catch (CardVerificationException e) {
        }

        /* Authenticate identity card with owner's photo should succeed */

        try {
            c.authenticateWithFace(photo);
            assertEquals(c.getGivenName(),"John");
        } catch (CardVerificationException e) {
            assertFalse(true);
        }
    }

    @Test
    public void testRevokedCertificate() throws IDPassException
    {
        /* Prepare the key set */

        byte[] encryptionKey = IDPassReader.generateEncryptionKey();
        byte[] signatureKey = IDPassReader.generateSecretSignatureKey();

        KeySet keySet = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(encryptionKey))
                .setSignatureKey(ByteString.copyFrom(signatureKey))
                .build();

        /* Prepare the root certificates list */

        byte[] rootKey = IDPassReader.generateSecretSignatureKey();
        Certificate rootCert1 = IDPassReader.generateRootCertificate(rootKey);
        Certificates rootCerts = Certificates.newBuilder()
                                    .addCert(rootCert1)
                                    .build();

        /* Prepare the intermediate certificates */

        byte[] intermedKey1 = IDPassReader.generateSecretSignatureKey();
        Certificate intermedCert1 = IDPassReader.generateChildCertificate(rootKey,
                Arrays.copyOfRange(intermedKey1, 32, 64));
        Certificate intermedCert2 = IDPassReader.generateChildCertificate(intermedKey1, publicVerificationKey);
        Certificates intermedCerts = Certificates.newBuilder()
                                        .addCert(intermedCert1)
                                        .addCert(intermedCert2)
                                        .build();

        IDPassReader reader = new IDPassReader(keySet, rootCerts);

        assertTrue(reader.addIntermediateCertificates(intermedCerts));

        IDPassReader.addRevokedKey(Arrays.copyOfRange(intermedKey1, 32, 64));
        assertFalse(reader.addIntermediateCertificates(intermedCerts));
    }

    @Test
    public void testCardSignVerify() throws IOException, IDPassException, NotVerifiedException {
        String msg = "attack at dawn!";
        IDPassReader reader = new IDPassReader(m_keyset, null);

        Card card = newTestCard(reader);
        card.authenticateWithPIN("1234"); // needs to auth first before can sign

        byte[] signature = card.sign(msg.getBytes());
        assertTrue(signature.length == 64);

        assertTrue(card.verify(msg.getBytes(), signature,card.getPublicKey()));
        String tampered = "attack at dawn";
        assertFalse(card.verify(tampered.getBytes(), signature, card.getPublicKey()));

        IDPassReader reader2 = new IDPassReader(m_keyset2, null);
        Card card2 = newTestCard(reader2);
        card2.authenticateWithPIN("1234");
        assertTrue(card2.verify(msg.getBytes(), signature, card.getPublicKey()));

        signature = card2.sign(msg.getBytes());
        assertTrue(signature.length == 64);

        assertTrue(card2.verify(msg.getBytes(), signature,card2.getPublicKey()));
        assertTrue(card.verify(msg.getBytes(), signature,card2.getPublicKey()));
    }

    @Disabled("This is only used for generating QR code images for debugging purposes")
    @Test
    public void testSaveQRcode() throws IDPassException, IOException {

        IDPassReader reader = new IDPassReader(m_keyset, m_rootcerts);
        Card card = newTestCard(reader, m_certchain);
        File outputfile = new File("testqr2.jpg");
        ImageIO.write(card.asQRCode(), "jpg", outputfile);

        reader.saveConfiguration("test", "reader1.cfg", "changeit");

        IDPassHelper.writeKeyStoreEntry(
            "rootcertificatesprivatekeys","reader1.cfg.p12", "changeit", m_rootkey);

        IDPassHelper.writeKeyStoreEntry(
            "intermedcertificatesprivatekeys","reader1.cfg.p12", "changeit", signaturekey);
    }

    /*
    The below test cases reads from the file system for
    testing purposes in order to persist keyset and
    certificates used to open a QR code ID
    later on
     */

    @Test
    public void test_read_id_without_certificate()
            throws IDPassException, IOException, NotFoundException
    {
        // Load the keyset of the reader used to create the card
        byte[] ks = Files.readAllBytes(Paths.get("testdata/keyset.dat"));
        KeySet keyset = KeySet.parseFrom(ks);

        // Initialize reader with proper keyset
        IDPassReader reader = new IDPassReader(keyset, null);
        reader.setQrImageScanner(qrImageScanner);

        File qrcodeId = new File(String.valueOf(Paths.get("testdata/image.jpg")));
        BufferedImage bufferedImage = ImageIO.read(qrcodeId);

        // Read the QR code image
        Card cardOriginal = reader.open(bufferedImage);
        cardOriginal.authenticateWithPIN("1234");
        String name = cardOriginal.getGivenName();
        assertEquals(name,"John");
    }

    @Test
    public void test_read_id_with_certificate()
            throws IDPassException, IOException, NotFoundException
    {
        // Load the keyset of the reader used to create the card
        byte[] ks = Files.readAllBytes(Paths.get("testdata/testkeyset.dat"));
        KeySet keyset = KeySet.parseFrom(ks);

        // Load the root certs of the reader used to created the card
        byte[] rootcertsbuf = Files.readAllBytes(Paths.get("testdata/testrootcerts.dat"));
        Certificates rootcerts = Certificates.parseFrom(rootcertsbuf );

        // Initialize reader
        IDPassReader reader = new IDPassReader(keyset, rootcerts);
        reader.setQrImageScanner(qrImageScanner);

        File qrcodeId = new File(String.valueOf(Paths.get("testdata/card_with_cert.jpg")));
        BufferedImage bufferedImage = ImageIO.read(qrcodeId);

        // Read the QR code image
        Card cardOriginal = reader.open(bufferedImage); // presence of correct root certs is only up to here

        // hereafter, correct keyset is necessary to be able to operate on the card

        cardOriginal.authenticateWithPIN("1234"); // Now, this one needs correct keyset to work
        String name = cardOriginal.getGivenName();
        assertEquals(name,"John");
    }

    @Test
    public void test_read_id_with_certificate_reader_config()
            throws IOException, NotFoundException
    {
        try {
            // Initialize reader
            IDPassReader reader = new IDPassReader("default", "testdata/reader.cfg.p12", "changeit");
            reader.setQrImageScanner(qrImageScanner);

            File qrcodeId = new File(String.valueOf(Paths.get("testdata/testqr1.jpg")));
            BufferedImage bufferedImage = ImageIO.read(qrcodeId);

            // Read the QR code image
            Card cardOriginal = reader.open(bufferedImage); // presence of correct root certs is only up to here

            // hereafter, correct keyset is necessary to be able to operate on the card

            cardOriginal.authenticateWithPIN("1234"); // Now, this one needs correct keyset to work
            String name = cardOriginal.getGivenName();
            assertEquals(name, "John");
        } catch (IDPassException e) {
            assertFalse(true);
        }
    }

    @Test
    public void test_read_p12_inputstream()
            throws IOException, NotFoundException
    {
        try {
            File p12File = new File("testdata/reader.cfg.p12");
            InputStream is = new FileInputStream(p12File);
            // Initialize reader
            IDPassReader reader = new IDPassReader("default", is, "changeit", "changeit");
            reader.setQrImageScanner(qrImageScanner);

            File qrcodeId = new File(String.valueOf(Paths.get("testdata/testqr1.jpg")));
            BufferedImage bufferedImage = ImageIO.read(qrcodeId);

            // Read the QR code image
            Card cardOriginal = reader.open(bufferedImage); // presence of correct root certs is only up to here

            // hereafter, correct keyset is necessary to be able to operate on the card

            cardOriginal.authenticateWithPIN("1234"); // Now, this one needs correct keyset to work
            String name = cardOriginal.getGivenName();
            assertEquals(name, "John");
        } catch (IDPassException e) {
            assertFalse(true);
        }
    }

    @Test
    public void test_dlib_function() throws IOException
    {
        try {
            byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
            IDPassReader reader = new IDPassReader("default", "testdata/reader.cfg.p12", "changeit");
            byte[] dimensions = reader.getFaceTemplate(photo, true);
            assertTrue(dimensions.length == 128 * 4);
            dimensions = reader.getFaceTemplate(photo, false);
            assertTrue(dimensions.length == 64 * 2);

            float threshold = reader.getFaceDiffThreshold();

            byte[] photo2 = Files.readAllBytes(Paths.get("testdata/manny2.bmp"));

            byte[] tmpl1 = reader.getFaceTemplate(photo, false);
            byte[] tmpl2 = reader.getFaceTemplate(photo2, false);
            float fdif = IDPassReader.compareFaceTemplates(tmpl1, tmpl2);
            assertTrue(fdif <= threshold);
        } catch (IDPassException e) {
            assertFalse(true);
        }
    }

    @Test
    public void test_verify_florence_id()
        throws IDPassException, IOException, NotFoundException
    {
        // photo1 and photo3 are Florence personal photos
        byte[] photo1 = Files.readAllBytes(Paths.get("testdata/florence_ID_Photo.jpg")); // high res
        byte[] photo3 = Files.readAllBytes(Paths.get("testdata/florence.jpg")); // low res
        byte[] asian0 = Files.readAllBytes(Paths.get("testdata/faces/asian0.jpg")); 
        String ssNumber = "SS Number";
        String ssNumberValue = "2 85 01 75 116 001 42";

        // First, we initialize the reader with the corresponding issuing keys that issued the QR code
        // ID florence_idpass.png card
        IDPassReader reader = new IDPassReader("default", "testdata/demokeys.cfg.p12","changeit");
        reader.setQrImageScanner(qrImageScanner);

        // Next, we prepare the QR code for reading. This is just a standard Java image load
        BufferedImage qrCodeImage = ImageIO.read(
            new File(String.valueOf(Paths.get("testdata/florence_idpass.png"))));

        // The reader scans the card to check if it is a QR code. The QR code public area
        // is read out and if there is presence of certificate(s), then it is validated against that
        // of the root certificate(s) of the reader. If the certificate validates, the reader::open()
        // method returns a Card. The card's public region should be publicly visible. Whereas,
        // its private region shall only be visible after successfull authentication.
        Card card0 = reader.open(qrCodeImage); // presence of correct root certs is only up to here

        assertEquals("MARION FLORENCE", card0.getGivenName());
        assertEquals("DUPONT", card0.getSurname());

        // After opening but prior to authentication, ssNumber field is not visible
        HashMap<String, String> card0Info = card0.getCardExtras();
        assertFalse(card0Info.containsKey(ssNumber));

        // Other person's face is not able to authenticate using Florence card0 ID card
        assertThrows(IDPassException.class,
            () -> card0.authenticateWithFace(asian0));

        // Because, card0 is still not authenticated, ssNumber is still not visible
        assertFalse(card0Info.containsKey(ssNumber));

        // Now let us successfully authenticate using Florence's lower resolution photo
        card0.authenticateWithFace(photo3);

        // Once authenticated, the ssNumber field in card0 shall be visible
        assertEquals("MARION FLORENCE",card0.getGivenName());
        assertTrue(card0Info.containsKey(ssNumber) &&
            card0Info.get(ssNumber).equals(ssNumberValue));

        // The card can also be verified by pin code. We scan again the qrCodeImage
        // to return another card3 and authenticate against card3 via pin code
        Card card3 = reader.open(qrCodeImage);

        // Prior to authentication, ssNumber shall not be visible
        HashMap<String, String> card3Info = card3.getCardExtras();
        assertFalse(card3Info.containsKey(ssNumber));

        // Successful pin code authentication on card3, shall make visible
        // the ssNumber field
        card3.authenticateWithPIN("1234");
        assertTrue(card3Info.containsKey(ssNumber) &&
                card3Info.get(ssNumber).equals(ssNumberValue));

        // Let us read the same QR code ID using a reader that is initialized with entirely different keys
        IDPassReader reader2 = new IDPassReader("default", "testdata/reader.cfg.p12","changeit");
        reader2.setQrImageScanner(qrImageScanner);

        // Because reader2 has different keys configuration,
        // then it is not able to render (or open) the QR code ID into a card
        assertThrows(InvalidCardException.class,
            () -> { Card card4 = reader2.open(qrCodeImage); });

        // However, reader2 can open the card (or render the QR code into a card)
        // if the reader skips certificate verification
        Card card5 = reader2.open(qrCodeImage, true);

        // A rendered or opened card (but not yet authenticated)
        // shall have its public fields always visible
        assertEquals("MARION FLORENCE", card5.getGivenName());
        assertEquals("DUPONT", card5.getSurname());

        // But, without being authenticated, its private field, such as ssNumber, is not visible
        HashMap<String, String> card5Info = card5.getCardExtras();
        assertFalse(card5Info.containsKey(ssNumber));

        // Because the reader2 has an entirely different keys configuration,
        // no successfull authentication is possible using reader2,
        // even if matching photo or pin code is presented.
        assertThrows(CardVerificationException.class,
            () -> card5.authenticateWithFace(photo1));

        assertThrows(CardVerificationException.class,
            () -> card5.authenticateWithPIN("1234"));

        // So using reader2, ssNumber is never visible
        assertFalse(card5Info.containsKey(ssNumber));

        // This time, let us initialize the reader with proper root certificate only
        // but with a different keyset. Let us recall, the keyset is the set of keys:
        // - encryption key
        // - secret signature key
        // - verification keys

        // First, let us copy the root key from our previous reader object to reconstruct 
        // the proper root certificate(s)
        byte[][] ret = IDPassHelper.readKeyStoreEntry(
                "rootcertificatesprivatekeys","testdata/demokeys.cfg.p12", "changeit");

        Certificate rootcert = IDPassReader.generateRootCertificate(ret[0]);
        Certificates rootcerts = Certificates.newBuilder().addCert(rootcert).build();

        // Using the root certificate(s) from a previous reader and combined with a different keyset, let us
        // initialize a new reader3 instance
        IDPassReader reader3 = new IDPassReader(m_keyset, rootcerts);
        reader3.setQrImageScanner(qrImageScanner);

        // Because reader3 is initialized with proper root certificate(s),
        // it is able to open (or render) the QR code into a Card.
        Card card6 = reader3.open(qrCodeImage);

        // A succesfully opened (or rendered) card has its public fields visible. 
        // But prior to authentication, the private field ssNumber is not visible
        assertEquals("MARION FLORENCE", card6.getGivenName());
        assertEquals("DUPONT", card6.getSurname());
        HashMap<String, String> card6Info = card6.getCardExtras();
        assertFalse(card6Info.containsKey(ssNumber)); // not visible

        // Now let us attempt to authenticate using Florence's photo.
        // Because reader3 is not initialized with the matching keyset, then
        // authentication is not possible even with matching photo
        assertThrows(CardVerificationException.class,
                () -> card6.authenticateWithFace(photo1));

        // Authentication is also not possible even with correct pin code
        assertThrows(CardVerificationException.class,
                () -> card6.authenticateWithPIN("1234"));

        // Because card6 is not authenticated, the ssNumber is not visible
        assertFalse(card6Info.containsKey(ssNumber));
    }

    @Test
    public void test_generate_scaled_idpass() throws IOException, IDPassException, NotFoundException {

        byte[] photo = Files.readAllBytes(Paths.get("testdata/florence.jpg"));

        Ident ident = Ident.newBuilder()
                .setPhoto(ByteString.copyFrom(photo))
                .setGivenName("MARION FLORENCE")
                .setSurName("DUPONT")
                .setPin("1234")
                .setDateOfBirth(Date.newBuilder().setYear(1985).setMonth(1).setDay(1))
                .addPubExtra(Pair.newBuilder().setKey("Sex").setValue("F"))
                .addPubExtra(Pair.newBuilder().setKey("Nationality").setValue("French"))
                .addPubExtra(Pair.newBuilder().setKey("Date Of Issue").setValue("02 JAN 2025"))
                .addPubExtra(Pair.newBuilder().setKey("Date Of Expiry").setValue("01 JAN 2035"))
                .addPubExtra(Pair.newBuilder().setKey("ID").setValue("SA437277"))
                .addPrivExtra(Pair.newBuilder().setKey("SS Number").setValue("2 85 01 75 116 001 42"))
                .build();

        IDPassReader reader = new IDPassReader(m_keyset, m_rootcerts);
        reader.setQrImageScanner(qrImageScanner);

        reader.setDetailsVisible(
                IDPassReader.DETAIL_GIVENNAME |
                IDPassReader.DETAIL_SURNAME |
                IDPassReader.DETAIL_DATEOFBIRTH |
                IDPassReader.DETAIL_PLACEOFBIRTH);

        File tempFile = File.createTempFile("idpasslite", ".png");

        Card card = reader.newCard(ident,m_certchain);

        BufferedImage ri = card.asQRCode();
        ImageIO.write(ri, "png", tempFile);

        BufferedImage qrimage = ImageIO.read(tempFile);
        Card idcard = reader.open(qrimage); 
        idcard.authenticateWithPIN("1234");
        assertEquals("MARION FLORENCE", idcard.getGivenName());
        tempFile.delete();
    }

    @Test
    public void test_generate_svg() throws IDPassException, IOException, NotFoundException {

        byte[] photo = Files.readAllBytes(Paths.get("testdata/florence_ID_Photo.jpg"));

        Ident ident = Ident.newBuilder()
                .setPhoto(ByteString.copyFrom(photo))
                .setGivenName("MARION FLORENCE")
                .setSurName("DUPONT")
                .setPin("1234")
                .setDateOfBirth(Date.newBuilder().setYear(1985).setMonth(1).setDay(1))
                .addPubExtra(Pair.newBuilder().setKey("Sex").setValue("F"))
                .addPubExtra(Pair.newBuilder().setKey("Nationality").setValue("French"))
                .addPubExtra(Pair.newBuilder().setKey("Date Of Issue").setValue("02 JAN 2025"))
                .addPubExtra(Pair.newBuilder().setKey("Date Of Expiry").setValue("01 JAN 2035"))
                .addPubExtra(Pair.newBuilder().setKey("ID").setValue("SA437277"))
                .addPrivExtra(Pair.newBuilder().setKey("SS Number").setValue("2 85 01 75 116 001 42"))
                .build();

        IDPassReader reader = new IDPassReader(m_keyset, m_rootcerts);
        reader.setQrImageScanner(qrImageScanner);

        reader.setDetailsVisible(
                IDPassReader.DETAIL_GIVENNAME |
                IDPassReader.DETAIL_SURNAME);

        Card card = reader.newCard(ident,m_certchain);

        // Load SVG to BufferedImage and feed image into reader
        // to create card2
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = card.asQRCodeSVG().getBytes(StandardCharsets.UTF_8);
        bos.write(buf, 0, buf.length);

        InputStream inputStream = new ByteArrayInputStream(bos.toByteArray());
        BufferedImage bi = ImageIO.read(inputStream);

        Card card2 = reader.open(bi);
        assertNotNull(card2);
        assertArrayEquals(card.asBytes(), card2.asBytes());
        assertTrue(card2.getGivenName().equals("MARION FLORENCE"));
    }

    @Test
    public void test_jgenerate_florence_id() throws IDPassException, IOException {

        byte[] photo = Files.readAllBytes(Paths.get("testdata/florence_ID_Photo.jpg"));

        Ident ident = Ident.newBuilder()
                .setPhoto(ByteString.copyFrom(photo))
                .setGivenName("MARION FLORENCE")
                .setSurName("DUPONT")
                .setPin("1234")
                .setDateOfBirth(Date.newBuilder().setYear(1985).setMonth(1).setDay(1))
                .addPubExtra(Pair.newBuilder().setKey("Sex").setValue("F"))
                .addPubExtra(Pair.newBuilder().setKey("Nationality").setValue("French"))
                .addPubExtra(Pair.newBuilder().setKey("Date Of Issue").setValue("02 JAN 2025"))
                .addPubExtra(Pair.newBuilder().setKey("Date Of Expiry").setValue("01 JAN 2035"))
                .addPubExtra(Pair.newBuilder().setKey("ID").setValue("SA437277"))
                .addPrivExtra(Pair.newBuilder().setKey("SS Number").setValue("2 85 01 75 116 001 42"))
                .build();

        IDPassReader reader = new IDPassReader("default", "testdata/demokeys.cfg.p12","changeit");

        reader.setDetailsVisible(
                IDPassReader.DETAIL_GIVENNAME |
                IDPassReader.DETAIL_SURNAME |
                IDPassReader.DETAIL_DATEOFBIRTH);

        byte[][] ret = IDPassHelper.readKeyStoreEntry(
                "rootcertificatesprivatekeys", "testdata/demokeys.cfg.p12", "changeit");
        byte[] root_key = ret[0];

        ret = IDPassHelper.readKeyStoreEntry(
                "intermedcertificatesprivatekeys", "testdata/demokeys.cfg.p12", "changeit");
        byte[] intermed_key = ret[0];

        byte[] verification_key = Arrays.copyOfRange(intermed_key, 32, 64);
        Certificate childcert = IDPassReader.generateChildCertificate(root_key, verification_key);
        Certificates certchain = Certificates.newBuilder().addCert(childcert).build();

        Card card = reader.newCard(ident,certchain);
        card.saveToPNG("florence_idpass.png");
        card.saveToSVG("florence_idpass.svg");
    }

    @Test
    public void testNewProtobufFields() throws IDPassException, IOException {

        PostalAddress address = PostalAddress.newBuilder()
                .addAddressLines("526 N Plymouth Blvd")
                .addAddressLines("Los Angeles, CA US")
                .setRegionCode("5")
                .setLanguageCode("en")
                .setPostalCode("90004")
                .build();

        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));

        Ident ident = Ident.newBuilder()
                .setPhoto(ByteString.copyFrom(photo))
                .setGivenName("Manny")
                .setSurName("Pacquiao")
                .setPin("1234")
                .setPlaceOfBirth("Bukidnon, Philippines")
                .setDateOfBirth(Date.newBuilder().setYear(1978).setMonth(12).setDay(17))
                .addPubExtra(Pair.newBuilder().setKey("gender").setValue("male").setKey("height").setValue("5.5ft"))
                .addPrivExtra(Pair.newBuilder().setKey("blood type").setValue("O"))
                .setFullName("Manny Pacquiao")
                .setUIN("4957694814")
                .setGender(2)
                .setPostalAddress(address)
                .build();

        byte[] buff = ident.toByteArray();
        int n = buff.length;

        IDPassReader reader = new IDPassReader(m_keyset, null);
        Card card = reader.newCard(ident, null);

        PostalAddress addr = card.getPostalAddress();
        assertNull(addr, "Because postalAddress is private by default and not yet authenticated");
        assertNull(card.getUIN(), "Because UIN is private by default and not yet authenticated");

        card.authenticateWithPIN("1234");

        addr = card.getPostalAddress();
        assertNotNull(addr, "postalAddress now visible after success authentication");
        assertEquals(card.getUIN(), "4957694814");
    }

    @Test
    public void testVisibilityFlags()
        throws IDPassException, IOException
    {
        PostalAddress address = PostalAddress.newBuilder()
                .addAddressLines("526 N Plymouth Blvd")
                .addAddressLines("Los Angeles, CA US")
                .setRegionCode("5")
                .setLanguageCode("en")
                .setPostalCode("90004")
                .build();

        byte[] photo = Files.readAllBytes(Paths.get("testdata/florence_ID_Photo.jpg"));

        Ident ident = Ident.newBuilder()
                .setUIN("314159")
                .setPhoto(ByteString.copyFrom(photo))
                .setGivenName("MARION FLORENCE")
                .setSurName("DUPONT")
                .setFullName("MRS. MARION FLORENCE DUPONT")
                .setGender(1)
                .setPin("1234")
                .setDateOfBirth(Date.newBuilder().setYear(1985).setMonth(1).setDay(1))
                .setPlaceOfBirth("Paris, France")
                .addPubExtra(Pair.newBuilder().setKey("Nationality").setValue("French"))
                .addPubExtra(Pair.newBuilder().setKey("Date Of Issue").setValue("02 JAN 2025"))
                .addPubExtra(Pair.newBuilder().setKey("Date Of Expiry").setValue("01 JAN 2035"))
                .addPubExtra(Pair.newBuilder().setKey("ID").setValue("SA437277"))
                .addPrivExtra(Pair.newBuilder().setKey("SS Number").setValue("2 85 01 75 116 001 42"))
                .setPostalAddress(address)
                .build();

        IDPassReader reader = new IDPassReader(m_keyset, null);

        reader.setDetailsVisible(
                IDPassReader.DETAIL_GIVENNAME |
                IDPassReader.DETAIL_SURNAME |
                IDPassReader.DETAIL_DATEOFBIRTH |
                IDPassReader.DETAIL_PLACEOFBIRTH |
                IDPassReader.DETAIL_POSTALADDRESS);

        Card card = reader.newCard(ident, null);

        assertNotNull(card.getPostalAddress(), "Because DETAIL_POSTALADDRESS is set to visible");
        assertNull(card.getfullName(), "Because fullName is private and not yet authenticated");
        assertEquals(card.getPlaceOfBirth(),"Paris, France");
        assertEquals(card.getGivenName(),"MARION FLORENCE");
        assertEquals(card.getSurname(),"DUPONT");

        card.authenticateWithPIN("1234");

        assertEquals(card.getfullName(), "MRS. MARION FLORENCE DUPONT");
        assertNotNull(card.getPostalAddress(), "Because DETAIL_POSTALADDRESS is set to visible");
    }

    /**
     * Merge two CardDetails into one
     */

    @Test
    public void testMergeDetails() {
        CardDetails d1 = CardDetails.newBuilder()
                .setFullName("John Murdoch")
                .build();

        CardDetails d2 = CardDetails.newBuilder()
                .setGivenName("JOHN")
                .setSurName("MURDOCH")
                .build();

        CardDetails merged = IDPassHelper.mergeCardDetails(d1,d2);

        assertEquals(merged.getAllFields().keySet().size(), 3);
        assertEquals(merged.getFullName(), "John Murdoch");
        assertEquals(merged.getSurName(), "MURDOCH");
        assertEquals(merged.getGivenName(), "JOHN");

        merged = IDPassHelper.mergeCardDetails(d2,d1);

        assertEquals(merged.getAllFields().keySet().size(), 3);
        assertEquals(merged.getFullName(), "John Murdoch");
        assertEquals(merged.getSurName(), "MURDOCH");
        assertEquals(merged.getGivenName(), "JOHN");

        org.idpass.lite.proto.Date dob = org.idpass.lite.proto.Date.newBuilder()
                .setYear(1967)
                .setMonth(10)
                .setDay(29)
                .build();

        // Add dob into d1 CardDetails
        d1 = d1.toBuilder().setDateOfBirth(dob).build();
        merged = IDPassHelper.mergeCardDetails(d2,d1);

        assertEquals(merged.getAllFields().keySet().size(), 4);
        assertEquals(merged.getFullName(), "John Murdoch");
        assertEquals(merged.getSurName(), "MURDOCH");
        assertEquals(merged.getGivenName(), "JOHN");

        List<Pair> extras = new ArrayList<>();
        extras.add(Pair.newBuilder().setKey("Weight").setValue("152 lbs").build());
        extras.add(Pair.newBuilder().setKey("Hair Color").setValue("black").build());

        // Add extras to d1 CardDetails
        for (Pair x : extras) {
            d1 = d1.toBuilder().addExtra(x).build();
        }

        extras.clear();

        extras.add(Pair.newBuilder().setKey("Eye Color").setValue("Hazel").build());
        extras.add(Pair.newBuilder().setKey("Height").setValue("6 feet").build());
        extras.add(Pair.newBuilder().setKey("ID Type").setValue("Drivers' license").build());

        // Add extras to d2 CardDetails
        for (Pair x : extras) {
            d2 = d2.toBuilder().addExtra(x).build();
        }

        merged = IDPassHelper.mergeCardDetails(d1,d2);

        // Check if fields got merged
        assertEquals(merged.getAllFields().keySet().size(), 5);
        assertEquals(merged.getFullName(), "John Murdoch");
        assertEquals(merged.getSurName(), "MURDOCH");
        assertEquals(merged.getGivenName(), "JOHN");
        assertEquals(merged.getExtraCount(), d1.getExtraCount() + d2.getExtraCount());

        List<Pair> mergedExtras = Stream.concat(d1.getExtraList().stream(),
                d2.getExtraList().stream()).collect(Collectors.toList());

        for (Pair x : mergedExtras) {
            assertTrue(merged.getExtraList().contains(x));
        }
    }
}
