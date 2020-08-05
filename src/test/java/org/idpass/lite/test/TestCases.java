/*
 * Copyright 2020 Newlogic Impact Lab Pte. Ltd.
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
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.zxing.NotFoundException;
import org.api.proto.*;
import org.idpass.lite.IDPassHelper;
import org.idpass.lite.Card;
import org.idpass.lite.IDPassReader;
import org.idpass.lite.exceptions.CardVerificationException;
import org.idpass.lite.exceptions.IDPassException;
import org.idpass.lite.exceptions.InvalidCardException;
import org.idpass.lite.exceptions.NotVerifiedException;
import org.junit.Ignore;
import org.junit.Test;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.*;

public class TestCases {
    byte[] encryptionkey    = IDPassHelper.generateEncryptionKey();
    byte[] signaturekey     = IDPassHelper.generateSecretSignatureKey();
    byte[] verificationkey  = Arrays.copyOfRange(signaturekey, 32, 64);

    KeySet m_keyset = KeySet.newBuilder()
            .setEncryptionKey(ByteString.copyFrom(encryptionkey))
            .setSignatureKey(ByteString.copyFrom(signaturekey))
            .addVerificationKeys(byteArray.newBuilder()
                    .setTyp(byteArray.Typ.ED25519PUBKEY)
                    .setVal(ByteString.copyFrom(verificationkey)).build())
            .build();

    Ident.Builder m_IdentBuilder = Ident.newBuilder()
            .setGivenName("John")
            .setSurName("Doe")
            .setPin("1234")
            .setPlaceOfBirth("Aubusson, France")
            .setDateOfBirth(Dat.newBuilder().setYear(1980).setMonth(12).setDay(17))
            .addPubExtra(KV.newBuilder().setKey("gender").setValue("male").setKey("color").setValue("blue"))
            .addPrivExtra(KV.newBuilder().setKey("food").setValue("pizza").setKey("movie").setValue("darkcity"));

    private Card newTestCard(IDPassReader reader) throws IDPassException, IOException {
        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));

        Ident ident = m_IdentBuilder.setPhoto(ByteString.copyFrom(photo))
                .addPubExtra(KV.newBuilder().setKey("sports").setValue("boxing").setKey("game").setValue("cards"))
                .addPrivExtra(KV.newBuilder().setKey("age").setValue("35").setKey("address").setValue("16th Elm Street"))
                .build();

        Card card = reader.newCard(ident,null);
        return card;
    }


    @Test
    public void testcreateCard2WithCertificates()
            throws IOException, IDPassException {
        byte[] signer0 = IDPassReader.generateSecretSignatureKey();

        Certificate signer0RootCert = IDPassReader.generateRootCertificate(signer0);
        Certificate signerFromSigner0Cert = IDPassReader.generateChildCertificate(signer0, verificationkey); // very important

        Certificates rootcertificates  = Certificates.newBuilder().addCert(signer0RootCert).build();

        IDPassReader reader = new IDPassReader(m_keyset, rootcertificates);
        Certificates certs = Certificates.newBuilder().addCert(signerFromSigner0Cert).build();

        //IDPassReader.addRevokedKey(Arrays.copyOfRange(signer0,32,64));
        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
        Ident ident = m_IdentBuilder.setPhoto(ByteString.copyFrom(photo)).build();

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
        assertFalse(card2.verifyCertificate());
        try {
            card2.authenticateWithPIN("1234");
            assertTrue(false);
        } catch (Exception e) {
            // because the card's certificate chain
            // could not find needed root certificate
        }
    }

    @Test
    public void testOpenCardWithNoVerificationKey() throws IOException, IDPassException {
        byte[] signer0 = IDPassReader.generateSecretSignatureKey();

        Certificate signer0RootCert = IDPassReader.generateRootCertificate(signer0);
        Certificate signerFromSigner0Cert = IDPassReader.generateChildCertificate(signer0, verificationkey); // very important

        Certificates rootcertificates  = Certificates.newBuilder().addCert(signer0RootCert).build();

        IDPassReader reader = new IDPassReader(m_keyset, rootcertificates);

        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
        Ident ident = m_IdentBuilder.setPhoto(ByteString.copyFrom(photo)).build();


        Certificates certs = Certificates.newBuilder().addCert(signerFromSigner0Cert).build();

        Card card = reader.newCard(ident, certs);
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
        Certificate signerFromSigner0Cert = IDPassReader.generateChildCertificate(signer0, verificationkey); // very important

        Certificates rootcertificates = Certificates.newBuilder().addCert(signer0RootCert).build();

        IDPassReader reader = new IDPassReader(m_keyset, rootcertificates);

        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
        Ident ident = m_IdentBuilder.setPhoto(ByteString.copyFrom(photo)).build();


        Certificates certs = Certificates.newBuilder().addCert(signerFromSigner0Cert).build();

        Card card = reader.newCard(ident, certs);
        Card cardOK = reader.open(card.asBytes());
        assertNotNull(cardOK);

        byte[] newSignatureKey = IDPassHelper.generateSecretSignatureKey();
        byte[] newVerificationKey = Arrays.copyOfRange(newSignatureKey, 32, 64);

        KeySet keyset2 = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(encryptionkey))
                .setSignatureKey(ByteString.copyFrom(signaturekey))
                .addVerificationKeys(byteArray.newBuilder()
                        .setTyp(byteArray.Typ.ED25519PUBKEY)
                        .setVal(ByteString.copyFrom(newVerificationKey)).build())
                .build();

        IDPassReader reader2 = new IDPassReader(keyset2, rootcertificates);
        Card card2 = reader2.open(card.asBytes());
        assertNotNull(card2);
    }


    @Test
    public void testcreateCardWithCertificates()
            throws IOException, IDPassException, NotVerifiedException
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
        Certificate signer4From0Cert = IDPassReader.generateChildCertificate(signer0, verificationkey); // very important

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
        Ident ident = m_IdentBuilder.setPhoto(ByteString.copyFrom(photo)).build();

        Card card = reader.newCard(ident,certs);

        try {
            card.authenticateWithPIN("1234");
        } catch (Exception e) {
            System.out.println("error");
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
        } catch (CardVerificationException e) {
            // should go here, because root certificates of reader3
            // cannot anchor the certificate chain in the  QR code ID
        }
    }

    @Test
    public void testcreateCard()
            throws IOException, IDPassException {

        IDPassReader reader = new IDPassReader(m_keyset, null);

        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
        Ident ident = m_IdentBuilder.setPhoto(ByteString.copyFrom(photo)).build();

        Card card = reader.newCard(ident, null);

        assertNotNull(card);
        assertTrue(card.asBytes().length > 0);
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
        Card card = newTestCard(reader);

        BufferedImage qrCode = card.asQRCode();
        assertTrue(qrCode.getHeight() > 50);
        assertTrue(qrCode.getWidth() > 50);

        Card readCard = reader.open(qrCode);
        assertNotNull(readCard);
        assertArrayEquals(card.asBytes(), readCard.asBytes());
    }

    @Ignore("For now, this needs generation of proper qrcode.png file")
    @Test
    public void testGetQRCodeFromPhoto() throws IOException, IDPassException, NotFoundException {
        byte[] verificationKey = {42, 68, -30, -58, 75, 118, 93, -106, 80, -106, -20, -43, 75, -43, 97, 48, 115, 101, 91, -122, -12, -79, 124, 74, -40, -76, 55, -108, 79, -124, 59, 62};

        IDPassReader reader = new IDPassReader(m_keyset, null);

        File originalQrCode = new File(String.valueOf(Paths.get("testdata/qrcode.png")));
        BufferedImage bufferedImage = ImageIO.read(originalQrCode);
        Card cardOriginal = reader.open(bufferedImage);

        File photoQrCode = new File(String.valueOf(Paths.get("testdata/photo_qrcode1.jpg")));
        bufferedImage = ImageIO.read(photoQrCode);
        Card cardPhoto = reader.open(bufferedImage);

        File binary = new File(String.valueOf(Paths.get("testdata/qrcode.bin")));
        Card cardBin = reader.open(Files.readAllBytes(binary.toPath()));

        assertArrayEquals(cardOriginal.asBytes(), cardPhoto.asBytes());
        assertArrayEquals(cardBin.asBytes(), cardPhoto.asBytes());
    }


    @Test
    public void testCardWrongPublicSignatureVerification()
            throws IOException,  IDPassException {
        byte[] encryptionkey    = IDPassHelper.generateEncryptionKey();
        byte[] signaturekey     = IDPassHelper.generateSecretSignatureKey();
        byte[] wrongVerificationkey = Arrays.copyOfRange(IDPassHelper.generateSecretSignatureKey(),32,64);

        IDPassReader reader = new IDPassReader(m_keyset, null);

        Card card = newTestCard(reader);

        KeySet ks2 = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(encryptionkey))
                .setSignatureKey(ByteString.copyFrom(signaturekey))
                .addVerificationKeys(byteArray.newBuilder()
                        .setTyp(byteArray.Typ.ED25519PUBKEY)
                        .setVal(ByteString.copyFrom(wrongVerificationkey)).build())
                .build();

        reader = new IDPassReader(ks2, null);

        try {
            reader.open(card.asBytes());
            assertTrue(false);
        } catch (IDPassException e) {
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

        IDPassReader reader = new IDPassReader(m_keyset, null);

        Card card = newTestCard(reader);

        KeySet ks1 = ksBuilder.addVerificationKeys(byteArray.newBuilder()
                        .setTyp(byteArray.Typ.ED25519PUBKEY)
                        .setVal(ByteString.copyFrom(otherVerificationkey))).build();

        reader = new IDPassReader(ks1, null);

        Card newCard = null;

        try {
            newCard = reader.open(card.asBytes());
            assertFalse(true);
        } catch (IDPassException e) {
            reader = new IDPassReader(m_keyset, null);
            newCard = reader.open(card.asBytes());
            newCard.authenticateWithPIN("1234");
        }

    }
}
