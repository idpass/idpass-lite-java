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
import com.google.protobuf.InvalidProtocolBufferException;
import org.api.proto.Certificates;
import org.api.proto.Ident;
import org.api.proto.KeySet;
import org.api.proto.byteArray;
import org.idpass.lite.IDPassLite;
import org.idpass.lite.Card;
import org.idpass.lite.IDPassHelper;
import org.idpass.lite.IDPassReader;
import org.idpass.lite.exceptions.CardVerificationException;
import org.idpass.lite.exceptions.IDPassException;
import org.idpass.lite.exceptions.InvalidCardException;
import org.idpass.lite.exceptions.NotVerifiedException;
import org.idpass.lite.proto.Date;
import org.idpass.lite.proto.*;
import org.idpass.lite.test.utils.Helper;
import org.junit.jupiter.api.*;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class TestCases {

	static {
        IDPassLite.initialize();
	}

    byte[] encryptionkey    = IDPassHelper.generateEncryptionKey();
    byte[] signaturekey     = IDPassHelper.generateSecretSignatureKey();
    byte[] publicVerificationKey = IDPassHelper.getPublicKey(signaturekey);

    KeySet m_keyset = KeySet.newBuilder()
            .setEncryptionKey(ByteString.copyFrom(encryptionkey))
            .setSignatureKey(ByteString.copyFrom(signaturekey))
            .addVerificationKeys(byteArray.newBuilder()
                    .setTyp(byteArray.Typ.ED25519PUBKEY)
                    .setVal(ByteString.copyFrom(publicVerificationKey)).build())
            .build();

    byte[] encryptionkey2    = IDPassHelper.generateEncryptionKey();
    byte[] signaturekey2     = IDPassHelper.generateSecretSignatureKey();
    byte[] publicVerificationKey2 = IDPassHelper.getPublicKey(signaturekey2);
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
    @DisplayName("Check that root and intermediate certificates are verified when opening a card")
    public void testCreateCardWithCertificates()
            throws IOException, IDPassException {
        byte[] rootKey = IDPassReader.generateSecretSignatureKey();

        // Create a root key to be configured in the ID PASS reader
        Certificate rootCert = IDPassReader.generateRootCertificate(rootKey);
        Certificates rootCertificates = Certificates.newBuilder().addCert(rootCert).build();

        IDPassReader reader = new IDPassReader(m_keyset, rootCertificates);

        // Create the content of a new card
        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
        Ident ident = newIdentBuilder().setPhoto(ByteString.copyFrom(photo)).build();

        // Create the intermediate certificate that has been signed by the root key
        Certificate signerFromRootCert = IDPassReader.generateChildCertificate(rootKey, publicVerificationKey); // very important
        Certificates certs = Certificates.newBuilder().addCert(signerFromRootCert).build();

        // Create the new card
        Card card = reader.newCard(ident, certs);

        //try to re-open the card using the previous reader object (and root certificate)
        Card cardOK = reader.open(card.asBytes());
        assertNotNull(cardOK);
        assertTrue(card.verifyCertificate());
        card.authenticateWithPIN("1234");
        assertTrue(card.verifyCertificate());

        // try to open the card with a random root certificate
        byte[] signer1 = IDPassReader.generateSecretSignatureKey();
        Certificate signer1RootCert = IDPassReader.generateRootCertificate(signer1);
        Certificates rootCertificates1 = Certificates.newBuilder().addCert(signer1RootCert).build();

        IDPassReader reader2 = new IDPassReader(m_keyset, rootCertificates1);

        //Check that the opening of the card fail ad the root certificate cannot be checked
        try {
            reader2.open(card.asBytes());
            assertTrue(false);
        } catch (InvalidCardException ignored) {}

        //Check that the opening of the card work if we skip the certificate verification
        Card card2 = reader2.open(card.asBytes(), true);
        assertFalse(card2.verifyCertificate());
        card.authenticateWithPIN("1234");
        assertEquals("John", card.getGivenName());
        assertFalse(card2.verifyCertificate());
    }

    @Test
    @DisplayName("Test open card with no verification key")
    public void testOpenCardWithNoVerificationKey() throws IOException, IDPassException {
        // Generate root key for a self-signed certificate
        byte[] signer0 = IDPassReader.generateSecretSignatureKey();

        Certificate signer0RootCert = IDPassReader.generateRootCertificate(signer0);
        Certificate signerFromSigner0Cert = IDPassReader.generateChildCertificate(signer0, publicVerificationKey); // very important

        Certificates rootcertificates  = Certificates.newBuilder().addCert(signer0RootCert).build();

        // Initialize a reader with default test keyset, and a root certificates
        IDPassReader reader = new IDPassReader(m_keyset, rootcertificates);

        // Get a pre-populated test ident structure
        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
        Ident ident = newIdentBuilder().setPhoto(ByteString.copyFrom(photo)).build();

        // Create an intermediate certificate of m_keyset's signature key
        Certificates certificateChainToRoot = Certificates.newBuilder().addCert(signerFromSigner0Cert).build();

        Card card = reader.newCard(ident, certificateChainToRoot);
        Card cardOK = reader.open(card.asBytes());
        assertNotNull(cardOK);

        byte[] newSignatureKey = IDPassHelper.generateSecretSignatureKey();

        // Create a keyset with similar encryption key but different signature key
        KeySet keyset = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(encryptionkey))
                .setSignatureKey(ByteString.copyFrom(newSignatureKey))
                .build();

        // Initialize second reader using new keyset and root certificates
        IDPassReader reader2 = new IDPassReader(keyset, rootcertificates);

        // Check the second reader can open the card
        Card card2 = reader2.open(card.asBytes());
        assertNotNull(card2);

        assertTrue(card2.verifyCertificate());
        assertFalse(card2.verifyCardSignature());
    }

    @Test
    @DisplayName("Testing opening card with unknown verification key")
    public void testOpenCardWithUnkownVerificationKey() throws IOException, IDPassException {
        // Generate root key for a self-signed certificate
        byte[] signer0 = IDPassReader.generateSecretSignatureKey();

        Certificate signer0RootCert = IDPassReader.generateRootCertificate(signer0);
        Certificate signerFromSigner0Cert = IDPassReader.generateChildCertificate(signer0, publicVerificationKey); // very important

        Certificates rootCertificates = Certificates.newBuilder().addCert(signer0RootCert).build();

        // Initialize a reader with default test keyset, and a root certificates
        IDPassReader reader = new IDPassReader(m_keyset, rootCertificates);

        // Get a pre-populated test ident structure
        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
        Ident ident = newIdentBuilder().setPhoto(ByteString.copyFrom(photo)).build();

        // Create an intermediate certificate of m_keyset's signature key
        Certificates certs = Certificates.newBuilder().addCert(signerFromSigner0Cert).build();

        // Generate an ID PASS lite card from filled-up ident structure with an intermediate certificate
        Card card = reader.newCard(ident, certs);
        Card cardOK = reader.open(card.asBytes());
        assertNotNull(cardOK);

        // Generate a new keyset with different signature key but similar encryption key
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

        // Initialize a second reader using slightly modified keyset, and same root certificates
        IDPassReader reader2 = new IDPassReader(keyset2, rootCertificates);
        Card card2 = reader2.open(card.asBytes());
        assertNotNull(card2);
        //TODO open the private part

        assertEquals(card.getSurname(),"");
        assertEquals(card.getGivenName(),"");

        try {
            // Check that card2 is not able to authenticate
            card2.authenticateWithPIN("1234");
        } catch (CardVerificationException ignored) {assertTrue(false);}
    }


    @Test
    @DisplayName("Test opening a card from a reader with different encryption key")
    public void testOpenCardWithAnotherEncryptionKey() throws IOException, IDPassException {
        // Generate a test root key to create a self-signed root certificate
        byte[] signer0 = IDPassReader.generateSecretSignatureKey();

        Certificate signer0RootCert = IDPassReader.generateRootCertificate(signer0);
        Certificate signerFromSigner0Cert = IDPassReader.generateChildCertificate(signer0, publicVerificationKey); // very important

        // Create a self-signed root certificate
        Certificates rootcertificates = Certificates.newBuilder().addCert(signer0RootCert).build();

        // Initialize a reader using default test keyset and the generated root certificate
        IDPassReader reader = new IDPassReader(m_keyset, rootcertificates);

        // Get a pre-populated test ident structure
        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
        Ident ident = newIdentBuilder().setPhoto(ByteString.copyFrom(photo)).build();

        // Create an intermediate certificate of m_keyset's signature key
        Certificates certs = Certificates.newBuilder().addCert(signerFromSigner0Cert).build();

        // Generate a test ID PASS lite card and verify can open the card
        Card card = reader.newCard(ident, certs);
        Card cardOK = reader.open(card.asBytes());
        assertNotNull(cardOK);

        // Generate needed test keys to construct a test keyset object

        // First, generate a test encryption key
        byte[] newEncryptionkey = IDPassHelper.generateEncryptionKey();

        byte[] newSignatureKey = new byte[64];
        byte[] newVerificationKey = new byte[32];
        // Next, generate an ED25519 key pair
        IDPassReader.generateSecretSignatureKeypair(newVerificationKey, newSignatureKey);

        // Finally, construct a keyset object using the generated test keys
        KeySet newKeyset = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(newEncryptionkey))
                .setSignatureKey(ByteString.copyFrom(newSignatureKey))
                .addVerificationKeys(byteArray.newBuilder()
                        .setTyp(byteArray.Typ.ED25519PUBKEY)
                        .setVal(ByteString.copyFrom(newVerificationKey)).build())
                .build();

        // Initialize a second reader using the new keyset and same root certificates
        IDPassReader reader2 = new IDPassReader(newKeyset, rootcertificates);

        // Check that the second reader can open the ID PASS lite card as card2
        Card card2 = reader2.open(card.asBytes());
        assertNotNull(card2);

        try {
            // Check can authenticate on card2 using pin code
            card2.authenticateWithPIN("1234");
            assertTrue(false);
        } catch (CardVerificationException ignored) {}
    }


    @Test
    @DisplayName("Test reading card with another reader's configuration with different certificates")
    public void testcreateCardWithCertificates()
            throws IOException, IDPassException
    {
        // Generate test keys
        byte[] signer0 = IDPassReader.generateSecretSignatureKey();
        byte[] signer1 = IDPassReader.generateSecretSignatureKey();
        byte[] signer2 = IDPassReader.generateSecretSignatureKey();
        byte[] signer3 = IDPassReader.generateSecretSignatureKey();
        byte[] signer4 = IDPassReader.generateSecretSignatureKey();
        byte[] signer9 = IDPassReader.generateSecretSignatureKey();

        // Generate a chain of certificates from the test keys
        Certificate signer0RootCert = IDPassReader.generateRootCertificate(signer0);
        Certificate signer1RootCert = IDPassReader.generateRootCertificate(signer1);

        Certificate signer2From1Cert = IDPassReader.generateChildCertificate(signer1, IDPassHelper.getPublicKey(signer2));
        Certificate signer3From2Cert = IDPassReader.generateChildCertificate(signer2, IDPassHelper.getPublicKey(signer3));

        Certificate signer4From3Cert = IDPassReader.generateChildCertificate(signer3, IDPassHelper.getPublicKey(signer4));
        Certificate signer4From0Cert = IDPassReader.generateChildCertificate(signer0, publicVerificationKey); // very important

        Certificates rootcertificates = Certificates.newBuilder()
                .addCert(signer0RootCert)
                .addCert(signer1RootCert)
                .build();

        // Initialize a reader with test default keyset and generated root certificates
        IDPassReader reader = new IDPassReader(m_keyset, rootcertificates);

        // Generate a certificate chain for the card
        Certificates certs = Certificates.newBuilder()
                .addCert(signer0RootCert)
                .addCert(signer1RootCert)
                .addCert(signer2From1Cert)
                .addCert(signer3From2Cert)
                .addCert(signer4From3Cert)
                .addCert(signer4From0Cert)
                .build();

        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
        Ident ident = newIdentBuilder().setPhoto(ByteString.copyFrom(photo)).build();

        // Generate a test ID PASS lite card with attached certificates chain
        Card card = reader.newCard(ident,certs);

        try {
            // Check can successfully authenticate using pin code
            card.authenticateWithPIN("1234");
        } catch (CardVerificationException ignored) {
            assertFalse(true);
        }

        // Check that the card's attached certificates chain does verify and can open the card
        assertTrue(card.verifyCertificate());
        assertNotNull(card);
        assertTrue(card.asBytes().length > 0);
        reader.open(card.asBytes());

        // Initialize another reader with default test keyset and the generated root certificates
        IDPassReader reader2 = new IDPassReader(m_keyset, rootcertificates);

        // Check that the second reader can open, authenticate and verify the ID PASS lite card
        Card card2 = reader2.open(card.asBytes());
        card2.authenticateWithPIN(("1234"));
        assertTrue(card2.verifyCertificate());

        card2 = reader2.open(card.asBytes());
        assertTrue(card2.verifyCertificate());

        // Create another root certificate
        Certificates rootcertificates2 = Certificates.newBuilder()
                .addCert(IDPassReader.generateRootCertificate(signer9))
                .build();

        // Initialize a third reader with default test keyset and different root certificate
        IDPassReader reader3 = new IDPassReader(m_keyset, rootcertificates2);

        try {
            // Check that the third reader can open the card
            reader3.open(card.asBytes());
            assertTrue(false);
        } catch (InvalidCardException ignored) {}

        // Check that the third reader can also open the card with certificates check skip
        card2 = reader3.open(card.asBytes(), true);
        // But card2 cannot verify its attached certificates as reader3 has different root certificates
        assertFalse(card2.verifyCertificate());

        try {
            // Check that card2 could not authenticate
            card2.authenticateWithPIN(("1234"));
            assertTrue(false);
        } catch (CardVerificationException ignored) {
            // should go here, because root certificates of reader3
            // cannot anchor the certificate chain in the  QR code ID
        }
    }

    @Test
    @DisplayName("Test with the same signature key, but all the other keys are different")
    public void testcreateCardWithNoCertificates()
            throws IOException, IDPassException {
        // Initialize reader with test keyset, no root certificates
        IDPassReader reader = new IDPassReader(m_keyset, null);

        // Fill-in ident data structure with Manny's photo
        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
        Ident ident = newIdentBuilder().setPhoto(ByteString.copyFrom(photo)).build();

        // Generate ID PASS lite card from the filled-in data structure,
        // no intermediate certificates
        Card card = reader.newCard(ident, null);

        // Check that the card is generated and that it has some content
        assertNotNull(card);
        assertTrue(card.asBytes().length > 0);

        // Check that the reader can open the card, skipping certificate check
        reader.open(card.asBytes(), true);

        // Generate test keys
        byte[] newEncryptionkey = IDPassHelper.generateEncryptionKey();
        byte[] newSignatureKey = IDPassHelper.generateSecretSignatureKey();
        byte[] newVerificationKey = IDPassHelper.getPublicKey(newSignatureKey);

        //Test with new keys for everything
        KeySet newKeyset = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(newEncryptionkey))
                .setSignatureKey(ByteString.copyFrom(newSignatureKey))
                .addVerificationKeys(byteArray.newBuilder()
                        .setTyp(byteArray.Typ.ED25519PUBKEY)
                        .setVal(ByteString.copyFrom(newVerificationKey)).build())
                .build();

        // Initialize another reader with different keyset and no root certificates
        IDPassReader reader2 = new IDPassReader(newKeyset, null);

        try {
            // Check that the second reader (with different keyset) cannot open the card
            // even if skipping certificate verification
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

        // Initialize new reader with different keyset's verification keys and no certificate chain
        reader2 = new IDPassReader(newKeyset, null);

        // Check that the new reader can open the original card
        reader2.open(card.asBytes(), true);
    }

    @Test
    @DisplayName("Test that wrong pin code cannot authenticate")
    public void testPinCode() throws IOException, IDPassException {
        // Initialize reader with test keyset, no root certificates
        IDPassReader reader = new IDPassReader(m_keyset, null);
        // Generate a test ID PASS lite card
        Card card = newTestCard(reader);

        try {
            // Check that a wrong pin code cannot authenticate
            card.authenticateWithPIN("0000");
            assertTrue(false);
        } catch (CardVerificationException e) {}

        try {
            // Check that a correct pin code can authenticate
            card.authenticateWithPIN("1234");
        } catch (CardVerificationException e) {
            assertTrue(false);
        }
    }

    @Test
    @DisplayName("Test that every identity fields are not publicly visible by default")
    public void testDataVisibility() throws IOException, IDPassException {
        // Initialize reader with test keyset, no root certificates
        IDPassReader reader = new IDPassReader(m_keyset, null);
        // Generate a test ID PASS lite card
        Card card = newTestCard(reader);

        // Check that no identity fields are visible prior to authentication
        assertEquals("", card.getGivenName());
        assertEquals("", card.getSurname());
        assertEquals(null,card.getDateOfBirth());
        assertEquals("", card.getPlaceOfBirth());

        try {
            // Authenticate with pin code
            card.authenticateWithPIN("1234");
        } catch (CardVerificationException e) {
            assertTrue(false);
        }

        // Check that every identity fields are now visible after authentication
        assertEquals("John", card.getGivenName());
        assertEquals("Doe", card.getSurname());
        assertEquals("Aubusson, France", card.getPlaceOfBirth());
        assertNotNull(card.getDateOfBirth());
    }

    @Test
    @DisplayName("Test that the configugred card details are publicly visible")
    public void testDataVisibility2() throws IOException, IDPassException {
        // Initialize reader with test keyset, no root certificates
        IDPassReader reader = new IDPassReader(m_keyset, null);
        // Configure the reader to make two identity fields publicly visible
        reader.setDetailsVisible(
                IDPassReader.DETAIL_GIVENNAME |
                IDPassReader.DETAIL_PLACEOFBIRTH);
        // Generate a test ID PASS lite card
        Card card = newTestCard(reader);

        // Check that the configured details field are publicly visible
        assertEquals("John", card.getGivenName());
        assertEquals("Aubusson, France", card.getPlaceOfBirth());

        // Check that other details field are not publicly visible
        assertNull(card.getDateOfBirth());
        assertEquals("", card.getSurname());

        try {
            // Authenticate using pin code
            card.authenticateWithPIN("1234");
        } catch (CardVerificationException e) {
            assertTrue(false);
        }

        // Check that every detail fields are now visible after authentication
        assertEquals("John", card.getGivenName());
        assertEquals("Doe", card.getSurname());
        assertEquals("Aubusson, France", card.getPlaceOfBirth());
        assertEquals(17, card.getDateOfBirth().getDate());
        assertEquals(12, card.getDateOfBirth().getMonth() + 1);
        assertEquals(1980, card.getDateOfBirth().getYear() + 1900);
    }

    @Test
    @DisplayName("Test card authentication with card owner's photo")
    public void testFace() throws IOException, IDPassException {
        // Initialize reader with default test keyset, no root certificates
        IDPassReader reader = new IDPassReader(m_keyset, null);
        // Generate a test card with Manny's photo in it
        Card card = newTestCard(reader);
        try {
            // Authenticating to card with a different person's face should fail
            byte[] photo = Files.readAllBytes(Paths.get("testdata/brad.jpg"));
            card.authenticateWithFace(photo);
            assertTrue(false);
        } catch (CardVerificationException e) {}

        try {
            // Authenticating to card with a card owner's photo should succeed
            byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));
            card.authenticateWithFace(photo);
        } catch (CardVerificationException e) {
            assertTrue(false);
        }

        //reset the card.
        card = newTestCard(reader);
        try {
            // Authenticating to card with a card owner's photo should succeed
            byte[] photo = Files.readAllBytes(Paths.get("testdata/manny4.jpg"));
            card.authenticateWithFace(photo);
        } catch (CardVerificationException e) {
            assertTrue(false);
        }
    }

    @Test
    @DisplayName("Test adjusting threshold to lower value for face recognition")
    public void testFaceStrictThreshold() throws IOException, IDPassException {
        // Initialize reader with test keyset, no root certificates
        IDPassReader reader = new IDPassReader(m_keyset, null);

        //try with a very strict threshold, so even Manny does not match with Manny
        Card card = newTestCard(reader); // test card has Manny's photo

        // Configure face recognition value to low threshold
        reader.setFaceDiffThreshold(0.1f);
        assertEquals(reader.getFaceDiffThreshold(), 0.1f);

        try {
            byte[] photo = Files.readAllBytes(Paths.get("testdata/manny4.jpg"));
            // Check that facial authentication will fail due to very low threshold
            card.authenticateWithFace(photo);
            assertTrue(false);
        } catch (CardVerificationException e) {
        }

    }

    @Test
    @DisplayName("Test adjusting threshold to upper value for face recognition")
    public void testFaceRelaxedThreshold() throws IOException, IDPassException {
        // Initialize reader with default test keyset, no root certificates
        IDPassReader reader = new IDPassReader(m_keyset, null);

        Card card = newTestCard(reader); // the test card has manny's photo

        //try with a very relaxed threshold so it confuse brad with Manny
        // Configure face recognition value to upper threshold
        reader.setFaceDiffThreshold(0.9f);

        try {
            // Authentication to the card with a different person's face
            // will succeed when threshold settings is relaxed to an upper value
            byte[] photo = Files.readAllBytes(Paths.get("testdata/brad.jpg"));
            card.authenticateWithFace(photo);
        } catch (CardVerificationException e) {
            assertTrue(false);
        }

    }

    @Test
    @DisplayName("Test that card's public key cannot be retrieved without authentication")
    public void testPublicKey() throws IOException, IDPassException {
        // Initialize a reader using test keyset, no root certificate
        IDPassReader reader = new IDPassReader(m_keyset, null);
        // Generate a test ID PASS lite card
        Card card = newTestCard(reader);

        try {
            // Check that the card's public key cannot be retrieved
            // prior to authentication
            card.getPublicKey();
            assertTrue(false);
        } catch (NotVerifiedException e) {
        }

        // Authenticate to the card using pin code
        card.authenticateWithPIN("1234");

        try {
            // Check that the card's public key can now be retrieved
            // after authentication
            byte[] key = card.getPublicKey();
            assertEquals(32, key.length);
        } catch (NotVerifiedException e) {
            assertTrue(false);
        }
    }

    @Test
    @DisplayName("A test to scan and read back a QR code image and test the two cards are equal")
    public void testGetQRCode() throws IOException, IDPassException {
        // Initialize reader with test keyset and no root certificate
        IDPassReader reader = new IDPassReader(m_keyset, null);
        // Configure a QR code scanner that the reader will use during scanning

        // Create a test ID PASS lite card
        Card card = newTestCard(reader);

        // Render the ID PASS lite card as a QR code image
        BufferedImage qrCode = Helper.toBufferedImage(card);

        // Check the QR code image size, not empty
        assertTrue(qrCode.getHeight() > 50);
        assertTrue(qrCode.getWidth() > 50);

        // Scan the QR code image, and skip certificate check
        Card readCard = reader.open(Helper.scanQRCode(qrCode), true); // HERE

        // Check that an ID PASS lite card is generated from the
        // scanned QR code image. And that, the two card contents match
        assertNotNull(readCard);
        assertArrayEquals(card.asBytes(), readCard.asBytes());
    }

    @Test
    @DisplayName("A test to open a card with an attached certificate chain using a different reader")
    public void testCardWrongPublicSignatureVerification()
            throws IOException,  IDPassException {
        // Generate test keys
        byte[] encryptionkey    = IDPassHelper.generateEncryptionKey();
        byte[] signaturekey     = IDPassHelper.generateSecretSignatureKey();
        byte[] wrongVerificationkey = IDPassHelper.getPublicKey(IDPassHelper.generateSecretSignatureKey());

        // Initialize reader with default test keyset and root certificates
        IDPassReader reader = new IDPassReader(m_keyset, m_rootcerts);

        // Generate a test ID PASS lite card with an attached test certificate chain
        Card card = newTestCard(reader, m_certchain);

        // Build a different keyset from the generated test keys
        KeySet ks2 = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(encryptionkey))
                .setSignatureKey(ByteString.copyFrom(signaturekey))
                .addVerificationKeys(byteArray.newBuilder()
                        .setTyp(byteArray.Typ.ED25519PUBKEY)
                        .setVal(ByteString.copyFrom(wrongVerificationkey)).build())
                .build();

        // Initialize another reader with different keyset
        IDPassReader reader2 = new IDPassReader(ks2, m_rootcerts);

        try {
            // Check the second reader can open the card
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
    @DisplayName("Test to open a card using another with different keyset, but similar root certificates")
    public void testCardSignatureVerification()
            throws IOException, IDPassException {
        // Generate test keys
        byte[] encryptionkey    = IDPassHelper.generateEncryptionKey();
        byte[] signaturekey     = IDPassHelper.generateSecretSignatureKey();
        byte[] otherVerificationkey = IDPassHelper.getPublicKey(IDPassHelper.generateSecretSignatureKey());

        KeySet.Builder ksBuilder = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(encryptionkey))
                .setSignatureKey(ByteString.copyFrom(signaturekey));

        // Initialize reader with test keyset and test root certificates
        IDPassReader reader = new IDPassReader(m_keyset, m_rootcerts);

        // Create a test card using test certificate chain
        Card card = newTestCard(reader, m_certchain);

        // Do a finalize build of another keyset from the generated test keys
        KeySet ks1 = ksBuilder.addVerificationKeys(byteArray.newBuilder()
                        .setTyp(byteArray.Typ.ED25519PUBKEY)
                        .setVal(ByteString.copyFrom(otherVerificationkey))).build();

        // Initialize another reader2 using a different keyset ks1
        IDPassReader reader2 = new IDPassReader(ks1, m_rootcerts);

        Card newCard = null;

        try {
            // Verify that card created in reader1 can be open by reader2 even if
            // they don't have same keyset.
            newCard = reader2.open(card.asBytes());
        } catch (IDPassException e) {
            assertFalse(true); // HERE
        }

        try {
            // Verify that card cannot be authenticated even with correct pin code
            newCard.authenticateWithPIN("1234");
            assertFalse(true);
        } catch (CardVerificationException e) {

        }
    }

    @Test
    @DisplayName("Create a test card and use the card to encrypt & decrypt a test message")
    public void testCardEncryptDecrypt()
            throws IDPassException, IOException, NotVerifiedException
    {
        // Initialize reader with required keyset and null for the optional root certificates
        IDPassReader reader = new IDPassReader(m_keyset, null);
        // Generate a test ID PASS lite card
        Card card = newTestCard(reader);

        // This is the message that the card will encrypt
        String msg = "attack at dawn!";

        // Store the encrypted message in this byte array
        byte[] encrypted = new byte[0];

        try {
            // Using the card to encrypt the message prior to authentication should fail
            encrypted = card.encrypt(msg.getBytes());
            assertFalse(true);
        } catch (NotVerifiedException e) {

        }

        // Authenticate to the card using pin code
        card.authenticateWithPIN("1234");

        try {
            // Check can now use the card to encrypt the message
            encrypted = card.encrypt(msg.getBytes());
            assertTrue(encrypted.length > 1);
        } catch (NotVerifiedException e) {
            assertFalse(true);
        }

        // Check can now use the card to decrypt the message
        String decrypted = new String(card.decrypt(encrypted));
        assertEquals(decrypted, msg);
    }

    @Test
    @DisplayName("Basic flow creating a card with certificate chain and verified by the reader")
    public void testBasicFlow()
            throws IOException, IDPassException
    {
        // Generate test keys
        byte[] encryptionKey = IDPassReader.generateEncryptionKey();
        byte[] signatureKey = IDPassReader.generateSecretSignatureKey();

        // Initialize keyset data structure with test keys

        KeySet keySet = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(encryptionKey))
                .setSignatureKey(ByteString.copyFrom(signatureKey))
                .build();

        // Optional: Prepare list of root certificates

        byte[] rootKey1 = IDPassReader.generateSecretSignatureKey();
        byte[] rootKey2 = IDPassReader.generateSecretSignatureKey();

        Certificate rootCert1 = IDPassReader.generateRootCertificate(rootKey1);
        Certificate rootCert2 = IDPassReader.generateRootCertificate(rootKey2);

        Certificates rootCerts = Certificates.newBuilder()
                .addCert(rootCert1)
                .addCert(rootCert2)
                .build();

        // Optional: Prepare list of intermediate certificates chain. The leaf certificate's
        // public key should be of the signature key from key set

        byte[] intermedKey1 = IDPassReader.generateSecretSignatureKey();
        Certificate intermedCert1 = IDPassReader.generateChildCertificate(rootKey1,
                IDPassHelper.getPublicKey(intermedKey1));

        Certificate intermedCert2 = IDPassReader.generateChildCertificate(intermedKey1,
                IDPassHelper.getPublicKey(signatureKey));

        Certificates intermedCerts = Certificates.newBuilder()
                .addCert(intermedCert1)
                .addCert(intermedCert2)
                .build();

        // Initialize the library via an IDPassReader instance with mandatory keyset and an
        // optional root certificates

        IDPassReader reader = new IDPassReader(keySet, rootCerts);

        // Fill-up ident data structure with personal details of an identity to register

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

        // Create an ID PASS lite card from the ident data structure with intermediate certificates.
        // This ID card can be rendered as a QR code.

        Card card = reader.newCard(ident, intermedCerts);

        // Verify the attached certificates in card is valid
        assertTrue(card.verifyCertificate());
    }

    @Test
    @DisplayName("Test basic card creation and authentication")
    public void testMinimalCompleteFlow()
            throws IOException, IDPassException {
        // Generate test keys
        byte[] encryptionKey = IDPassReader.generateEncryptionKey();
        byte[] signatureKey = IDPassReader.generateSecretSignatureKey();

        // Initialize the keyset data structure with test keys

        KeySet keySet = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(encryptionKey))
                .setSignatureKey(ByteString.copyFrom(signatureKey))
                .build();

        // Initialize reader instance with mandatory keyset
        // and no root certificate
        IDPassReader reader = new IDPassReader(keySet, null);
        // Set a QR code image scanner that the reader will use during scanning

        // Fill-up ident data structure with personal details of an identity to register

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

        // Generate an ID PASS lite card object from the filled-in ident data structure

        Card card = reader.newCard(ident, null);

        // Render the ID PASS lite card object as a QR code image

        BufferedImage qrCode = Helper.toBufferedImage(card);

        // Read back the QR code image to reconstruct the ID PASS lite card object

        Card c = reader.open(Helper.scanQRCode(qrCode), true); // boolean true means skip certificate check

        // Given name field is not visible prior to authentication
        assertEquals(c.getGivenName(),"");

        // Load facial photo of a different person
        byte[] photo_brad = Files.readAllBytes(Paths.get("testdata/brad.jpg"));

        try {
            // Authenticating to the card as a different person should fail
            c.authenticateWithFace(photo_brad);
            assertFalse(true);
        } catch (CardVerificationException e) {
        }

        // Authenticating to the card with owner's photo should succeed

        try {
            c.authenticateWithFace(photo);
            assertEquals(c.getGivenName(),"John");
        } catch (CardVerificationException e) {
            assertFalse(true);
        }
    }

    @Test
    @DisplayName("Test revoking a certificate")
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
                IDPassHelper.getPublicKey(intermedKey1));
        Certificate intermedCert2 = IDPassReader.generateChildCertificate(intermedKey1, IDPassHelper.getPublicKey(signatureKey));
        Certificates intermedCerts = Certificates.newBuilder()
                                        .addCert(intermedCert1)
                                        .addCert(intermedCert2)
                                        .build();

        // Initialize reader with test keyset and root certificates
        IDPassReader reader = new IDPassReader(keySet, rootCerts);

        // Check can successfully add certificates chain to the reader configuration
        assertTrue(reader.addIntermediateCertificates(intermedCerts));

        // Revoke one certificate in the chain
        IDPassReader.addRevokedKey(IDPassHelper.getPublicKey(intermedKey1));

        // Check can no longer add a certificate chain when one of them is revoked
        assertFalse(reader.addIntermediateCertificates(intermedCerts));
    }

    @Test
    @DisplayName("Test generate a 64 bytes detached signature and its verification")
    public void testCardSignVerify() throws IOException, IDPassException, NotVerifiedException {
        // The message to be signed
        String msg = "attack at dawn!";

        // Initialize reader using test keyset and no certificates.
        IDPassReader reader = new IDPassReader(m_keyset, null);

        // Create a test card from this reader
        Card card = newTestCard(reader);

        // Authenticate on the card
        card.authenticateWithPIN("1234"); // needs to auth first before can sign

        // Use the card to compute a 64-bytes detached signature of msg
        byte[] signature = card.sign(msg.getBytes());
        assertTrue(signature.length == 64);

        // Use the card to verify the detached signature against msg is valid
        assertTrue(card.verify(msg.getBytes(), signature,card.getPublicKey()));

        // Use the card to verify the detached signature against a tampered msg is invalid
        StringBuilder tampered = new StringBuilder(msg);
        tampered.setCharAt(0, 'A');
        assertFalse(card.verify(tampered.toString().getBytes(), signature, card.getPublicKey()));

        // Initialize second reader with different test keyset; No root certificates.
        IDPassReader reader2 = new IDPassReader(m_keyset2, null);

        // Create a second test card from second reader, and authenticate in card2
        Card card2 = newTestCard(reader2);
        card2.authenticateWithPIN("1234");

        // Check the second card to verify the detached signature from first card
        assertTrue(card2.verify(msg.getBytes(), signature, card.getPublicKey()));

        // Use second card to compute detached signature of msg
        signature = card2.sign(msg.getBytes());
        assertTrue(signature.length == 64);

        // Either cards can verify the detached signature
        assertTrue(card2.verify(msg.getBytes(), signature,card2.getPublicKey()));
        assertTrue(card.verify(msg.getBytes(), signature,card2.getPublicKey()));
    }

    @Disabled("This is only used for generating QR code images for debugging purposes")
    @Test
    @DisplayName("For debugging purposes only")
    public void testSaveQRcode() throws IDPassException, IOException {
        // Initialize reader from test keyset and root certificates
        IDPassReader reader = new IDPassReader(m_keyset, m_rootcerts);

        // Render a test card with attached test certificate
        Card card = newTestCard(reader, m_certchain);

        // Save the card to file system as a QR code image
        File outputfile = new File("testqr2.jpg");
        ImageIO.write(Helper.toBufferedImage(card), "jpg", outputfile);

        // Persist the reader's configuration to a keystore file
        Helper.saveConfiguration("test", new File("reader1.cfg"), "changeit", "changeit", m_keyset, m_rootcerts);

        // We can also save other blobs of data to the keystore file
        Helper.writeKeyStoreEntry(
            "rootcertificatesprivatekeys",new File("reader1.cfg.p12"), "changeit", "changeit", m_rootkey);

        Helper.writeKeyStoreEntry(
            "intermedcertificatesprivatekeys",new File("reader1.cfg.p12"), "changeit", "changeit", signaturekey);
    }

    @Test
    @DisplayName("Test reading a card when the reader is configured without root certificates")
    public void test_read_id_without_certificate()
            throws IDPassException, IOException {
        // Load the keyset from a plain file
        byte[] ks = Files.readAllBytes(Paths.get("testdata/keyset.dat"));
        KeySet keyset = KeySet.parseFrom(ks);

        // Initialize reader with the loaded keyset. No root certificates is used.
        IDPassReader reader = new IDPassReader(keyset, null);
        // Configure a QR scanner that the reader will use during scanning

        // Load a test QR code image file with no certificate
        File qrFile = new File(String.valueOf(Paths.get("testdata/image.jpg")));
        BufferedImage bufferedImageNoCert = ImageIO.read(qrFile);

        // Load a test QR code image file with certificate
        qrFile = new File(String.valueOf(Paths.get("testdata/card_with_cert.jpg")));
        BufferedImage bufferedImageWithCert = ImageIO.read(qrFile);

        Card cardOriginal = null;

        try {
            // Render an ID PASS lite card from a scanned QR code image
            cardOriginal = reader.open(Helper.scanQRCode(bufferedImageWithCert));
            assertFalse(true);
        } catch (InvalidCardException e) {
            // A reader without configured root certificate must skip certificate check
            // to render a card from the QR code image
            cardOriginal = reader.open(Helper.scanQRCode(bufferedImageWithCert), true);
        }

        // Render an ID PASS lite card from a scanned QR code image with no certficate
        cardOriginal = reader.open(Helper.scanQRCode(bufferedImageNoCert));

        // Given name is not visible prior to authentication
        assertEquals(cardOriginal.getGivenName(), "");

        // Authenticate using pin code
        cardOriginal.authenticateWithPIN("1234");

        // Check can read given name after authentication
        assertEquals(cardOriginal.getGivenName(),"John");
    }

    @Test
    @DisplayName("Test reader configuration from plain files")
    public void test_read_id_with_certificate()
            throws IDPassException, IOException {

        // Load the keyset of the reader from a plain file
        byte[] ks = Files.readAllBytes(Paths.get("testdata/testkeyset.dat"));
        KeySet keyset = KeySet.parseFrom(ks);

        // Load the root certs of the reader from a plain file
        byte[] rootcertsbuf = Files.readAllBytes(Paths.get("testdata/testrootcerts.dat"));
        Certificates rootcerts = Certificates.parseFrom(rootcertsbuf );

        // Initialize reader from the loaded byte arrays for keyset and certificates
        IDPassReader reader = new IDPassReader(keyset, rootcerts);
        // Configure a QR code scanner that the reader will use during scanning

        // Load a test QR code image file
        File qrcodeId = new File(String.valueOf(Paths.get("testdata/card_with_cert.jpg")));
        BufferedImage bufferedImage = ImageIO.read(qrcodeId);

        // Render an ID PASS lite card from the scanned QR code image
        Card cardOriginal = reader.open(Helper.scanQRCode(bufferedImage)); // presence of correct root certs is only up to here

        // Hereafter, correct keyset is necessary to be able to operate on the card

        // Given name is not visible prior to authentication
        assertEquals(cardOriginal.getGivenName(), "");

        // Authenticate using pin code
        cardOriginal.authenticateWithPIN("1234"); // Now, this one needs correct keyset to work

        // Given name is now visible after authentication
        assertEquals(cardOriginal.getGivenName(),"John");
    }

    @Test
    @DisplayName("Test reading a card when the reader is configured with correct keyset and root certificates")
    public void test_read_id_with_certificate_reader_config()
            throws IOException {
        try {
            byte[][] buf = Helper.readKeyStoreEntry("default_keyset", "testdata/reader.cfg.p12", "changeit", "changeit");
            KeySet keyset = KeySet.parseFrom(buf[0]);
            buf = Helper.readKeyStoreEntry("default_rootcertificates", "testdata/reader.cfg.p12", "changeit", "changeit");
            Certificates rootcertificates = Certificates.parseFrom(buf[0]);

            // Initialize reader using keys from a keystore file
            IDPassReader reader = new IDPassReader(keyset, rootcertificates);
            // Configure a QR code scanner that the reader will use to scan

            // Read a test QR code file
            File qrcodeId = new File(String.valueOf(Paths.get("testdata/testqr1.jpg")));
            BufferedImage bufferedImage = ImageIO.read(qrcodeId);

            // Read the QR code image
            Card cardOriginal = reader.open(Helper.scanQRCode(bufferedImage)); // presence of correct root certs is only up to here

            // Hereafter, correct keyset is necessary to be able to operate on the card

            // Given name is not visible if not authenticated
            assertEquals(cardOriginal.getGivenName(), "");

            // Authenticate using pin code
            cardOriginal.authenticateWithPIN("1234"); // Now, this one needs correct keyset to work

            // Can read given name after authentication
            assertEquals(cardOriginal.getGivenName(), "John");
        } catch (IDPassException e) {
            assertFalse(true);
        }
    }

    @Test
    @DisplayName("Using InputStream to read a keystore file")
    public void test_read_p12_inputstream()
            throws IOException {
        try {
            byte[][] buf = Helper.readKeyStoreEntry("default_keyset", "testdata/reader.cfg.p12", "changeit", "changeit");
            KeySet keyset = KeySet.parseFrom(buf[0]);
            buf = Helper.readKeyStoreEntry("default_rootcertificates", "testdata/reader.cfg.p12", "changeit", "changeit");
            Certificates rootcertificates = Certificates.parseFrom(buf[0]);

            // Initialize reader from a keystore file using InputStream
            IDPassReader reader = new IDPassReader(keyset, rootcertificates);
            // Configure a QR code scanner that the reader will use during scanning

            // Read a test QR code file
            File qrcodeId = new File(String.valueOf(Paths.get("testdata/testqr1.jpg")));
            BufferedImage bufferedImage = ImageIO.read(qrcodeId);

            // Render an ID PASS lite card from a read QR code image
            Card cardOriginal = reader.open(Helper.scanQRCode(bufferedImage)); // presence of correct root certs is only up to here

            // Hereafter, correct keyset is necessary to be able to operate on the card

            // Given name is not visible if not authenticated
            assertEquals(cardOriginal.getGivenName(),"");

            // Authenticate using pin code
            cardOriginal.authenticateWithPIN("1234"); // Now, this one needs correct keyset to work

            // Can read given name after authentication
            assertEquals(cardOriginal.getGivenName(), "John");
        } catch (IDPassException e) {
            assertFalse(true);
        }
    }

    @Test
    @DisplayName("Check if the configured difference threshold can recognize two photos")
    public void test_dlib_function() throws IOException
    {
        try {
            byte[][] buf = Helper.readKeyStoreEntry("default_keyset", "testdata/demokeys.cfg.p12", "changeit", "changeit");
            KeySet keyset = KeySet.parseFrom(buf[0]);
            buf = Helper.readKeyStoreEntry("default_rootcertificates", "testdata/demokeys.cfg.p12", "changeit", "changeit");
            Certificates rootcertificates = Certificates.parseFrom(buf[0]);

            // Read a facial photo of Manny to array
            byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));

            // Initialize reader using keys and certificate from a keystore file
            IDPassReader reader = new IDPassReader(keyset, rootcertificates);

            // Compute the full dimension of 128 floats (4 bytes per float) of the facial photo
            byte[] dimensions = reader.getFaceTemplate(photo, true);
            assertTrue(dimensions.length == 128 * 4);

            // Compute the half dimension of 64 floats (2 bytes per float) of the facial photo
            dimensions = reader.getFaceTemplate(photo, false);
            assertTrue(dimensions.length == 64 * 2);

            // Get the configured (Euclidean) difference threshold value
            float threshold = reader.getFaceDiffThreshold();

            // Read another facial photo of Manny to array
            byte[] photo2 = Files.readAllBytes(Paths.get("testdata/manny2.bmp"));

            // Compute half facial dimensions (aka templates) of the two photos
            byte[] tmpl1 = reader.getFaceTemplate(photo, false);
            byte[] tmpl2 = reader.getFaceTemplate(photo2, false);

            // Compute difference of the two photos belonging to the same person
            float fdif = IDPassReader.compareFaceTemplates(tmpl1, tmpl2);

            // Verify that the fdif difference is within the configured difference threshold
            assertTrue(fdif <= threshold);
        } catch (IDPassException e) {
            assertFalse(true);
        }
    }

    @Test
    @DisplayName("A narrative description of test cases trying to read an existing QR code card")
    public void test_verify_florence_id()
        throws IDPassException, IOException {
        // photo1 and photo3 are Florence personal photos
        byte[] photo1 = Files.readAllBytes(Paths.get("testdata/florence_ID_Photo.jpg")); // high res
        byte[] photo3 = Files.readAllBytes(Paths.get("testdata/florence.jpg")); // low res
        byte[] asian0 = Files.readAllBytes(Paths.get("testdata/faces/asian0.jpg")); 
        String ssNumber = "SS Number";
        String ssNumberValue = "2 85 01 75 116 001 42";

        byte[][] buf = Helper.readKeyStoreEntry("default_keyset", "testdata/demokeys.cfg.p12", "changeit", "changeit");
        KeySet keyset = KeySet.parseFrom(buf[0]);
        buf = Helper.readKeyStoreEntry("default_rootcertificates", "testdata/demokeys.cfg.p12", "changeit", "changeit");
        Certificates rootcertificates = Certificates.parseFrom(buf[0]);

        // First, we initialize the reader with our test keys from the keystore file
        IDPassReader reader = new IDPassReader(keyset, rootcertificates);
        // Configure a QR code scanner that the reader will use to scan

        // Next, we prepare the QR code for reading. This is just a standard Java image load
        BufferedImage qrCodeImage = ImageIO.read(
            new File(String.valueOf(Paths.get("testdata/florence_idpass.png"))));

        // The reader scans the card to check if it is a QR code. The QR code public area
        // is read out and if there is presence of certificate(s), then it is validated against that
        // of the root certificate(s) of the reader. If the certificate validates, the reader::open()
        // method returns a Card. The card's public region should be publicly visible. Whereas,
        // its private region shall only be visible after successfull authentication.
        Card card0 = reader.open(Helper.scanQRCode(qrCodeImage)); // presence of correct root certs is only up to here

        assertEquals("MARION FLORENCE", card0.getGivenName());
        assertEquals("DUPONT", card0.getSurname());

        // After opening but prior to authentication, ssNumber field is not visible
        HashMap<String, String> card0Info = card0.getCardExtras();
        assertFalse(card0Info.containsKey(ssNumber));

        // A photo of another person shall not be able to authenticate using Florence card0 ID card
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

        // The card can also be authenticated by pin code. We scan again the qrCodeImage
        // to return another card3 and authenticate against card3 via pin code
        Card card3 = reader.open(Helper.scanQRCode(qrCodeImage));

        // As before, prior to authentication, ssNumber shall not be visible
        HashMap<String, String> card3Info = card3.getCardExtras();
        assertFalse(card3Info.containsKey(ssNumber));

        // Successful pin code authentication on card3, shall make visible the ssNumber field
        card3.authenticateWithPIN("1234");
        assertTrue(card3Info.containsKey(ssNumber) &&
                card3Info.get(ssNumber).equals(ssNumberValue));

        byte[][] buf2 = Helper.readKeyStoreEntry("default_keyset", "testdata/reader.cfg.p12", "changeit", "changeit");
        KeySet keyset2 = KeySet.parseFrom(buf2[0]);
        buf2 = Helper.readKeyStoreEntry("default_rootcertificates", "testdata/reader.cfg.p12", "changeit", "changeit");
        Certificates rootcertificates2 = Certificates.parseFrom(buf2[0]);

        // Let us read the same QR code ID using a reader that is initialized with entirely different keys
        IDPassReader reader2 = new IDPassReader(keyset2, rootcertificates2);

        // Because reader2 has different keys configuration,
        // then it is not able to render (or open) the QR code ID into a card
        assertThrows(InvalidCardException.class,
            () -> { Card card4 = reader2.open(Helper.scanQRCode(qrCodeImage)); });

        // However, reader2 can open the card (or render the QR code into a card)
        // if the reader skips certificate verification
        Card card5 = reader2.open(Helper.scanQRCode(qrCodeImage), true);

        // A rendered or opened card (but not yet authenticated)
        // shall have its public fields always visible. This visibility setting
        // was made when the QR code image was originally generated, and not from this test case.
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
        byte[][] entry = Helper.readKeyStoreEntry(
                "rootcertificatesprivatekeys","testdata/demokeys.cfg.p12", "changeit", "changeit");

        Certificate rootcert = IDPassReader.generateRootCertificate(entry[0]);
        Certificates rootcerts = Certificates.newBuilder().addCert(rootcert).build();

        // Using the root certificate(s) from a previous reader and combined with a different keyset, let us
        // initialize a new reader3 instance
        IDPassReader reader3 = new IDPassReader(m_keyset, rootcerts);

        // Because reader3 is initialized with proper root certificate(s),
        // it is able to open (or render) the QR code into a Card.
        Card card6 = reader3.open(Helper.scanQRCode(qrCodeImage));

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
    @DisplayName("To check if the scaled-up PNG image of the QR code is working")
    public void test_generate_scaled_idpass() throws IOException, IDPassException {
        // Prepare data structure and fill-in with identity details
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

        // Initialize reader with test keyset and root certificates
        IDPassReader reader = new IDPassReader(m_keyset, m_rootcerts);
        // Configure a QR code scanner the reader will use to scan a QR code

        // Configure reader to set some detail fields as publicly visible
        reader.setDetailsVisible(
                IDPassReader.DETAIL_SURNAME |
                IDPassReader.DETAIL_DATEOFBIRTH |
                IDPassReader.DETAIL_PLACEOFBIRTH);

        // Create an empty temporary file
        File tempFile = File.createTempFile("idpasslite", ".png");

        // Create a card from filled-in ident data structure and test certificate chain
        Card card = reader.newCard(ident,m_certchain);

        // Render the card into a QR code and save it as a scaled-up PNG file
        BufferedImage ri = Helper.toBufferedImage(card);
        ImageIO.write(ri, "png", tempFile);

        // Scan back the QR code from the saved PNG file
        BufferedImage qrimage = ImageIO.read(tempFile);
        Card idcard = reader.open(Helper.scanQRCode(qrimage));

        // Given name field is not visible prior to authentication
        assertEquals(idcard.getGivenName(),"");

        // Authenticate on the card with test pin code and verify given name field
        idcard.authenticateWithPIN("1234");
        assertEquals("MARION FLORENCE", idcard.getGivenName());

        tempFile.delete();
    }

    @Test
    @DisplayName("To test that a generated card and a QR scanned card are equal")
    public void test_generate_svg() throws IDPassException, IOException {
        // Prepare data structures and fill-in with identity details
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

        // Initialize reader with default test keyset and root certificates
        IDPassReader reader = new IDPassReader(m_keyset, m_rootcerts);

        // Configure a QR code image scanner into the reader

        // Configure some detail fields to be publicly visible
        reader.setDetailsVisible(
                IDPassReader.DETAIL_GIVENNAME |
                IDPassReader.DETAIL_SURNAME);

        // Create an ID PASS lite card from the filled-in ident data structure, and a certificate
        Card card = reader.newCard(ident,m_certchain);

        // Load SVG to BufferedImage and feed image into reader to create card2
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = card.asQRCodeSVG().getBytes(StandardCharsets.UTF_8);
        bos.write(buf, 0, buf.length);

        InputStream inputStream = new ByteArrayInputStream(bos.toByteArray());
        BufferedImage bi = ImageIO.read(inputStream);

        // Scan the QR code image from first card
        Card card2 = reader.open(Helper.scanQRCode(bi));

        // Check that the generated card and the scanned card are the same
        assertNotNull(card2);
        assertArrayEquals(card.asBytes(), card2.asBytes());
        assertTrue(card2.getGivenName().equals("MARION FLORENCE")); // DETAIL_GIVENNAME is publicly visible
    }

    @Test
    @DisplayName("A test case that writes QR code image into file system with the provided identity details")
    public void test_jgenerate_florence_id() throws IDPassException, IOException {
        // Prepare data structures and fill-in with identity details
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

        byte[][] buf = Helper.readKeyStoreEntry("default_keyset", "testdata/demokeys.cfg.p12", "changeit", "changeit");
        KeySet keyset = KeySet.parseFrom(buf[0]);
        buf = Helper.readKeyStoreEntry("default_rootcertificates", "testdata/demokeys.cfg.p12", "changeit", "changeit");
        Certificates rootcertificates = Certificates.parseFrom(buf[0]);

        // Initialize library with default keyset and certificate from a keystore file
        IDPassReader reader = new IDPassReader(keyset, rootcertificates);

        // Configure library to make some detail fields publicly visible in the rendered card
        reader.setDetailsVisible(
                IDPassReader.DETAIL_GIVENNAME |
                IDPassReader.DETAIL_SURNAME |
                IDPassReader.DETAIL_DATEOFBIRTH);

        // Read back the root key from its corresponding keystore key name
        byte[][] entry = Helper.readKeyStoreEntry(
                "rootcertificatesprivatekeys", "testdata/demokeys.cfg.p12", "changeit", "changeit");
        byte[] root_key = entry[0];

        entry = Helper.readKeyStoreEntry(
                "intermedcertificatesprivatekeys", "testdata/demokeys.cfg.p12", "changeit", "changeit");
        byte[] intermed_key = entry[0];

        // Create a certchain that will be attached in the rendered card
        byte[] verification_key = IDPassHelper.getPublicKey(intermed_key);
        Certificate childcert = IDPassReader.generateChildCertificate(root_key, verification_key);
        Certificates certchain = Certificates.newBuilder().addCert(childcert).build();

        // Create a digitally signed card from the filled-in ident data structure
        Card card = reader.newCard(ident,certchain);

        // Write the ID PASS lite card to file system as a secure QR code image
        File outPNG = File.createTempFile("outPNG",".png");
        File outSVG = File.createTempFile("outSVG",".svg");

        Helper.saveImage(card, "png", new FileOutputStream(outPNG));
        Helper.saveImage(card, "svg", new FileOutputStream(outSVG));

        assertTrue(outPNG.exists() && outPNG.length() > 0);
        assertTrue(outSVG.exists() && outSVG.length() > 0);

        outPNG.delete();
        outSVG.delete();
    }

    @Test
    @DisplayName("Test to check that newly added protobuf fields are working")
    public void testNewProtobufFields() throws IDPassException, IOException {
        // Prepare data structures and fill-in with values
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

        // Initialize reader with keyset, no certificate
        IDPassReader reader = new IDPassReader(m_keyset, null);
        // Create ID PASS lite card from filled-in ident data structure.
        Card card = reader.newCard(ident, null); // no attached certificate

        // Check that retrieving a private field prior to authentication does not return the field value
        PostalAddress addr = card.getPostalAddress();
        assertNull(addr); // Because postalAddress is private by default and card owner is not yet authenticated
        assertNull(card.getUIN()); // Because UIN is private by default and card owner is not yet authenticated

        // Card owner authenticates with his pin code
        card.authenticateWithPIN("1234");

        // Check that previously hidden fields are now visible after authentication
        addr = card.getPostalAddress();
        assertNotNull(addr); // postalAddress now visible after success authentication
        assertEquals(addr.getAddressLinesCount(), 2);
        assertTrue(addr.getAddressLines(0).equals("526 N Plymouth Blvd"));
        assertTrue(addr.getAddressLines(1).equals("Los Angeles, CA US"));
        assertTrue(addr.getRegionCode().equals("5"));
        assertTrue(addr.getLanguageCode().equals("en"));
        assertTrue(addr.getPostalCode().equals("90004"));
        assertEquals(card.getUIN(), "4957694814");
    }

    @Test
    @DisplayName("Test visibility of identity fields when a card is created")
    public void testVisibilityFlags()
            throws IDPassException, IOException, ParseException {
        // Prepare data structure and fill-in with identity information
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

        // Initialize reader with keyset and no certificates
        IDPassReader reader = new IDPassReader(m_keyset, null);

        // Configure reader to render the below detail fields as publicly visible
        reader.setDetailsVisible(
                IDPassReader.DETAIL_GIVENNAME |
                IDPassReader.DETAIL_SURNAME |
                IDPassReader.DETAIL_DATEOFBIRTH |
                IDPassReader.DETAIL_PLACEOFBIRTH |
                IDPassReader.DETAIL_POSTALADDRESS);

        // Create an ID PASS lite card from the filled-in ident data structure
        Card card = reader.newCard(ident, null); // The generated card is not using certificate

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd");

        // Check that the configured fields are visible prior to authentication
        assertEquals(card.getGivenName(),"MARION FLORENCE");
        assertEquals(card.getSurname(),"DUPONT");
        assertTrue(card.getDateOfBirth().compareTo(sdf.parse("1985/1/1")) == 0);
        assertEquals(card.getPlaceOfBirth(),"Paris, France");
        assertNotNull(card.getPostalAddress());

        // Check that the fullName is not visible prior to authentication
        assertNull(card.getfullName());

        // Now, card owner authenticates with pin code
        card.authenticateWithPIN("1234");

        // Check that the fullName is now visible once authenticated
        assertEquals(card.getfullName(), "MRS. MARION FLORENCE DUPONT");
    }

    /**
     * Merge two CardDetails into one
     */
	//@Disabled
    @Test
    @DisplayName("Merge two card details into one")
    public void testMergeDetails() throws InvalidProtocolBufferException {
        // Create first detail
        CardDetails d1 = CardDetails.newBuilder()
                .setFullName("John Murdoch")
                .build();
        // Create second detail
        CardDetails d2 = CardDetails.newBuilder()
                .setGivenName("JOHN")
                .setSurName("MURDOCH")
                .build();

        // Merge the two details into one
        CardDetails merged = IDPassReader.mergeCardDetails(d1,d2);

        // Check that merged detail should have 3 fields and that each field match values
        assertEquals(merged.getAllFields().keySet().size(), 3);
        assertEquals(merged.getFullName(), "John Murdoch");
        assertEquals(merged.getSurName(), "MURDOCH");
        assertEquals(merged.getGivenName(), "JOHN");

        // Merge the two details, to make sure that the order does not matter
        merged = IDPassReader.mergeCardDetails(d2,d1);

        // Check that merged detail should have 3 fields and that each field match values
        assertEquals(merged.getAllFields().keySet().size(), 3);
        assertEquals(merged.getFullName(), "John Murdoch");
        assertEquals(merged.getSurName(), "MURDOCH");
        assertEquals(merged.getGivenName(), "JOHN");

        // Create Date object and add this new field to first detail
        org.idpass.lite.proto.Date dob = org.idpass.lite.proto.Date.newBuilder()
                .setYear(1967)
                .setMonth(10)
                .setDay(29)
                .build();

        // Add dob into d1 CardDetails
        d1 = d1.toBuilder().setDateOfBirth(dob).build();
        // Merge again the two details
        merged = IDPassReader.mergeCardDetails(d2,d1);

        // Check that merged detail should now have 4 fields and that each field match values
        assertEquals(merged.getAllFields().keySet().size(), 4);
        assertEquals(merged.getFullName(), "John Murdoch");
        assertEquals(merged.getSurName(), "MURDOCH");
        assertEquals(merged.getGivenName(), "JOHN");
        assertTrue(
            merged.getDateOfBirth().getYear() == dob.getYear() &&
            merged.getDateOfBirth().getMonth() == dob.getMonth() &&
            merged.getDateOfBirth().getDay() == dob.getDay());

        // Create list of key/value pairs and add it to first details
        List<Pair> extras = new ArrayList<>();
        extras.add(Pair.newBuilder().setKey("Weight").setValue("152 lbs").build());
        extras.add(Pair.newBuilder().setKey("Hair Color").setValue("black").build());

        // Add extras to d1 CardDetails
        for (Pair x : extras) {
            d1 = d1.toBuilder().addExtra(x).build();
        }

        extras.clear(); // empty out data structure

        // Create list of key/value pairs and add it to second details
        extras.add(Pair.newBuilder().setKey("Eye Color").setValue("Hazel").build());
        extras.add(Pair.newBuilder().setKey("Height").setValue("6 feet").build());
        extras.add(Pair.newBuilder().setKey("ID Type").setValue("Drivers' license").build());

        // Add extras to d2 CardDetails
        for (Pair x : extras) {
            d2 = d2.toBuilder().addExtra(x).build();
        }

        PostalAddress address = PostalAddress.newBuilder()
                .addAddressLines("526 N Plymouth Blvd")
                .addAddressLines("Los Angeles, CA US")
                .setRegionCode("5")
                .setLanguageCode("en")
                .setPostalCode("90004")
                .build();

        d2 = d2.toBuilder().setPostalAddress(address).build();

        // Merge again the two details
        merged = IDPassReader.mergeCardDetails(d1,d2);

        // Check if every fields got merged including the merged key/value pairs
        // and postal address
        assertEquals(merged.getAllFields().keySet().size(), 6);
        assertEquals(merged.getFullName(), "John Murdoch");
        assertEquals(merged.getSurName(), "MURDOCH");
        assertEquals(merged.getGivenName(), "JOHN");
        assertTrue(
            merged.getDateOfBirth().getYear() == dob.getYear() &&
            merged.getDateOfBirth().getMonth() == dob.getMonth() &&
            merged.getDateOfBirth().getDay() == dob.getDay());
        assertEquals(merged.getExtraCount(), d1.getExtraCount() + d2.getExtraCount());

        List<Pair> mergedExtras = Stream.concat(
            d1.getExtraList().stream(),
            d2.getExtraList().stream())
        .collect(Collectors.toList());

        for (Pair x : mergedExtras) {
            assertTrue(merged.getExtraList().contains(x));
        }

        assertArrayEquals(merged.getPostalAddress().toByteArray(),
                address.toByteArray());
    }

    /**
     * Tests write/read of entries in p12 keystore file
     *
     * @throws IOException If wrong keystore password
     * @throws IDPassException If wrong keystore password
     */
    @Test
    @DisplayName("Write and read back random entry values into a keystore file")
    public void writeReadKeyStoreEntryTest()
        throws IOException, IDPassException
    {
        SecureRandom sr = new SecureRandom();
        // Generate keystore file password and key password
        String keystorePass =  Helper.randomString(64);
        String keyPass = Helper.randomString(64);
        // Keystore entries are just blobs of byte arrays with user-specific meanings
        byte[] buf1 = new byte[13];
        byte[] buf2 = new byte[64];
        byte[] buf3 = new byte[256];
        // Populate random bytes for each keystore entry
        sr.nextBytes(buf1);
        sr.nextBytes(buf2);
        sr.nextBytes(buf3);

        // Create keystore empty test file
        File keystorefile = File.createTempFile("tmp", null);
        // Store the blobs buf1 and buf2 under keyentry1
        // Store the blob buf3 under keyentry2
        Helper.writeKeyStoreEntry("keyentry1", keystorefile, keystorePass, keyPass, buf1, buf2);
        Helper.writeKeyStoreEntry("keyentry2", keystorefile, keystorePass, keyPass, buf3);

        // Read back keyentry1
        byte[][] entry = Helper.readKeyStoreEntry("keyentry1", new FileInputStream(keystorefile), keystorePass, keyPass);
        // Verify that the entry has two blobs and that they match values
        assertEquals(entry.length, 2);
        assertArrayEquals(buf1, entry[0]);
        assertArrayEquals(buf2, entry[1]);

        // Read back keyentry2
        entry = Helper.readKeyStoreEntry("keyentry2", new FileInputStream(keystorefile), keystorePass, keyPass);
        // Verify that the entry has one blob and that it match value
        assertEquals(entry.length, 1);
        assertArrayEquals(buf3, entry[0]);

        keystorefile.delete(); // delete keystore test file
    }
}
