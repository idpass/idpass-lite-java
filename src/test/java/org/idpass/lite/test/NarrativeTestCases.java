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
import org.idpass.lite.Card;
import org.idpass.lite.IDPassHelper;
import org.idpass.lite.IDPassLite;
import org.idpass.lite.IDPassReader;
import org.idpass.lite.exceptions.CardVerificationException;
import org.idpass.lite.exceptions.IDPassException;
import org.idpass.lite.exceptions.InvalidCardException;
import org.idpass.lite.proto.*;
import org.idpass.lite.test.utils.Helper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Each narrative test case shall adhere to the following conventions:
 *
 * 1) Each test case is narrated to describe its flow. Attendant circumstances
 *    are described to provide additional context.
 *
 * 2) Each test case pivots around one theme.
 *
 * 3) KeySet objects shall use the variable names ks1, ks2, ... ks<n> when
 *    several of them are required in a particular test case. Otherwise,
 *    the singular variable name ks is used.
 *
 * 4) IDPassReader objects shall use the variable names reader1,reader2, ... reader<n> when
 *    several of them are required in a particular test case. Otherwise,
 *    the singular variable name reader is used.
 *
 * 5) Card objects shall use the variable names card1, card2, ... card<n> when
 *    several of them are required in a particular test case. Otherwise, the singular
 *    variable name card is used.
 *
 * 6) Each test case that requires identity information shall use the pre-populated
 *    and fixed m_ident data structure.
 *
 * 8) The variable name leafcert is specially designated to the certificate of a reader's pk
 *    where pk ∈ KeySet::signaturekey
 *
 * 9) Take note of the following phrases (attached vs configured) convention and their meanings:
 *    - Certificate attached in a card     = Is the intermediate certificate embedded inside the QR code.
 *    - Certificate configured in a reader = Is the self-signed root certificate set in a reader instance
 */

public class NarrativeTestCases {

	static {
        IDPassLite.initialize();
	}

    // Protobuf data structure that is filled with identity details.
    // An ID PASS lite card is generated from this data structure.

    Ident m_ident = Ident.newBuilder()
            .setUIN("4957694814")
            .setPhoto(ByteString.copyFrom(Files.readAllBytes(Paths.get("testdata/florence.jpg"))))
            .setGivenName("MARION FLORENCE")
            .setSurName("DUPONT")
            .setFullName("Dr. Marion Florence Dupont")
            .setGender(1)
            .setPin("1234")
            .setDateOfBirth(Date.newBuilder().setYear(1985).setMonth(1).setDay(1))
            .addPubExtra(Pair.newBuilder().setKey("Nationality").setValue("French"))
            .addPubExtra(Pair.newBuilder().setKey("Date Of Issue").setValue("02 JAN 2025"))
            .addPubExtra(Pair.newBuilder().setKey("Date Of Expiry").setValue("01 JAN 2035"))
            .addPubExtra(Pair.newBuilder().setKey("ID").setValue("SA437277"))
            .addPrivExtra(Pair.newBuilder().setKey("SS Number").setValue("2 85 01 75 116 001 42"))
            .setPostalAddress(PostalAddress.newBuilder()
                .addAddressLines("526 N Plymouth Blvd")
                .addAddressLines("Los Angeles, CA US")
                .setRegionCode("5")
                .setLanguageCode("en")
                .setPostalCode("90004")
                .build())
            .build();

    public NarrativeTestCases() throws IOException {

    }

    @Test
    @DisplayName("Testing two readers opening a card without a certificate")
    public void two_readers_without_certificate() throws IDPassException, InvalidProtocolBufferException {

        KeySet ks1 = KeySet.newBuilder()
            .setEncryptionKey(IDPassHelper.generateEncryptionKeyAsByteString())
            .setSignatureKey(IDPassHelper.generateSecretSignatureKeyAsByteString())
            .build();

        // Initialize our first reader without root certificate(s)
        IDPassReader reader1 = new IDPassReader(ks1, null);

        // Generate an ID PASS lite card without an attached certificate(s)
        Card card = reader1.newCard(m_ident, null);

        // Re-opening the card with the same reader
        assertNotNull(reader1.open(card.asBytes()));

        // But a tampered card1 could not be opened.
        assertThrows(InvalidCardException.class, () -> {
            byte[] buf = card.asBytes();
            buf[8] = 'x'; // tamper value of one byte to a different value
            reader1.open(buf);
        });

        // We can check that card1 has no attached certificate(s)
        assertFalse(card.hasCertificate());

        // Because card1 has no attached certificate, so no certificate verification is possible.
        assertFalse(card.verifyCertificate());

        // However, card1's signature can be computed against its contents.
        // And if card1's signer key is in reader1's trusted verification keys, then
        // card1's signature is valid
        assertTrue(card.verifyCardSignature());

        // All detail fields are hidden by default prior to authentication
        assertEquals("",card.getDetails().getSurName());
        assertEquals("",card.getDetails().getGivenName());
        assertEquals("",card.getDetails().getFullName());

        card.authenticateWithPIN("1234");

        // All detail fields are now visible after authentication
        assertEquals(m_ident.getSurName(),card.getDetails().getSurName());
        assertEquals(m_ident.getGivenName(),card.getDetails().getGivenName());
        assertEquals(m_ident.getFullName(),card.getDetails().getFullName());

        ////////////// Let us create a second reader2 with different keyset ////////////////

        KeySet ks2 = KeySet.newBuilder()
            .setEncryptionKey(IDPassHelper.generateEncryptionKeyAsByteString())
            .setSignatureKey(IDPassHelper.generateSecretSignatureKeyAsByteString())
            .build();

        IDPassReader reader2 = new IDPassReader(ks2, null);

        // card1's signature can be computed against its contents.
        // However card1's signer key is missing in reader2's trusted verification keys.
        // Therefore, reader2 cannot open card1.
        assertThrows(InvalidCardException.class,() ->
            reader2.open(card.asBytes())
        );
    }

    @Test
    @DisplayName("A reader with no configured root certificate cannot create a card with certificate")
    public void reader_with_no_certificate() throws IDPassException {

        KeySet ks = KeySet.newBuilder()
                .setEncryptionKey(IDPassHelper.generateEncryptionKeyAsByteString())
                .setSignatureKey(IDPassHelper.generateSecretSignatureKeyAsByteString())
                .build();

        byte[] rootkey = IDPassHelper.generateSecretSignatureKey();

        // Notice that the reader is initialized without a root certificate.
        // And then it tries to generate a card with an attached certificate.

        IDPassReader reader = new IDPassReader(ks, null);

        Certificate leafcert = IDPassReader.generateChildCertificate(rootkey,
                IDPassHelper.getPublicKey(ks.getSignatureKey().toByteArray()));
        Certificates certchain = Certificates.newBuilder().addCert(leafcert).build();

        // Therefore, the reader cannot generate a card, and throws an exception.
        assertThrows(InvalidCardException.class, () ->
            reader.newCard(m_ident, certchain)
        );
    }

    @Test
    @DisplayName("A reader configured with a root certificate cannot create a " +
            "card with a certificate that cannot anchor to the reader's root certificate")
    public void create_card_using_reader_with_certificate() throws IDPassException {

        KeySet ks = KeySet.newBuilder()
                .setEncryptionKey(IDPassHelper.generateEncryptionKeyAsByteString())
                .setSignatureKey(IDPassHelper.generateSecretSignatureKeyAsByteString())
                .build();

        byte[] rootkey1 = IDPassHelper.generateSecretSignatureKey();
        Certificate rootcert = IDPassReader.generateRootCertificate(rootkey1);
        Certificates rootcerts = Certificates.newBuilder().addCert(rootcert).build();

        // Notice that the reader is initialized with a certificate from rootkey1. Whereas,
        // certchain is a certificate that is anchored from rootkey2.

        IDPassReader reader = new IDPassReader(ks, rootcerts);

        byte[] rootkey2 = IDPassHelper.generateSecretSignatureKey();

        Certificate leafcert = IDPassReader.generateChildCertificate(rootkey2,
                IDPassHelper.getPublicKey(ks.getSignatureKey().toByteArray()));
        Certificates certchain = Certificates.newBuilder().addCert(leafcert).build();

        // Therefore, the reader cannot generate a card, and throws an exception
        assertThrows(InvalidCardException.class, () ->
                reader.newCard(m_ident, certchain)
        );
    }

    @Test
    @DisplayName("Card read using two readers having same encryption key and different signature key.")
    public void two_readers_same_encryptionkey() throws IDPassException {

        KeySet ks1 = KeySet.newBuilder()
                .setEncryptionKey(IDPassHelper.generateEncryptionKeyAsByteString())
                .setSignatureKey(IDPassHelper.generateSecretSignatureKeyAsByteString())
                .build();

        // Initialize our first reader without root certificate(s)
        IDPassReader reader1 = new IDPassReader(ks1, null);

        Card card1 = reader1.newCard(m_ident, null);

        KeySet ks2 = KeySet.newBuilder()
                .setEncryptionKey(ks1.getEncryptionKey())
                .setSignatureKey(IDPassHelper.generateSecretSignatureKeyAsByteString())
                .build();

        // Initialize our second reader without root certificate(s)
        IDPassReader reader2 = new IDPassReader(ks2, null);

        // Notice now that reader1 and reader2 have the same encryption key but
        // different ED25519 signature key.

        // And that reader2 cannot open card1 whether skip certificate flag is true or false.
        // Do observe that this boolean flag is irrelevant since card1 has no attached
        // certificate and both readers don't have configured root certificates either.
        assertThrows(InvalidCardException.class, () ->
                reader2.open(card1.asBytes())
        );

        assertThrows(InvalidCardException.class, () ->
                reader2.open(card1.asBytes(), true)
        );

        // Only reader1 can open and authenticate on card1
        assertDoesNotThrow(() -> reader1.open(card1.asBytes()));
        assertDoesNotThrow(() -> reader1.open(card1.asBytes(), true));
        assertDoesNotThrow(() -> reader1.open(card1.asBytes(), true).authenticateWithPIN("1234"));
    }

    @Test
    @DisplayName("Card read using two readers having same encryption key, different signature key and with certificate")
    public void two_readers_same_encryptionkey_with_certificate() throws IDPassException {

        KeySet ks1 = KeySet.newBuilder()
                .setEncryptionKey(IDPassHelper.generateEncryptionKeyAsByteString())
                .setSignatureKey(IDPassHelper.generateSecretSignatureKeyAsByteString())
                .build();

        ////////////// create a root certificate /////////////////
        byte[] rootkey = IDPassHelper.generateSecretSignatureKey();
        Certificate rootcert = IDPassReader.generateRootCertificate(rootkey);
        Certificates rootcertsA = Certificates.newBuilder().addCert(rootcert).build();
        /////////////////////////////////////////////////////////////////////////////

        // Initialize our first reader with root certificate
        IDPassReader reader1 = new IDPassReader(ks1, rootcertsA);

        /////////////// create intermediate certificate ////////////////////
        Certificate leafcert = IDPassReader.generateChildCertificate(rootkey,
                IDPassHelper.getPublicKey(ks1.getSignatureKey().toByteArray()));
        Certificates certchain = Certificates.newBuilder().addCert(leafcert).build();
        //////////////////////////////////////////////////////////////////////////////

        // Generate card1 using reader1
        Card card1 = reader1.newCard(m_ident, certchain);

        KeySet ks2 = KeySet.newBuilder()
                .setEncryptionKey(ks1.getEncryptionKey())
                .setSignatureKey(IDPassHelper.generateSecretSignatureKeyAsByteString())
                .build();

        // Initialize our second reader without root certificate
        IDPassReader reader2 = new IDPassReader(ks2, null);

        // Notice now that reader1 and reader2 have the same encryption key but
        // different ED25519 signature key.

        // And that reader2 cannot open card1 when card1's certificate is checked
        // because reader2 has no configured root certificates.
        assertThrows(InvalidCardException.class, () ->
                reader2.open(card1.asBytes())
        );

        // However, reader2 can open card1 if certificate check is skipped.
        Card card2 = reader2.open(card1.asBytes(), true);
        assertNotNull(card2);

        // But card2 cannot be authenticated because reader2 has no root certificate
        // to verify card2's certificate
        assertThrows(CardVerificationException.class, () ->
                card2.authenticateWithPIN("1234")
        );

        //////////// Let us create a third reader3 ////////////////

        //////////////// create root certificates /////////////////
        byte[] rootkey2 = IDPassHelper.generateSecretSignatureKey();
        Certificate rootcert2 = IDPassReader.generateRootCertificate(rootkey2);
        Certificates rootcertsB = Certificates.newBuilder()
                .addCert(rootcert)
                .addCert(rootcert2)
                .build();
        //////////////////////////////////////////////////////////////////////////////

        KeySet ks3 = KeySet.newBuilder()
                .setEncryptionKey(ks1.getEncryptionKey())
                .setSignatureKey(IDPassHelper.generateSecretSignatureKeyAsByteString())
                .build();

        // Notice that reader3 has same encryption key to reader1.
        // This enables reader3 to decrypt card1.

        IDPassReader reader3 = new IDPassReader(ks3, rootcertsB);

        // This succeeds because reader3's root certificates verifies card1's attached certificate.
        // Although reader3's signaturekey differs from reader1, but this key is not used when
        // card certificate is present.
        Card card3 = reader3.open(card1.asBytes());
        assertNotNull(card3);

        // This also succeeds because reader3's root certificate(s) verifies
        // card1's attached certificate. The reader3's trusted
        // verification key(s) is not used when a card has certificate.
        assertDoesNotThrow(() -> card3.authenticateWithPIN("1234"));
    }

    @Test
    @DisplayName("Two readers with same encryption key can open a card generated by the other")
    public void read_card_between_readers_same_encryptionkey() throws IDPassException, InvalidProtocolBufferException {

        KeySet ks1 = KeySet.newBuilder()
                .setEncryptionKey(IDPassHelper.generateEncryptionKeyAsByteString())
                .setSignatureKey(IDPassHelper.generateSecretSignatureKeyAsByteString())
                .build();

        ////////////// create a root certificate /////////////////
        byte[] rootkey = IDPassHelper.generateSecretSignatureKey();
        Certificate rootcert = IDPassReader.generateRootCertificate(rootkey);
        Certificates rootcertsA = Certificates.newBuilder().addCert(rootcert).build();
        /////////////////////////////////////////////////////////////////////////////

        /////////////// create intermediate certificate ////////////////////
        Certificate leafcert = IDPassReader.generateChildCertificate(rootkey,
                IDPassHelper.getPublicKey(ks1.getSignatureKey().toByteArray()));
        Certificates certchain = Certificates.newBuilder().addCert(leafcert).build();
        //////////////////////////////////////////////////////////////////////////////

        // Initialize our first reader with root certificate
        IDPassReader reader1 = new IDPassReader(ks1, rootcertsA);
        reader1.setDetailsVisible(IDPassReader.DETAIL_GIVENNAME);

        Card card1 = reader1.newCard(m_ident, certchain);

        KeySet ks2 = KeySet.newBuilder()
                .setEncryptionKey(ks1.getEncryptionKey())
                .setSignatureKey(IDPassHelper.generateSecretSignatureKeyAsByteString())
                .build();

        // Initialize our second reader with same encryption key,
        // different signature key and without root certificate
        IDPassReader reader2 = new IDPassReader(ks2, null);

        // Notice now that reader1 and reader2 have the same encryption key but
        // different ED25519 signature key, and that reader1 has root certificate
        // and reader2 has no root certificate.

        // reader2 cannot open card1 if certificate check is enabled, which is
        // the default behaviour of `open()`. It throws an exception.
        assertThrows(InvalidCardException.class, () ->
                reader2.open(card1.asBytes())
        );

        // However, reader2 can open card1 if certificate check is skipped. Note that,
        // reader1 is configured to generate cards with given name publicly visible.
        Card card2 = reader2.open(card1.asBytes(), true);
        assertNotNull(card2);
        assertEquals(m_ident.getGivenName(),card2.getDetails().getGivenName());

        // Other fields are not visible prior to authentication
        assertEquals("", card2.getDetails().getSurName());

        // However, card2 cannot be authenticated because reader2 has no root certificate
        // to verify card2's certificate
        assertThrows(CardVerificationException.class, () ->
                card2.authenticateWithPIN("1234")
        );

        // Therefore, only reader1 can fully worked on the card
        Card card3 = reader1.open(card2.asBytes());
        card3.authenticateWithPIN("1234");
        assertEquals(m_ident.getFullName(), card3.getDetails().getFullName());
    }

    @Test
    @DisplayName("Reading a card with a revoked attached certificate")
    public void card_certificate_is_revoked() throws IDPassException {

        KeySet ks = KeySet.newBuilder()
                .setEncryptionKey(IDPassHelper.generateEncryptionKeyAsByteString())
                .setSignatureKey(IDPassHelper.generateSecretSignatureKeyAsByteString())
                .build();

        ////////////// create a root certificate /////////////////
        byte[] rootkey = IDPassHelper.generateSecretSignatureKey();
        Certificate rootcert = IDPassReader.generateRootCertificate(rootkey);
        Certificates rootcertsA = Certificates.newBuilder().addCert(rootcert).build();
        /////////////////////////////////////////////////////////////////////////////

        IDPassReader reader1 = new IDPassReader(ks, rootcertsA);

        /////////// create intermediate certificate /////////////////////////
        Certificate leafcert = IDPassReader.generateChildCertificate(rootkey,
                IDPassHelper.getPublicKey(ks.getSignatureKey().toByteArray()));
        Certificates certchain = Certificates.newBuilder().addCert(leafcert).build();
        //////////////////////////////////////////////////////////////////////////////

        Card card = reader1.newCard(m_ident, certchain);

        // Revoke a certificate public key. This revocation is shared by all reader instances
        IDPassReader.addRevokedKey(IDPassHelper.getPublicKey(rootkey)); // ∀

        // The card can no longer be authenticated because its certificate (or chain) has been revoked
        assertThrows(CardVerificationException.class, () -> card.authenticateWithPIN("1234"));

        IDPassReader reader2 = new IDPassReader(ks, rootcertsA);

        // A card with a revoked certificate (or chain) cannot be opened by default
        assertThrows(InvalidCardException.class, () -> reader2.open(card.asBytes()));

        // But it can be opened if certificate check is skipped
        assertDoesNotThrow(() -> reader2.open(card.asBytes(), true));
    }

    @Test
    @DisplayName("Save a reader's configuration to a PKCS12 file")
    public void save_reader_configuration() throws IDPassException, IOException {

        File p12File = File.createTempFile("readerconfig", ".p12");

        KeySet ks = KeySet.newBuilder()
                .setEncryptionKey(IDPassHelper.generateEncryptionKeyAsByteString())
                .setSignatureKey(IDPassHelper.generateSecretSignatureKeyAsByteString())
                .build();

        ////////////// create a root certificate /////////////////
        byte[] rootkey = IDPassHelper.generateSecretSignatureKey();
        Certificate rootcert = IDPassReader.generateRootCertificate(rootkey);
        Certificates rootcertsA = Certificates.newBuilder().addCert(rootcert).build();
        /////////////////////////////////////////////////////////////////////////////

        // Initialize reader from test keyset and root certificate
        IDPassReader reader1 = new IDPassReader(ks, rootcertsA);

        /////////////// create intermediate certificate ////////////////////
        Certificate leafcert = IDPassReader.generateChildCertificate(rootkey,
                IDPassHelper.getPublicKey(ks.getSignatureKey().toByteArray()));
        Certificates certchain = Certificates.newBuilder().addCert(leafcert).build();
        //////////////////////////////////////////////////////////////////////////////

        Card card1 = reader1.newCard(m_ident, certchain);

        // Save the card to file system as a QR code image
        File qrFile = File.createTempFile("qrcode", ".jpg");
        ImageIO.write(Helper.toBufferedImage(card1), "jpg", qrFile);

        card1.authenticateWithPIN("1234");

        // Persist the reader's configuration to a keystore file
        String keystorePass = Helper.randomString(10);
        String keyPass = Helper.randomString(10);
        String keyAliasPrefix = "test";
        Helper.saveConfiguration(keyAliasPrefix, p12File, keystorePass, keyPass, ks, rootcertsA);

        // We can also save other blobs of data to the keystore file
        Helper.writeKeyStoreEntry("rootcertificatesprivatekeys",
                p12File, keystorePass, keyPass, rootkey);

        Helper.writeKeyStoreEntry("intermedcertificatesprivatekeys",
                p12File, keystorePass, keyPass, IDPassHelper.getPublicKey(ks.getSignatureKey().toByteArray()));

        InputStream is = new FileInputStream(p12File);
        IDPassReader reader2 = new IDPassReader(ks, rootcertsA);

        BufferedImage qrPic = ImageIO.read(qrFile);
        Card card2 = reader2.open(Helper.scanQRCode(qrPic));
        card2.authenticateWithPIN("1234");

        assertEquals(m_ident.getFullName(),card2.getDetails().getFullName());
        assertArrayEquals(card1.asBytes(), card2.asBytes());

        p12File.delete();
        qrFile.delete();
    }

    @Test
    @DisplayName("Test set and get an environment variable")
    public void environVarTest() {
        String name = "TESTVARNAME";
        String value = Helper.randomString(64);
        IDPassReader.setenv(name, value, true);
        String val = IDPassReader.getenv(name);
        assertEquals(value, val);
    }
}
