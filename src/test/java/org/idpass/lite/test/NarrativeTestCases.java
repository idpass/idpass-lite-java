package org.idpass.lite.test;

import com.google.protobuf.ByteString;
import org.api.proto.Certificates;
import org.api.proto.Ident;
import org.api.proto.KeySet;
import org.idpass.lite.Card;
import org.idpass.lite.IDPassHelper;
import org.idpass.lite.IDPassReader;
import org.idpass.lite.exceptions.CardVerificationException;
import org.idpass.lite.exceptions.IDPassException;
import org.idpass.lite.exceptions.InvalidCardException;
import org.idpass.lite.proto.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class NarrativeTestCases {

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
    @DisplayName("Test cases that are not using certificates")
    public void test1() throws IDPassException {

        KeySet ks1 = KeySet.newBuilder()
            .setEncryptionKey(IDPassHelper.generateEncryptionKeyAsByteString())
            .setSignatureKey(IDPassHelper.generateSecretSignatureKeyAsByteString())
            .build();

        // Initialize our first reader without root certificate(s)
        IDPassReader reader1 = new IDPassReader(ks1, null);

        // Generate an ID PASS lite card without an attached certificate(s)
        Card card1 = reader1.newCard(m_ident, null);

        // Since card1 is created from reader1, then reader1
        // can open card1 successfully
        assertNotNull(reader1.open(card1.asBytes()));

        // But a tampered card1 could not be opened.
        assertThrows(InvalidCardException.class, () -> {
            byte[] buf = card1.asBytes();
            buf[8] = 'x'; // tamper value of one byte to a different value
            reader1.open(buf);
        });

        // We can check that card1 has no attached certificate(s)
        assertFalse(card1.hasCertificate());

        // Because card1 has no attached certificate, so no certificate verification is possible.
        assertFalse(card1.verifyCertificate());

        // However, card1's signature can be computed against its contents.
        // And if card1's signer key is in reader1's trusted verification keys, then
        // card1's signature is valid
        assertTrue(card1.verifyCardSignature());

        // All detail fields are hidden by default prior to authentication
        assertEquals(card1.getDetails().getSurName(),"");
        assertEquals(card1.getDetails().getGivenName(),"");
        assertEquals(card1.getDetails().getFullName(),"");

        card1.authenticateWithPIN("1234");

        // All detail fields are now visible after authentication
        assertEquals(card1.getDetails().getSurName(),m_ident.getSurName());
        assertEquals(card1.getDetails().getGivenName(),m_ident.getGivenName());
        assertEquals(card1.getDetails().getFullName(),m_ident.getFullName());

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
            reader2.open(card1.asBytes())
        );
    }

    @Test
    @DisplayName("A reader with no configured root certificate cannot create a card with certificate")
    public void test2() throws IDPassException {
        byte[] sk = IDPassHelper.generateSecretSignatureKey();

        KeySet ks = KeySet.newBuilder()
                .setEncryptionKey(IDPassHelper.generateEncryptionKeyAsByteString())
                .setSignatureKey(ByteString.copyFrom(sk))
                .build();

        byte[] rootkey = IDPassHelper.generateSecretSignatureKey();

        // Notice that the reader is initialized without a root certificate.
        // And then it tries to generate a card with an attached certificate.

        IDPassReader reader = new IDPassReader(ks, null);

        Certificate leafcert = IDPassReader.generateChildCertificate(rootkey,
                Arrays.copyOfRange(sk, 32, 64));
        Certificates certchain = Certificates.newBuilder().addCert(leafcert).build();

        // Therefore, the reader cannot generate a card, and throws an exception.
        assertThrows(InvalidCardException.class, () ->
            reader.newCard(m_ident, certchain)
        );
    }

    @Test
    @DisplayName("A reader configured with a root certificate cannot create a " +
            "card with a certificate that cannot anchor to the reader's root certificate")
    public void test3() throws IDPassException {

        byte[] sk = IDPassHelper.generateSecretSignatureKey();

        KeySet ks = KeySet.newBuilder()
                .setEncryptionKey(IDPassHelper.generateEncryptionKeyAsByteString())
                .setSignatureKey(ByteString.copyFrom(sk))
                .build();

        byte[] rootkey1 = IDPassHelper.generateSecretSignatureKey();
        Certificate rootcert = IDPassReader.generateRootCertificate(rootkey1);
        Certificates rootcerts = Certificates.newBuilder().addCert(rootcert).build();

        byte[] rootkey2 = IDPassHelper.generateSecretSignatureKey();

        // Notice that the reader is initialized with a certificate from rootkey1. Whereas,
        // certchain is a certificate that is anchored from rootkey2.

        IDPassReader reader = new IDPassReader(ks, rootcerts);

        Certificate leafcert = IDPassReader.generateChildCertificate(rootkey2,
                Arrays.copyOfRange(sk, 32, 64));
        Certificates certchain = Certificates.newBuilder().addCert(leafcert).build();

        // Therefore, the reader cannot generate a card, and throws an exception
        assertThrows(InvalidCardException.class, () ->
                reader.newCard(m_ident, certchain)
        );
    }

    @Test
    @DisplayName("Two readers with same encryption key only")
    public void test4() throws IDPassException {

        ByteString encryptionKey = IDPassHelper.generateEncryptionKeyAsByteString();

        KeySet ks1 = KeySet.newBuilder()
                .setEncryptionKey(encryptionKey)
                .setSignatureKey(IDPassHelper.generateSecretSignatureKeyAsByteString())
                .build();

        // Initialize our first reader without root certificate(s)
        IDPassReader reader1 = new IDPassReader(ks1, null);

        Card card1 = reader1.newCard(m_ident, null);

        KeySet ks2 = KeySet.newBuilder()
                .setEncryptionKey(encryptionKey)
                .setSignatureKey(IDPassHelper.generateSecretSignatureKeyAsByteString())
                .build();

        // Initialize our second reader without root certificate(s)
        IDPassReader reader2 = new IDPassReader(ks2, null);

        // Notice now that reader1 and reader2 have the same encryption key but
        // different ED25519 signature key.

        // And that reader2 cannot open card1 wither skip certificate flag is true or false.
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
    @DisplayName("Same as test4, but this time certificates are used")
    public void test5() throws IDPassException {
        ByteString encryptionKey = IDPassHelper.generateEncryptionKeyAsByteString();
        byte[] sk = IDPassHelper.generateSecretSignatureKey();

        KeySet ks1 = KeySet.newBuilder()
                .setEncryptionKey(encryptionKey)
                .setSignatureKey(ByteString.copyFrom(sk))
                .build();

        ////////////// create a root certificate /////////////////
        byte[] rootkey = IDPassHelper.generateSecretSignatureKey();
        Certificate rootcert = IDPassReader.generateRootCertificate(rootkey);
        Certificates rootcertsA = Certificates.newBuilder().addCert(rootcert).build();
        /////////////////////////////////////////////////////////////////////////////

        /////////////// create intermediate certificate ////////////////////
        Certificate leafcert = IDPassReader.generateChildCertificate(rootkey,
                Arrays.copyOfRange(sk, 32, 64));
        Certificates certchain = Certificates.newBuilder().addCert(leafcert).build();
        //////////////////////////////////////////////////////////////////////////////

        // Initialize our first reader with root certificate
        IDPassReader reader1 = new IDPassReader(ks1, rootcertsA);
        // Generate card1 using reader1
        Card card1 = reader1.newCard(m_ident, certchain);

        KeySet ks2 = KeySet.newBuilder()
                .setEncryptionKey(encryptionKey)
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
                .setEncryptionKey(encryptionKey)
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
    @DisplayName("Two readers sharing same encryption key can open a card generated by the other")
    public void test6() throws IDPassException {
        ByteString encryptionKey = IDPassHelper.generateEncryptionKeyAsByteString();
        byte[] sk = IDPassHelper.generateSecretSignatureKey();

        KeySet ks1 = KeySet.newBuilder()
                .setEncryptionKey(encryptionKey)
                .setSignatureKey(ByteString.copyFrom(sk))
                .build();

        ////////////// create a root certificate /////////////////
        byte[] rootkey = IDPassHelper.generateSecretSignatureKey();
        Certificate rootcert = IDPassReader.generateRootCertificate(rootkey);
        Certificates rootcertsA = Certificates.newBuilder().addCert(rootcert).build();
        /////////////////////////////////////////////////////////////////////////////

        /////////////// create intermediate certificate ////////////////////
        Certificate leafcert = IDPassReader.generateChildCertificate(rootkey,
                Arrays.copyOfRange(sk, 32, 64));
        Certificates certchain = Certificates.newBuilder().addCert(leafcert).build();
        //////////////////////////////////////////////////////////////////////////////

        // Initialize our first reader with root certificate
        IDPassReader reader1 = new IDPassReader(ks1, rootcertsA);
        reader1.setDetailsVisible(IDPassReader.DETAIL_GIVENNAME);

        Card card1 = reader1.newCard(m_ident, certchain);

        KeySet ks2 = KeySet.newBuilder()
                .setEncryptionKey(encryptionKey)
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
        assertEquals(card2.getDetails().getGivenName(), m_ident.getGivenName());

        // Other fields are not visible prior to authentication
        assertEquals(card2.getDetails().getSurName(), "");

        // However, card2 cannot be authenticated because reader2 has no root certificate
        // to verify card2's certificate
        assertThrows(CardVerificationException.class, () ->
                card2.authenticateWithPIN("1234")
        );

        // Therefore, only reader1 can fully worked on the card
        Card card3 = reader1.open(card2.asBytes());
        card3.authenticateWithPIN("1234");
        assertEquals(card3.getDetails().getFullName(), m_ident.getFullName());
    }

    @Test
    @DisplayName("TODO")
    public void test7() {

    }

    @Test
    @DisplayName("TODO")
    public void test8() {

    }

    @Test
    @DisplayName("TODO")
    public void test9() {

    }
}
