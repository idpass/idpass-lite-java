package org.idpass.lite.test;

import com.google.protobuf.ByteString;
import org.api.proto.Certificates;
import org.api.proto.Ident;
import org.api.proto.KeySet;
import org.idpass.lite.Card;
import org.idpass.lite.IDPassHelper;
import org.idpass.lite.IDPassReader;
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

        Certificate childcert = IDPassReader.generateChildCertificate(rootkey,
                Arrays.copyOfRange(sk, 32, 64));
        Certificates certchain = Certificates.newBuilder().addCert(childcert).build();

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

        Certificate childcert = IDPassReader.generateChildCertificate(rootkey2,
                Arrays.copyOfRange(sk, 32, 64));
        Certificates certchain = Certificates.newBuilder().addCert(childcert).build();

        // Therefore, the reader cannot generate a card, and throws an exception
        assertThrows(InvalidCardException.class, () ->
                reader.newCard(m_ident, certchain)
        );
    }

    @Test
    @DisplayName("TODO")
    public void test4() {

    }

    @Test
    @DisplayName("TODO")
    public void test5() {

    }

    @Test
    @DisplayName("TODO")
    public void test6() {

    }
}

