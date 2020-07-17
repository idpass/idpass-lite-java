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

import com.google.zxing.NotFoundException;
import org.idpass.lite.IDPassHelper;
import org.idpass.lite.Card;
import org.idpass.lite.IDPassReader;
import org.idpass.lite.exceptions.CardVerificationException;
import org.idpass.lite.exceptions.IDPassException;
import org.idpass.lite.exceptions.NotVerifiedException;
import org.junit.Test;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.*;

public class TestCases {
    byte[] encryptionkey    = IDPassHelper.generateEncryptionKey();
    byte[] signaturekey     = IDPassHelper.generateSecretSignatureKey();

    private Card newTestCard(IDPassReader reader) throws IDPassException, IOException {
        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));

        HashMap<String, String> pubExtras = new HashMap<String, String>();
        HashMap<String, String> privExtras = new HashMap<String, String>();
        privExtras.put("age","35");
        privExtras.put("address","16th Elm Street");
        pubExtras.put("gender","male");
        pubExtras.put("sports","boxing");

        Card card = reader.newCard(
                "John",
                "Doe",
                new Date(),
                "Aubusson, France",
                pubExtras,
                privExtras,
                photo,
                "1234");
        return card;
    }

    @Test
    public void testcreateCard()
            throws IOException, IDPassException {

        IDPassReader reader = new IDPassReader(encryptionkey, signaturekey);

        byte[] photo = Files.readAllBytes(Paths.get("testdata/manny1.bmp"));

        Card card = reader.newCard(
                "John",
                "Doe",
                new Date(),
                "Aubusson, France",
                null,
                null,
                photo,
                "1234");

        assertNotNull(card);
        assertTrue(card.asBytes().length > 0);
    }

    @Test
    public void testPinCode() throws IOException, IDPassException {
        IDPassReader reader = new IDPassReader(encryptionkey, signaturekey);
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
        IDPassReader reader = new IDPassReader(encryptionkey, signaturekey);
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
        assertNotEquals(0, card.getGivenName().length());
        assertNotEquals(0, card.getSurname().length());
        assertNotEquals(0, card.getPlaceOfBirth().length());
        assertNotNull(card.getDateOfBirth());
    }

    @Test
    public void testDataVisibility2() throws IOException, IDPassException {
        IDPassReader reader = new IDPassReader(encryptionkey, signaturekey);

        reader.setDetailsVisible(
                IDPassReader.DETAIL_GIVENNAME |
                        IDPassReader.DETAIL_PLACEOFBIRTH);

        Card card = newTestCard(reader);

        assertNotEquals(0, card.getGivenName().length());
        assertEquals(0, card.getSurname().length());
        assertNull(card.getDateOfBirth());
        assertNotEquals(0, card.getPlaceOfBirth().length());


        try {
            card.authenticateWithPIN("1234");
        } catch (CardVerificationException e) {
            assertTrue(false);
        }
        assertNotNull(card.getGivenName());
        assertNotNull(card.getSurname());
        assertNotNull(card.getPlaceOfBirth());
        assertNotNull(card.getDateOfBirth());
    }

    @Test
    public void testFace() throws IOException, IDPassException {
        IDPassReader reader = new IDPassReader(encryptionkey, signaturekey);

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
        IDPassReader reader = new IDPassReader(encryptionkey, signaturekey);
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
        IDPassReader reader = new IDPassReader(encryptionkey, signaturekey);
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
        IDPassReader reader = new IDPassReader(encryptionkey, signaturekey);
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
        IDPassReader reader = new IDPassReader(encryptionkey, signaturekey);
        Card card = newTestCard(reader);

        BufferedImage qrCode = card.asQRCode();
        assertTrue(qrCode.getHeight() > 50);
        assertTrue(qrCode.getWidth() > 50);

        Card readCard = reader.open(qrCode);
        assertNotNull(readCard);
        assertArrayEquals(card.asBytes(), readCard.asBytes());
    }

    @Test
    public void testGetQRCodeFromPhoto() throws IOException, IDPassException, NotFoundException {
        byte[] verificationKey = {42, 68, -30, -58, 75, 118, 93, -106, 80, -106, -20, -43, 75, -43, 97, 48, 115, 101, 91, -122, -12, -79, 124, 74, -40, -76, 55, -108, 79, -124, 59, 62};

        IDPassReader reader = new IDPassReader(encryptionkey, signaturekey, new byte[][]{verificationKey});

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

        IDPassReader reader = new IDPassReader(encryptionkey, signaturekey);

        Card card = newTestCard(reader);

        byte[][] wrongVerificationkeys = new byte[1][];
        wrongVerificationkeys[0] = wrongVerificationkey;
        reader = new IDPassReader(encryptionkey, signaturekey, wrongVerificationkeys);

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

        IDPassReader reader = new IDPassReader(encryptionkey, signaturekey);

        Card card = newTestCard(reader);

        byte[][] otherVerificationkeys = new byte[2][];
        otherVerificationkeys[0] = otherVerificationkey;
        otherVerificationkeys[1] = Arrays.copyOfRange(signaturekey,32,64);;
        reader = new IDPassReader(encryptionkey, signaturekey, otherVerificationkeys);

        Card newCard = reader.open(card.asBytes());

        newCard.authenticateWithPIN("1234");

        otherVerificationkeys = new byte[2][];
        otherVerificationkeys[1] = otherVerificationkey;
        otherVerificationkeys[0] = Arrays.copyOfRange(signaturekey,32,64);;
        reader = new IDPassReader(encryptionkey, signaturekey, otherVerificationkeys);

        newCard = reader.open(card.asBytes());

        newCard.authenticateWithPIN("1234");
    }
}
