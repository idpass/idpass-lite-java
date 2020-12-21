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

package org.idpass.lite;

import com.google.protobuf.InvalidProtocolBufferException;
import org.api.proto.Certificates;
import org.api.proto.Ident;
import org.idpass.lite.proto.*;
import org.idpass.lite.exceptions.CardVerificationException;
import org.idpass.lite.exceptions.IDPassException;
import org.idpass.lite.exceptions.InvalidCardException;
import org.idpass.lite.exceptions.NotVerifiedException;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.Date;

/**
 * An abstract representation of an ID PASS Card
 */
public class Card {
    private IDPassReader reader;
    private IDPassCards cards;
    private CardDetails privateCardDetails = null;
    private CardDetails publicCardDetails = null;
    private boolean isAuthenticated = false;
    private byte[] cardPublicKey = null;
    private byte[] cardAsByte = null;

    private HashMap<String, Object> cardDetails = new HashMap<String, Object>();
    private HashMap<String, String> cardExtras = new HashMap<String, String>();

    /**
     * Returns publicly visible details. Returns
     * a merge of publicly visible details and
     * private details if authenticated.
     * @return Identity field details
     */

    public CardDetails getDetails() {
        CardDetails details = publicCardDetails;
        if (isAuthenticated) {
            details = IDPassHelper.mergeCardDetails(
                publicCardDetails, privateCardDetails);
        }
        return details;
    }

    /**
     * This constructor is used to create a new ID PASS Card.
     * @param idPassReader The reader instance
     * @param ident The person details
     * @param certificates Certificate chain
     * @throws IDPassException ID PASS exception
     */
    protected Card(IDPassReader idPassReader, Ident ident,
                Certificates certificates) throws IDPassException {
        this.reader = idPassReader;
        byte[] card = this.reader.createNewCard(ident, certificates);

        try {
            this.cards = IDPassCards.parseFrom(card);
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidCardException();
        }
        this.cardAsByte = card;
        updateDetails();
    }

    public boolean hasCertificate()
    {
        return this.cards.getCertificatesCount() > 0 ? true : false;
    }

    /**
     * Verify the signature using certificate chain.
     *
     * @return True Returns true if certificate chain
     * validates and verifies the IDPassCard's signature.
     */

    public boolean verifyCertificate()
    {
        try {
            IDPassCards fullcard = IDPassCards.parseFrom(cardAsByte);
            int nCerts = reader.verifyCardCertificate(fullcard);
            return (nCerts < 0) ? false : true;
        } catch (InvalidProtocolBufferException e) {
            return false;
        }
    }

    /**
     * Parse and wrap a card
     * @param idPassReader The reader instance
     * @param card The QR code content byte array
     * @throws IDPassException custom exception
     */
    public Card(IDPassReader idPassReader, byte[] card)
            throws IDPassException
    {
        this.reader = idPassReader;

        try {
            this.cards = IDPassCards.parseFrom(card);
        } catch (InvalidProtocolBufferException e) {
            throw new IDPassException();
        }

        this.cardAsByte = card;

        updateDetails();
    }

    /**
     *
     * @return True of certificate is valid
     */
    public boolean verifyCardSignature()
    {
        try {
            IDPassCards fullcard = IDPassCards.parseFrom(cardAsByte);
            if (!this.reader.verifyCardSignature(fullcard)) {
                return false;
            }
        } catch (InvalidProtocolBufferException e) {
            return false;
        }

        return true;
    }

    /**
     *
     * @return true if the PIN or Face has been verified
     */

    public boolean isAuthenticated() {
        return isAuthenticated;
    }

    /**
     * Match the face present in the photo with the one in the card.
     * If it match access to the private part of the card is given.
     * @param photo of the card holder
     * @throws CardVerificationException custom exception
     * @throws InvalidCardException custom exception
     */
    public void authenticateWithFace(byte[] photo) throws CardVerificationException, InvalidCardException {
        byte[] buf = this.reader.verifyCardWithFace(photo, cardAsByte);

        verifyAuth(buf);
    }

    /**
     * Match the pin with the one in the card
     * If it match access to the private part of the card is given.
     * @param pin Pin code of the card holder
     * @throws CardVerificationException custom exception
     * @throws InvalidCardException custom exception
     */
    public void authenticateWithPIN(String pin)
            throws CardVerificationException, InvalidCardException
    {
        byte[] buf = this.reader.verifyCardWithPin(pin, cardAsByte);
        verifyAuth(buf);
    }

    /**
     *
     * @param buf The byte array of the Details protobuf message
     * @throws CardVerificationException custom exception
     * @throws InvalidCardException custom exception
     */
    private void verifyAuth(byte[] buf) throws CardVerificationException, InvalidCardException {

        if (buf.length == 0) {
            throw new CardVerificationException();
        }
        try {
            this.privateCardDetails = CardDetails.parseFrom(buf);
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidCardException();
        }
        this.isAuthenticated = true;
        updateDetails();
    }

    /**
     *
     * @return Returns the public key of the card
     * @throws NotVerifiedException custom exception
     * @throws InvalidCardException custom exception
     */
    public byte[] getPublicKey() throws NotVerifiedException, InvalidCardException {
        checkIsAuthenticated();
        byte[] ecard = cards.getEncryptedCard().toByteArray();

        if(this.cardPublicKey == null) {
            //TODO: Move this to the C library
            byte[] decrypted = this.reader.cardDecrypt(ecard);
            try {
                IDPassCard card = SignedIDPassCard.parseFrom(decrypted).getCard();
                byte[] card_skpk = card.getEncryptionKey().toByteArray(); // private key
                cardPublicKey = Arrays.copyOfRange(card_skpk, 32, 64); // public key
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidCardException();
            }
        }
        return this.cardPublicKey;
    }

    public String getUIN() {
        return (String) cardDetails.get("UIN");
    }

    public String getfullName() {
        return (String) cardDetails.get("fullName");
    }

    public int getGender() {
        return (int) cardDetails.get("gender");
    }

    public PostalAddress getPostalAddress() {
        return (PostalAddress) cardDetails.get("postalAddress");
    }

    /**
     *
     * @return Returns givenname
     */
    public String getGivenName() {
        return (String) cardDetails.get("givenName");
    }

    /**
     *
     * @return Returns owner surname
     */
    public String getSurname() {
        return (String) cardDetails.get("surname");
    }

    /**
     *
     * @return Returns place of birth
     */
    public String getPlaceOfBirth() {
        return (String) cardDetails.get("placeOfBirth");
    }

    /**
     *
     * @return date of birth
     */
    public Date getDateOfBirth() {
        return (Date) cardDetails.get("dateOfBirth");
    }

    /**
     *
     * @return Returns byte[] array representation of this card
     */
    public byte[] asBytes() {
        return this.cardAsByte;
    }

    /**
     *
     * @return Returns a QR Code containing the card's data
     */
    public BufferedImage asQRCode() {
        return this.reader.getQRCode(this.cardAsByte);
    }

    /**
     * Returns the SVG format of the QR code representation of
     * the id card.
     * @return String An XML SVG vector graphics format
     */

    public String asQRCodeSVG() {
        return this.reader.getQRCodeAsSVG(this.cardAsByte);
    }

    /**
     *  Check if access conditions are satisfied
     * @throws NotVerifiedException custom exception
     */
    private void checkIsAuthenticated() throws NotVerifiedException {
        if(!isAuthenticated()) {
            throw new NotVerifiedException();
        }
    }

    /**
     * Return identity extra information.
     * @return Key/value pair of additional information
     */

    public HashMap<String, String> getCardExtras()
    {
        return cardExtras;
    }

    /**
     * To update member fields
     */
    private void updateDetails() {
        cardDetails.clear();
        cardExtras.clear();
        cardDetails.put("dateOfBirth", null);

        PublicSignedIDPassCard pubCard = cards.getPublicCard();
        CardDetails publicDetails = pubCard.getDetails();

        publicCardDetails = publicDetails;

        if (publicDetails.hasDateOfBirth()) {
            cardDetails.put("dateOfBirth", convertDate(publicDetails.getDateOfBirth()));
        }
        cardDetails.put("surname", publicDetails.getSurName());
        cardDetails.put("givenName", publicDetails.getGivenName());
        cardDetails.put("placeOfBirth", publicDetails.getPlaceOfBirth());

        if (publicDetails.hasPostalAddress()) {
            cardDetails.put("postalAddress", publicDetails.getPostalAddress());
        }

        String maybe = publicDetails.getUIN();
        if (maybe != null && maybe.length() > 0) {
            cardDetails.put("UIN", maybe) ;
        }

        maybe = publicDetails.getFullName();
        if (maybe != null && maybe.length() > 0) {
            cardDetails.put("fullName", maybe) ;
        }

        int gndr = publicDetails.getGender();
        if (gndr != 0) {
            cardDetails.put("gender", gndr);
        }

        List<Pair> extraList = publicDetails.getExtraList();
        for (Pair i : extraList) {
            cardExtras.put(i.getKey(), i.getValue());
        }

        if(isAuthenticated) {
            String str = privateCardDetails.getSurName();
            if (str != null && str.length() > 0) {
                cardDetails.put("surname", str);
            }

            str = privateCardDetails.getGivenName();
            if (str != null && str.length() > 0) {
                cardDetails.put("givenName", str);
            }

            str = privateCardDetails.getPlaceOfBirth();
            if (str != null && str.length() > 0) {
                cardDetails.put("placeOfBirth", str);
            }

            if (privateCardDetails.hasDateOfBirth()) {
                cardDetails.put("dateOfBirth", convertDate(privateCardDetails.getDateOfBirth()));
            }

            str = privateCardDetails.getUIN();
            if (str != null && str.length() > 0) {
                cardDetails.put("UIN", str) ;
            }

            str = privateCardDetails.getFullName();
            if (str != null && str.length() > 0) {
                cardDetails.put("fullName", str) ;
            }

            int gender = privateCardDetails.getGender();
            if (gender != 0) {
                cardDetails.put("gender", gender);
            }

            if (privateCardDetails.hasPostalAddress()) {
                cardDetails.put("postalAddress", privateCardDetails.getPostalAddress());
            }

            extraList = privateCardDetails.getExtraList();
            for (Pair i : extraList) {
                cardExtras.put(i.getKey(), i.getValue());
            }
        }
    }

    /**
     *
     * @param pbDate A protobuf defined Date
     * @return Returns back a standard Java Date
     */
    private Date convertDate(org.idpass.lite.proto.Date pbDate) {
        return new GregorianCalendar(pbDate.getYear(), pbDate.getMonth() - 1, pbDate.getDay()).getTime();
    }

    /**
     * Encrypts input data using card's unique ed25519 public key
     *
     * @param data The input data to be encrypted
     * @return Returns the encrypted data
     * @throws NotVerifiedException Custom exception
     */

    public byte[] encrypt(byte[] data)
            throws NotVerifiedException
    {
        checkIsAuthenticated();

        byte[] encrypted = reader.encrypt(data, cardAsByte);
        return encrypted;
    }

    /**
     * Decrypts the input data using card's unique ed25519 private key
     *
     * @param data The input data to be decrypted.
     * @return Returns the decrypted data.
     * @throws NotVerifiedException Custom exception
     * @throws InvalidCardException Custom exception
     */

    public byte[] decrypt(byte[] data)
            throws NotVerifiedException, InvalidCardException
    {
        checkIsAuthenticated();
        byte[] plaintext = reader.decrypt(data, cardAsByte);
        return plaintext;
    }

    public byte[] sign(byte[] data)
            throws NotVerifiedException
    {
        checkIsAuthenticated();
        byte[] signature = reader.sign(data, cardAsByte);
        return signature;
    }

    public boolean verify(byte[] data, byte[] signature, byte[] pubkey)
            throws NotVerifiedException
    {
        checkIsAuthenticated();
        boolean flag = reader.verifySignature(data, signature, pubkey);
        return flag;
    }

    public boolean saveToSVG(String filename)
    {
        File outfile = new File(filename);
        try {
            Files.write(outfile.toPath(),
                asQRCodeSVG().getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            return false;
        }

        return true;
    }

    public boolean saveToPNG(String filename)
    {
        File outfile = new File(filename);
        try {
            ImageIO.write(asQRCode(), "png", outfile);
        } catch (IOException e) {
            return false;
        }

        return true;
    }


    public boolean saveToJPG(String filename)
    {
        File outfile = new File(filename);
        try {
            ImageIO.write(asQRCode(), "jpg", outfile);
        } catch (IOException e) {
            return false;
        }

        return true;
    }
}
