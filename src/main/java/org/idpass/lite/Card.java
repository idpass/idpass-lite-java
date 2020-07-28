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
import org.idpass.api.proto.CardDetails;
import org.idpass.api.proto.IDPassCard;
import org.idpass.api.proto.IDPassCards;
import org.idpass.api.proto.Pair;
import org.idpass.api.proto.PublicSignedIDPassCard;
import org.idpass.api.proto.SignedIDPassCard;
import org.idpass.api.proto.Certificate;
import org.idpass.lite.exceptions.CardVerificationException;
import org.idpass.lite.exceptions.IDPassException;
import org.idpass.lite.exceptions.InvalidCardException;
import org.idpass.lite.exceptions.NotVerifiedException;

import java.awt.image.BufferedImage;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.Date;

/**
 * An abstract representation of an ID PASS Card
 */
public class Card {
    private IDPassReader reader;
    private IDPassCards cards;
    private CardDetails privateCardDetails = null;
    private boolean isAuthenticated = false;
    private byte[] cardPublicKey = null;
    private byte[] cardAsByte = null;

    private HashMap<String, Object> cardDetails = new HashMap<String, Object>();
    private HashMap<String, String> cardExtras = new HashMap<String, String>();

    /**
     * ncerts - Count of certificates in the chain
     * signature - Signature of card's signerPublicKey
     * certs - List of certificates in a chain
     */
    private int ncerts;
    private byte[] signature;
    private List<Certificate> certs;

    /**
     * This constructor is used to create a new ID PASS Card.
     * @param idPassReader The reader instance
     * @param surname Person surname
     * @param givenName Person given name
     * @param dateOfBirth birthday ie, 1978/12/17
     * @param placeOfBirth Place of birth
     * @param publicExtra Arbitrary key/value pairs to reside in the public region
     * @param privateExtra Arbitrary key/value pairs to reside in teh private region
     * @param photo The photo bytes array
     * @param pin The card owner personal pin code
     * @param certificates Certificate chain
     * @throws IDPassException ID PASS exception
     */
    protected Card(IDPassReader idPassReader,
                String surname,
                String givenName,
                Date dateOfBirth,
                String placeOfBirth,
                HashMap<String, String> publicExtra,
                HashMap<String, String> privateExtra,
                byte[] photo,
                String pin,
                byte[][] certificates) throws IDPassException {
        this.reader = idPassReader;
        byte[] card = this.reader.createNewCard(
                surname,
                givenName,
                new SimpleDateFormat("yyyy/MM/dd").format(dateOfBirth),
                placeOfBirth,
                publicExtra,
                privateExtra,
                photo,
                pin,
                certificates);

        try {
            this.cards = IDPassCards.parseFrom(card);
            this.ncerts = this.cards.getCertificatesCount();
            this.signature = this.cards.getSignature().toByteArray();
            this.certs = this.cards.getCertificatesList();
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidCardException();
        }
        this.cardAsByte = card;
        updateDetails();
    }

    /**
     * Verify the signature using certificate chain.
     *
     * @return True Returns true if certificate chain
     * validates and verifies the IDPassCard's signature.
     */

    public boolean verifyCertificate() throws InvalidCardException, NotVerifiedException
    {
        if (this.ncerts > 0) {
            // verify card certificate
            if (reader.verifySignature(
                    getPublicKey(),
                    this.signature,
                    certs.get(0).getPubkey().toByteArray())) {

                // verify chain
                for (Certificate c : this.certs) {
                    byte[] pubkey = c.getPubkey().toByteArray();
                    byte[] signature = c.getSignature().toByteArray();
                    byte[] issuer = c.getIssuerkey().toByteArray();
                    if (!reader.verifySignature(pubkey, signature, issuer)) {
                        return false;
                    }
                }

                return true;

            } else {
                return false;
            }
        }

        return false;
    }

    /**
     * Parse and wrap a card
     * @param idPassReader The reader instance
     * @param card The QR code content byte array
     * @throws IDPassException custom exception
     */
    public Card(IDPassReader idPassReader, byte[] card) throws IDPassException {
        this.reader = idPassReader;

        try {
            this.cards = IDPassCards.parseFrom(card);
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidCardException();
        }
        verifyPublicCardSignature(this.cards.getPublicCard());
        this.cardAsByte = card;
        updateDetails();
    }

    /**
     *
     * @param publicCard The public region of the QR code ID
     * @throws IDPassException custom exception
     */
    private void verifyPublicCardSignature(PublicSignedIDPassCard publicCard) throws IDPassException {
        if (!publicCard.hasDetails()) {
            return;
        }
        byte[] blob = publicCard.getDetails().toByteArray();
        byte[] signerPublicKey = publicCard.getSignerPublicKey().toByteArray();

        byte[][] allowedKeys = IDPassHelper.divideArray(this.reader.verificationKeys, 32);
        boolean found = false;
        for (byte[]key: allowedKeys) {
            if (Arrays.equals(key, signerPublicKey)) {
                found = true;
                break;
            }
        }
        if(!found) {
            throw new IDPassException("Unknown Signer key: " + Arrays.toString(signerPublicKey));
        }
        boolean flag = this.reader.verifySignature(blob, publicCard.getSignature().toByteArray(), signerPublicKey);
        if (!flag) {
            throw new IDPassException("Signature does not match");
        }
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
        byte[] ecard = cards.getEncryptedCard().toByteArray();
        byte[] buf = this.reader.verifyCardWithFace(photo, ecard);

        verifyAuth(buf);
    }

    /**
     * Match the pin with the one in the card
     * If it match access to the private part of the card is given.
     * @param pin Pin code of the card holder
     * @throws CardVerificationException custom exception
     * @throws InvalidCardException custom exception
     */
    public void authenticateWithPIN(String pin) throws CardVerificationException, InvalidCardException {
        byte[] ecard = cards.getEncryptedCard().toByteArray();
        byte[] buf = this.reader.verifyCardWithPin(pin, ecard);

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
     *  Check if access conditions are satisfied
     * @throws NotVerifiedException custom exception
     */
    private void checkIsAuthenticated() throws NotVerifiedException {
        if(!isAuthenticated()) {
            throw new NotVerifiedException();
        }
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

        if (publicDetails.hasDateOfBirth()) {
            cardDetails.put("dateOfBirth", convertDate(publicDetails.getDateOfBirth()));
        }
        cardDetails.put("surname", publicDetails.getSurName());
        cardDetails.put("givenName", publicDetails.getGivenName());
        cardDetails.put("placeOfBirth", publicDetails.getPlaceOfBirth());

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
    private Date convertDate(org.idpass.api.proto.Date pbDate) {
        return new GregorianCalendar(pbDate.getYear(), pbDate.getMonth() - 1, pbDate.getDay()).getTime();
    }

}
