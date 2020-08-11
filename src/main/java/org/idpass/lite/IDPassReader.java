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
import com.google.zxing.BinaryBitmap;
import com.google.zxing.LuminanceSource;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.Result;
import com.google.zxing.ResultMetadataType;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import org.api.proto.*;
import org.idpass.lite.exceptions.IDPassException;
import org.idpass.lite.exceptions.InvalidCardException;
import org.idpass.lite.proto.IDPassCards;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;

/**
 * Wrapper class of the libidpasslite.so shared
 * library.
 */

public class IDPassReader {

    /**
     * These constants are used to make some generalized calls into
     * the library via an ioctl function of the library. The purpose
     * is to set or get settings that has effect on succeeding calls
     * into the library. The changes only take effect on the particular
     * context identified by the ctx handle. Other instance in different
     * threads are not affected.
     *
     * IOCTL_SET_FACEDIFF = The current threshold is 0.42 in half mode or 0.6 in full mode.
     * IOCTL_GET_FACEDIFF = Returns the threshold floating point value.
     * IOCTL_SET_FDIM = Sets to full mode or half mode for Dlib facial dimension vectors to represent a face
     * IOCTL_GET_FDIM = Gets the current mode either full mode or half mode.
     * IOCTL_SET_ECC = The default QR Code ECC is medium. But other values can be set.
     * IOCTL_SET_ACL = Each field CardDetails can be made visible or not in the returned public card.
     */
    private static final byte IOCTL_SET_FACEDIFF = 0x00;
    private static final byte IOCTL_GET_FACEDIFF = 0x01;
    private static final byte IOCTL_SET_FDIM = 0x02;
    private static final byte IOCTL_GET_FDIM = 0x03;
    private static final byte IOCTL_SET_ECC = 0x04;
    private static final byte IOCTL_SET_ACL = 0x05;

    /**
     *  These bit flags correspond to the fields
     *  of the CardDetails protobuf message definition.
     *  A set bit field indicates that the field is visible in
     *  the public region of the returned object.
     *
     *  These bit fields are used when using the IOCTL_SET_ACL
     *  ioctl command.
     */
    public static final int DETAIL_SURNAME = 1;
    public static final int DETAIL_GIVENNAME = 2;
    public static final int DETAIL_DATEOFBIRTH = 4;
    public static final int DETAIL_PLACEOFBIRTH = 8;
    public static final int DETAIL_CREATEDAT = 16;

    /**
     * The library is initialized with 3 types of keys.
     *
     * KeySet::encryptionKey: A crypto_aead_chacha20poly1305_IETF_KEYBYTES key.
     * The encrypted content of the QR Code card is protected by this
     * symmetric key.
     *
     * KeySet::signatureKey: An ED25519 key that is used both for encryption and
     * signing. The encrypted content of the QR code card is signed by
     * this key.
     *
     * KeySet::verificationKeys: This is a list of public keys. A facial recognition
     * match and a found verification key from this list are the required
     * access conditions to open a card.
     */
    private long ctx; // handle to library
    protected KeySet m_keyset;

    static {
        try {
            String idpasslib = IDPassLoader.getLibrary();
            System.load(idpasslib);
        } catch (IOException e) {
            //TODO: Log the error
            e.printStackTrace();
        }
    }

    /**
     * Instantiates an instance of the library with additional verification keys
     * @param ks The cryptographic key settings
     * @param rc The root certificates list
     * @throws IDPassException ID PASS exception
     */
    public IDPassReader(KeySet ks, Certificates rc)
            throws IDPassException {

        m_keyset = ks;

        // add `rootCertificates` to the parameter
        ctx = idpass_init(ks.toByteArray(), rc != null ? rc.toByteArray() : null);
        if (ctx == 0) {
            throw new IDPassException("ID PASS Lite could not be initialized");
        }
    }

    /**
     * Parse the content of a card
     * @param card The binary content of a card
     * @return Wrapper of the card
     * @throws IDPassException ID PASS exception
     * @throws InvalidProtocolBufferException Protobuf exception
     */
    public Card open(byte[] card)
            throws IDPassException, InvalidProtocolBufferException
    {
        return open(card, false);
    }

    /**
     * Parse the content of a card
     * @param bCard The binary content of a card
     * @param skipCertificateVerification Skip flag for certificate verification
     * @return Wrapper of the card
     * @throws IDPassException ID PASS exception
     * @throws InvalidProtocolBufferException Protobuf exception
     */
    public Card open(byte[] bCard, boolean skipCertificateVerification)
            throws IDPassException, InvalidProtocolBufferException
    {
        Card card = new Card(this, bCard);
        if(!skipCertificateVerification && !card.verifyCertificate()) {
            throw new InvalidCardException("Certificate could not be verified");
        }
        return card;
    }


    /**
     * Read a QR code image and parse the content of a card
     * @param bufferedImage The QR code image
     * @return Wrapper of the card
     * @throws IDPassException ID PASS exception
     * @throws NotFoundException QR Code not Found
     * @throws InvalidProtocolBufferException Protobuf exception
     */
    public Card open(BufferedImage bufferedImage)
            throws IDPassException, NotFoundException, InvalidProtocolBufferException
    {
        LuminanceSource source = new BufferedImageLuminanceSource(bufferedImage);
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));

        byte[] card;


        Result result = new MultiFormatReader().decode(bitmap);
        Map m = result.getResultMetadata();

        if (m.containsKey(ResultMetadataType.BYTE_SEGMENTS)) {
            List L = (List)m.get(ResultMetadataType.BYTE_SEGMENTS);
            card = (byte[])L.get(0);
        } else {
            card = result.getText().getBytes();
        }
        return this.open(card);
    }

    /**
     * Create a new ID PASS Card.
     * @param ident The person identity details
     * @param certificates Certificate chain
     * @throws IDPassException ID PASS exception
     * @return Returns Card object
     */
    public Card newCard(Ident ident, Certificates certificates)
            throws IDPassException
    {
        return new Card(this, ident, certificates);
    }

    /**
     * Given the pin code and a card content represented by
     * eSignedCard, this method returns the serialized bytes of a
     * SignedIDPassCard protobuf message object. These
     * bytes are used to instantiate a SignedIDPassCard object for
     * further operation on this object. A matching pin code
     * and valid verification key are the presequisite.
     * @param pin The personal pin code of the card owner
     * @param eSignedCard The EncryptedCard part of the card as byte[]
     * @return The byte array of the SignedIDPassCard if the pin is correct or an empty array
     */
    protected byte[] verifyCardWithPin(String pin, byte[] eSignedCard) {
        byte[] buf = verify_card_with_pin(ctx, pin, eSignedCard);

        return buf;
    }

    /**
     * Given a photo and the card content represented by eSignedCard,
     * this method returns the serialized bytes of a SignedIDPassCard
     * protobuf message object. A matching face recognition and valid
     * verification key are the prerequisites.
     * @param photo The card owner's photo
     * @param eSignedCard The EncryptedCard part of the card as byte[]
     * @return This returns the SignedIDPassCard of the card owner as byte[] if the face match or an empty array
     */
    protected byte[] verifyCardWithFace(byte[] photo, byte[] eSignedCard) {
        byte[] buf = verify_card_with_face(ctx, photo, eSignedCard);

        return buf;
    }

    /**
     * To make a particular Details field publicly visible in
     * the public region of the QR code ID.
     * By default, everything is private.
     * @param acl The bit flag of a specific field to make visible
     */
    public void setDetailsVisible(int acl)
    {
        byte[] ioctlcmd = new byte[] {
                IOCTL_SET_ACL,
                (byte)acl
        };

        ioctl(ctx, ioctlcmd);
    }

    /**
     * To adjust the Dlib facial recognition value used in identifying a face.
     * Face recognition depends on many factors from camera, image size, resolution
     * etc and the appropriate threshold can be adjusted as needed. Although,
     * in the Dlib documentation most widely used is the default 0.6 for the full mode
     * and 0.42 for the half mode.
     * @param value You must know which mode is active in order to have an optimal value
     * @throws IDPassException ID PASS exception
     */
    public void setFaceDiffThreshold(float value) throws IDPassException {
        byte[] buf = IDPassHelper.reverse(ByteBuffer.allocate(4).putFloat(value).array());
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        try {
            bos.write(IOCTL_SET_FACEDIFF);
            bos.write(buf);
        } catch (IOException e) {
            throw new IDPassException("Error Changing Threshold");
        }

        byte[] iobuf = bos.toByteArray();

        ioctl(ctx, iobuf);
    }

    /**
     * Returns the current facial threshold used to identify a face match.
     * During card creation and issuance, the card owner's facial template are
     * encoded inside the QR code.
     * If the card was created in full-mode, then this facial template occupies
     * 128*4 bytes inside the QR code.
     * If the card was created in half-mode, then this facial template occupies
     * 64*2 bytes inside the QR code.
     * @return Example values are 0.42 if half mode, or 0.6 if full mode
     */

    public float getFaceDiffThreshold()
    {
        float facediff = 0.0f;
        byte[] cmd = new byte[5];
        cmd[0] = IOCTL_GET_FACEDIFF;

        ioctl(ctx, cmd);

        byte[] b = IDPassHelper.reverse(Arrays.copyOfRange(cmd, 1,cmd.length));
        ByteBuffer buffer = ByteBuffer.wrap(b);
        facediff = buffer.getFloat();

        return facediff;
    }


    public static void addRevokedKey(byte[] publicKey) {

        //TODO call the Cpp to add to the list of revoked keys.
        add_revoked_key(publicKey);
    }

    public static void addRevokedKeys(byte[][] publicKey)
    {
        //TODO call the Cpp to add to the list of revoked keys.
        for (byte[] key : publicKey) {
            add_revoked_key(key);
        }
    }

    /**
     * These are the C functions documented in the idpass.h header file
     */
    //========================== JNI section =============================
    private native long idpass_init(byte[] ks, byte[] rootcerts);
    private native byte[] ioctl(long ctx, byte[] cmd);

    private native byte[] create_card_with_face(
            long ctx,
            byte[] ident);

    private native byte[] verify_card_with_face(long ctx, byte[] photo, byte[] ecard);
    private native byte[] verify_card_with_pin(long ctx, String pin, byte[] ecard);
    private native byte[] encrypt_with_card(long ctx, byte[] ecard, byte[] data);
    private native byte[] decrypt_with_card(long ctx, byte[] ciphertext, byte[] skpk);
    private native byte[] sign_with_card(long ctx, byte[] ecard, byte[] data);
    private native boolean verify_with_card(long ctx, byte[] msg, byte[] signature, byte[] pubkey);
    private native BitSet generate_qrcode_pixels(long ctx, byte[] data);
    private native byte[] compute_face_128d(long ctx, byte[] photo);
    private native byte[] compute_face_64d(long ctx, byte[] photo);
    private static native byte[] generate_encryption_key(); // 32
    private static native byte[] generate_secret_signature_key(); // 64
    private native byte[] card_decrypt(long ctx, byte[] ecard, byte[] key);
    private native float compare_face_template(byte[] face1, byte[] face2);
    private static native byte[] generate_root_certificate(byte[] secretKey);
    private static native byte[] generate_child_certificate(byte[] parentSecretKey, byte[] childSecretKey);
    private static native void add_revoked_key(byte[] pubkey);
    private native boolean add_certificates(long ctx, byte[] intermedcerts);
    private native int verify_card_certificate(long ctx, byte[] blob);
    //=========================================================

    public int verifyCardCertificate(IDPassCards fullcard)
    {
        return verify_card_certificate(ctx, fullcard.toByteArray());
    }

    /**
     * The ecard is the encrypted QR code content. This method
     * decrypts it. The decrypted bytes is used to re-construct
     * the IDPassCards protobuf message object. The IDPassCards object
     * is divided into two regions: a public and a private region.
     * @param ecard Content of QR code ID
     * @return The decrypted bytes of QR code ID
     */
    protected byte[] cardDecrypt(byte[] ecard)
    {
        return card_decrypt(ctx, ecard, m_keyset.getEncryptionKey().toByteArray());
    }

    /**
     * This is used to verify the detached signature of a message created by
     * the card owner or other card owners.
     * @param msg The signed message
     * @param signature The detached 64 bytes of the message
     * @param pubkey The public key of the signer
     * @return true if the message was signed by the key
     */
    protected boolean verifySignature(
            byte[] msg,
            byte[] signature,
            byte[] pubkey)
    {
        return verify_with_card(ctx,msg,signature,pubkey);
    }

    /**
     * This is used to issue a new QR code card with the details
     * passed in the parameters.
     * @param ident The person's identity details
     * @param certificates Certificate chain
     * @return The card content including the public and private parts
     * @throws IDPassException ID PASS exception
     */
    protected byte[] createNewCard(Ident ident, Certificates certificates)
            throws IDPassException
    {
        if (certificates != null) {
            // tip will sign
            if (!add_certificates(ctx, certificates.toByteArray())) {
                System.out.println("invalid chain");
            }
        }

        byte[] ecard = create_card_with_face(ctx, ident.toByteArray());

        if (ecard.length == 0) {
            throw new IDPassException();
        }
        return ecard;
    }

    /**
     *  Given any arbitrary content inside buf, this method returns
     *  its QR code binary representation.
     * @param buf Any arbitrary content
     * @return Return a standard Java image object
     */
    protected BufferedImage getQRCode(byte[] buf)
    {
        BitSet qrpixels = generate_qrcode_pixels(ctx, buf);

        int qrpixels_len = qrpixels.length() - 1; // always substract by 1
        int qrsidelen = (int) Math.sqrt(qrpixels_len);

        BufferedImage qrcode = new BufferedImage(qrsidelen,
                qrsidelen, BufferedImage.TYPE_INT_RGB);

        for (int x=0; x< qrsidelen; x++) {
            for (int y=0; y < qrsidelen; y++) {
                if (qrpixels.get(x * qrsidelen + y)) {
                    qrcode.setRGB(x, y, Color.BLACK.getRGB());
                } else {
                    qrcode.setRGB(x, y,Color.WHITE.getRGB());
                }
            }
        }

        return qrcode;
    }

    /**
     * Helper method for quick generation of needed encryption key
     * @return 32 bytes key
     */
    public static byte[] generateEncryptionKey()
    {
        return generate_encryption_key();
    }

    /**
     * Helper method for quick generation of needed ed25519 key
     * @return 64 bytes key
     */
    public static byte[] generateSecretSignatureKey()
    {
        return generate_secret_signature_key();
    }

    public static Certificate generateRootCertificate(byte[] secretKey)
            throws InvalidProtocolBufferException
    {
        Certificate c = Certificate.parseFrom(generate_root_certificate(secretKey));
        Certificate cc = c.toBuilder().setDesc("ROOTCERT").build();
        return cc;
    }

    public static Certificate generateChildCertificate(byte[] parentSecretKey, byte[] childSecretKey)
            throws InvalidProtocolBufferException
    {
        Certificate c = Certificate.parseFrom(generate_child_certificate(parentSecretKey, childSecretKey));
        Certificate cc = c.toBuilder().setDesc("CHILDCERT").build();
        return cc;
    }

    public byte[] encrypt(byte[] data, byte[] fullcard)
    {
        byte[] encrypted = encrypt_with_card(ctx, fullcard, data);
        return encrypted;
    }


    public byte[] decrypt(byte[] data, byte[] skpk)
    {
        byte[] decrypted = decrypt_with_card(ctx, data, skpk);
        return decrypted;
    }

    public boolean addIntermediateCertificates(Certificates certs)
    {
        return add_certificates(ctx, certs.toByteArray());
    }
}
