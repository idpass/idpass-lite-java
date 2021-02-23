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

package org.idpass.lite.test.utils;

import com.google.protobuf.ByteString;
import org.api.proto.Certificates;
import org.api.proto.KeySet;
import org.api.proto.byteArray;
import org.api.proto.byteArrays;
import org.idpass.lite.Card;
import org.idpass.lite.exceptions.IDPassException;
import org.idpass.lite.exceptions.InvalidCardException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.List;
import java.util.function.Function;

public class Helper {

    // QR code scanner with zxing dependency in test cases only
    public static Function<BufferedImage, byte[]> qrImageScanner = new QRCodeImageScanner();

    public static byte[] scanQRCode(BufferedImage qrPic) {
        return qrImageScanner.apply(qrPic);
    }

    /**
     *
     * @param card
     * @param format Either "png", "jpg", or "svg"
     * @param outfile
     * @return
     * @throws InvalidCardException
     */
    public static boolean saveImage(Card card, String format, OutputStream outfile)
            throws InvalidCardException
    {
        if (format.equals("png") || format.equals("jpg")) {
            BufferedImage qrcode = toBufferedImage(card);
            try {
                ImageIO.write(qrcode, format, outfile);
                return true;
            } catch (IOException e) {
                return false;
            }

        } else if (format.equals("svg")) {
            try {
                outfile.write(card.asQRCodeSVG().getBytes(StandardCharsets.UTF_8));
                return true;
            } catch (IOException e) {
                return false;
            }
        }

        return false;
    }

    /**
     * Renders an ID PASS Lite card into a QR code image.
     *
     * @param card An ID PASS Lite card
     * @return Returns a QR code image of the card
     * @throws InvalidCardException Corrupted card
     */
    public static BufferedImage toBufferedImage(Card card)
            throws InvalidCardException
    {
        BitSet qrpixels = card.asQRCode();
        int qrsidelen = (int) Math.sqrt(qrpixels.length() - 1);
        int margin = card.getMargin();
        int scale = card.getScale();

        BufferedImage qrcode = new BufferedImage(
            (qrsidelen + margin * 2) * scale,
            (qrsidelen + margin * 2) * scale,
            BufferedImage.TYPE_INT_RGB);

        for (int y = 0; y < qrcode.getHeight(); y++) {
            for (int x = 0; x < qrcode.getWidth(); x++) {
                int innerX = x / scale - margin;
                int innerY = y / scale - margin;
                boolean flag = false;

                if (innerX >= 0 && innerX < qrsidelen &&
                        innerY >= 0 && innerY < qrsidelen) {
                    flag = qrpixels.get(innerX + innerY * qrsidelen);
                }

                qrcode.setRGB(x, y, flag ? Color.BLACK.getRGB() :
                                           Color.WHITE.getRGB());
            }
        }

        return qrcode;
    }

    /**
     * A helper method to generate random alphananumeric
     * string to simulate keystore passwords during tests
     * @param n Length of password to generate
     * @return Returns alphananumeric string
     */
    public static String randomString(int n) {
        int leftLimit = 48; // numeral '0'
        int rightLimit = 122; // letter 'z'
        int targetStringLength = n;
        Random random = new Random();

        String generatedString = random.ints(leftLimit, rightLimit + 1)
                .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();

        return generatedString;
    }

    public static boolean saveConfiguration(String alias, File keystoreFile,
                                            String keystorePass, String keyPass,
                                            KeySet keyset, Certificates rootcertificates)
    {
        Helper.writeKeyStoreEntry(alias + "_keyset",keystoreFile,
                keystorePass, keyPass, keyset.toByteArray());

        if (rootcertificates != null) {
            Helper.writeKeyStoreEntry(alias + "_rootcertificates",
                    keystoreFile, keystorePass, keyPass, rootcertificates.toByteArray());
        }

        return true;
    }

    /**
     * Read back the saved IDPASS reader's configuration byte array identified by alias name.
     * @param alias The identifier name of the key/value to read from the keystore file
     * @param keystorepath Full file path of the keystore in the file system
     * @param password Password needed to read/write into the keystore file
     * @return Returns byte[] array of an IDPASS reader's needed security configuration
     * @throws IDPassException Throws custom exception
     */
    public static byte[][] readKeyStoreEntry(String alias, String keystorepath,
                                             String storePass, String keyPass)
            throws IDPassException
    {
        try {
            File file = new File(keystorepath);

            InputStream stream = new FileInputStream(file);
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(stream, storePass.toCharArray());
            SecretKey key = (SecretKey)store.getKey(alias, keyPass.toCharArray());

            if (key != null) {
                byte[] e = key.getEncoded();
                byte[] keybuf = Base64.getDecoder().decode(new String(e));
                byteArrays content = byteArrays.parseFrom(keybuf);
                List<byteArray> m = content.getValsList();
                byte[][] ret = new byte[m.size()][];
                for (int i = 0; i < m.size(); i++) {
                    ret[i] = m.get(i).getVal().toByteArray();
                }
                return ret;
            } else {
                // key not found
                return null;
            }
        } catch (KeyStoreException kse) {
            throw new IDPassException("PKCS12 error getting the key");
        } catch (Exception e) {
            throw new IDPassException("PKCS12 error opening the key file");
        }
    }

    /**
     * Add an entry identified by alias into p12 keystore file. The
     * entry value can be a list of byte arrays and whose meaning is
     * specific according to purpose of this entry.
     *
     * @param alias The name of the entry
     * @param keystorefile The p12 keystore file
     * @param keystorePass Password to open p12 keystore file
     * @param keyPass Password to access this entry
     * @param entry A list of byte arrays
     * @return True when entry succesfully added. False otherwise
     */
    public static boolean writeKeyStoreEntry(String alias, File keystorefile,
                                             String keystorePass, String keyPass, byte[] ... entry)
    {
        if (entry.length > 0) {

            byteArrays.Builder contentBuilder = byteArrays.newBuilder();

            for (byte[] e : entry) {
                byteArray buf = byteArray.newBuilder()
                        .setVal(ByteString.copyFrom(e))
                        .build();

                contentBuilder.addVals(buf);
            }

            byteArrays content = contentBuilder.build();

            try {

                KeyStore store = KeyStore.getInstance("PKCS12");
                if (!keystorefile.exists()) {
                    store.load(null, keystorePass.toCharArray());
                } else {
                    int n = (int) keystorefile.length();
                    if (n > 0) {
                        byte[] buf = new byte[n];
                        DataInputStream dis = new DataInputStream(new FileInputStream(keystorefile));
                        dis.readFully(buf);
                        dis.close();
                        store.load(new ByteArrayInputStream(buf), keystorePass.toCharArray());
                    } else {
                        store.load(null, keystorePass.toCharArray());
                    }
                }

                String contentValue = Base64.getEncoder().encodeToString(content.toByteArray());

                // prepare key entry
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBE");
                SecretKey keyEntry = factory.generateSecret(new PBEKeySpec(contentValue.toCharArray()));

                // save entry to keystore
                KeyStore.PasswordProtection keyStorePP = new KeyStore.PasswordProtection(keyPass.toCharArray());
                store.setEntry(alias, new KeyStore.SecretKeyEntry(keyEntry), keyStorePP);

                // Update keystore file
                FileOutputStream fos = new FileOutputStream(keystorefile);
                store.store(fos, keystorePass.toCharArray());
                fos.close();
                return true;

            } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                //throw new IDPassException("PKCS12 keystore read error");
                return false;
            }
        }

        return false;
    }

    /**
     * Read a key entry from p12 file identified by alias
     *
     * @param alias The key name of entry to read from p12 file
     * @param keystorepath An InputStream of the p12 keystore file
     * @param keystorePass Password to open keystore file
     * @param keyPass Password to access key entry
     * @return Returns array of byte array on success or null if key alias does not exsists
     * @throws IDPassException Wrong password either in keystore file or in key entry
     */
    public static byte[][] readKeyStoreEntry(String alias, InputStream keystorepath,
                                             String keystorePass, String keyPass)
            throws IDPassException
    {
        try {
            KeyStore store = Helper.getKeyStore(keystorepath, keystorePass);
            SecretKey key = (SecretKey)store.getKey(alias, keyPass.toCharArray());

            if (key != null) {
                byte[] e = key.getEncoded();
                byte[] keybuf = Base64.getDecoder().decode(new String(e));
                byteArrays content = byteArrays.parseFrom(keybuf);
                List<byteArray> m = content.getValsList();
                byte[][] ret = new byte[m.size()][];
                for (int i = 0; i < m.size(); i++) {
                    ret[i] = m.get(i).getVal().toByteArray();
                }
                return ret;
            } else {
                // key not found
                return null;
            }
        } catch (KeyStoreException kse) {
            throw new IDPassException("PKCS12 error getting the key");
        } catch (Exception e) {
            throw new IDPassException("PKCS12 error opening the key file");
        }
    }

    /**
     * Open the pkcs12 file with provided password and returns
     * the KeyStore object.
     *
     * @param stream FileInputStream of the pkcs12 file
     * @param password Password needed to open the pkcs12 file
     * @return KeyStore object
     * @throws IDPassException Standard exception
     */
    public static KeyStore getKeyStore(InputStream stream, String password)
            throws IDPassException
    {
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(stream, password.toCharArray());
            return store;
        } catch (KeyStoreException kse) {
            throw new IDPassException("PKCS12 error getting the key");
        } catch (Exception e) {
            throw new IDPassException("PKCS12 error opening the key file");
        }
    }

    /**
     * Read back the saved IDPASS reader's configuration byte array identified by alias name.
     * @param alias The identifier name of the key/value to read from the keystore file
     * @param store The loaded key store object
     * @param password Password to get a key
     * @return Returns byte[] array of an IDPASS reader's needed security configuration
     * @throws IDPassException Throws custom exception
     */
    public static byte[][] readKeyStoreEntry(String alias, KeyStore store, String password)
            throws IDPassException
    {
        try {
            SecretKey key = (SecretKey)store.getKey(alias, password.toCharArray());

            if (key != null) {
                byte[] e = key.getEncoded();
                byte[] keybuf = Base64.getDecoder().decode(new String(e));
                byteArrays content = byteArrays.parseFrom(keybuf);
                List<byteArray> m = content.getValsList();
                byte[][] ret = new byte[m.size()][];
                for (int i = 0; i < m.size(); i++) {
                    ret[i] = m.get(i).getVal().toByteArray();
                }
                return ret;
            } else {
                // key not found
                return null;
            }
        } catch (KeyStoreException kse) {
            throw new IDPassException("PKCS12 error getting the key");
        } catch (Exception e) {
            throw new IDPassException("PKCS12 error opening the key file");
        }
    }

    /**
     * Adds a key/value pair into a PKCS12 keystore file. The key name is identified by
     * alias and the value is in keybuf. The keybuf byte array is a custom byte array
     * that packs together the IDPASS reader's keyset and root certificates.
     * @param alias The key name identifier where to save the value
     * @param entry The byte[] entry value
     * @param keystorepath The full file path of the keystore file in the filesystem
     * @param password The password that protects the keystore file during read/write
     * @return True if the key/value is successfully added into the keystore file
     */
    public static boolean writeKeyStoreEntry(String alias, String keystorepath,
                                             String password, byte[] ... entry)
    {
        if (entry.length > 0) {

            byteArrays.Builder contentBuilder = byteArrays.newBuilder();

            for (byte[] e : entry) {
                byteArray buf = byteArray.newBuilder()
                        .setVal(ByteString.copyFrom(e))
                        .build();

                contentBuilder.addVals(buf);
            }

            byteArrays content = contentBuilder.build();

            try {
                String contentValue = Base64.getEncoder().encodeToString(content.toByteArray());

                // open/create keystore file with password
                KeyStore store = KeyStore.getInstance("PKCS12");
                File file = new File(keystorepath);

                if (!file.exists()) {
                    store.load(null, null); // Initialize a blank keystore
                    store.store(new FileOutputStream(keystorepath), password.toCharArray());
                }

                InputStream stream = new FileInputStream(file);
                store.load(stream, password.toCharArray());

                // prepare key entry
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBE");
                SecretKey keyEntry = factory.generateSecret(new PBEKeySpec(contentValue.toCharArray()));

                // save entry to keystore
                KeyStore.PasswordProtection keyStorePP = new KeyStore.PasswordProtection(password.toCharArray());
                store.setEntry(alias, new KeyStore.SecretKeyEntry(keyEntry), keyStorePP);

                // Update keystore file
                FileOutputStream out = new FileOutputStream(keystorepath);
                store.store(out, password.toCharArray());
                out.close();

                return true;

            } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                //throw new IDPassException("PKCS12 keystore read error");
                return false;
            }
        }

        return false;
    }

    public static List<String> getAliases(String keystorepath, String password)
            throws IDPassException
    {
        try {
            File file = new File(keystorepath);
            InputStream stream = new FileInputStream(file);
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(stream, password.toCharArray());
            return Collections.list(store.aliases());
        } catch (KeyStoreException kse) {
            throw new IDPassException("PKCS12 error getting the key");
        } catch (Exception e) {
            throw new IDPassException("PKCS12 error opening the key file");
        }
    }

    public static boolean isAliasExists(String alias, String keystorepath, String password)
            throws IDPassException
    {
        try {
            File file = new File(keystorepath);
            InputStream stream = new FileInputStream(file);
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(stream, password.toCharArray());
            return store.isKeyEntry(alias);
        } catch (KeyStoreException kse) {
            throw new IDPassException("PKCS12 error getting the key");
        } catch (Exception e) {
            throw new IDPassException("PKCS12 error opening the key file");
        }
    }
}
