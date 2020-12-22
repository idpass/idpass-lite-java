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

package org.idpass.lite;


import com.google.protobuf.ByteString;
import com.google.protobuf.Descriptors;
import org.api.proto.byteArray;
import org.api.proto.byteArrays;
import org.idpass.lite.exceptions.IDPassException;
import org.idpass.lite.proto.CardDetails;
import org.idpass.lite.proto.Pair;
import org.idpass.lite.proto.PostalAddress;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class IDPassHelper {
    // Helper method: For quick generation of needed encryption key
    public static byte[] generateEncryptionKey()
    {
        return IDPassReader.generateEncryptionKey();
    }

    // Helper method: For quick generation of needed ed25519 key
    public static byte[] generateSecretSignatureKey()
    {
        return IDPassReader.generateSecretSignatureKey();
    }

    public static byte[] reverse(byte[] arr)
    {
        byte[] buf = new byte[arr.length];
        int len = arr.length;
        for (int i = 0; i < len; i++) {
            buf[i] = arr[len - 1 - i];
        }
        return buf;
    }

    public static byte[][] divideArray(byte[] source, int chunksize) {


        byte[][] ret = new byte[(int)Math.ceil(source.length / (double)chunksize)][chunksize];

        int start = 0;

        for(int i = 0; i < ret.length; i++) {
            ret[i] = Arrays.copyOfRange(source,start, start + chunksize);
            start += chunksize ;
        }

        return ret;
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
     * Read back the saved IDPASS reader's configuration byte array identified by alias name.
     * @param alias The identifier name of the key/value to read from the keystore file
     * @param keystorepath Full file path of the keystore in the file system
     * @param password Password needed to read/write into the keystore file
     * @return Returns byte[] array of an IDPASS reader's needed security configuration
     * @throws IDPassException Throws custom exception
     */

    public static byte[][] readKeyStoreEntry(String alias, String keystorepath, String password)
        throws IDPassException
    {
        try {
            File file = new File(keystorepath);

            InputStream stream = new FileInputStream(file);
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(stream, password.toCharArray());
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

    public static CardDetails mergeCardDetails(
        CardDetails details1, CardDetails details2)
    {
        String strValue;
        Map<Descriptors.FieldDescriptor, Object> d1Fields = details1.getAllFields();
        CardDetails.Builder mergeBuilder = details2.toBuilder();

        for (Map.Entry<Descriptors.FieldDescriptor, Object> d1Field :
            d1Fields.entrySet())
        {
            Descriptors.FieldDescriptor fd = d1Field.getKey();

            switch (fd.toString()) {
                case "idpass.CardDetails.gender":
                    int intValue = (int)d1Field.getValue();
                    mergeBuilder.setGender(intValue);
                    break;

                case "idpass.CardDetails.fullName":
                    strValue = d1Field.getValue().toString();
                    mergeBuilder.setFullName(strValue);
                    break;

                case "idpass.CardDetails.surName":
                    strValue = d1Field.getValue().toString();
                    mergeBuilder.setSurName(strValue);
                    break;

                case "idpass.CardDetails.givenName":
                    strValue = d1Field.getValue().toString();
                    mergeBuilder.setGivenName(strValue);
                    break;

                case "idpass.CardDetails.UIN":
                    strValue = d1Field.getValue().toString();
                    mergeBuilder.setUIN(strValue);
                    break;

                case "idpass.CardDetails.placeOfBirth":
                    strValue = d1Field.getValue().toString();
                    mergeBuilder.setPlaceOfBirth(strValue);
                    break;

                case "idpass.CardDetails.dateOfBirth":
                    org.idpass.lite.proto.Date dValue =
                        (org.idpass.lite.proto.Date)d1Field.getValue();
                    mergeBuilder.setDateOfBirth(dValue);
                    break;

                case "idpass.CardDetails.postalAddress":
                    PostalAddress address = (PostalAddress)d1Field.getValue();
                    mergeBuilder.setPostalAddress(address);
                    break;

                case "idpass.CardDetails.extra":
                    List<Pair> extras = (List<Pair>)d1Field.getValue();
                    for (Pair e : extras) {
                        mergeBuilder.addExtra(e);
                    }
                    break;

                case "idpass.CardDetails.createdAt":
                    long longValue = (long)d1Field.getValue();
                    mergeBuilder.setCreatedAt(longValue);
                    break;

                default:
                    break;
            }
        }

        return mergeBuilder.build();
    }
}

