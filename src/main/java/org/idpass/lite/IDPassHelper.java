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
import org.idpass.lite.exceptions.InvalidKeyException;

import java.util.*;

public class IDPassHelper {
    /**
     * Get the public key from an ED25519 key
     * @param ed25519key An ED25519 key
     * @return Returns the public key
     * @throws InvalidKeyException If not an ED25519 expected key length
     */
    public static byte[] getPublicKey(byte[] ed25519key) throws InvalidKeyException {
        if (ed25519key.length != 64) {
            throw new InvalidKeyException("Not an ED25519 secret key");
        }
        return Arrays.copyOfRange(ed25519key, 32, 64);
    }
    public static ByteString generateEncryptionKeyAsByteString()
    {
        return ByteString.copyFrom(IDPassReader.generateEncryptionKey());
    }

    public static ByteString generateSecretSignatureKeyAsByteString()
    {
        return ByteString.copyFrom(IDPassReader.generateSecretSignatureKey());
    }

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

}

