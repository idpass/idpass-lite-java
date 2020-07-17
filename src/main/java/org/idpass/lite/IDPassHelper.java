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


import java.util.Arrays;

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
}
