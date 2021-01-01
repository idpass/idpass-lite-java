/*
 * Copyright 2021 Newlogic Impact Lab Pte. Ltd.
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

import com.google.zxing.*;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;

import java.awt.image.BufferedImage;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * The QRCodeImageScanner externalizes the zxing dependency outside
 * of idpass-lite-java jar library.
 */

public class QRCodeImageScanner implements Function<BufferedImage, byte[]> {
    @Override
    public byte[] apply(BufferedImage img) {

        LuminanceSource source = new BufferedImageLuminanceSource(img);
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));

        byte[] card;

        try {
            Result result = new MultiFormatReader().decode(bitmap);
            Map m = result.getResultMetadata();

            if (m.containsKey(ResultMetadataType.BYTE_SEGMENTS)) {
                List L = (List) m.get(ResultMetadataType.BYTE_SEGMENTS);
                card = (byte[]) L.get(0);
            } else {
                card = result.getText().getBytes();
            }
        } catch (NotFoundException e) {
            return null;
        }

        return card;
    }
}
