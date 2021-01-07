package org.idpass.lite.test.utils;

import org.idpass.lite.Card;
import org.idpass.lite.exceptions.InvalidCardException;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.BitSet;
import java.util.Random;
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
}
