package org.idpass.lite.test.utils;

import java.util.Random;

public class Helper {

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
