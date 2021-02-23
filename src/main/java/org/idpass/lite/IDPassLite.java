package org.idpass.lite;

/**
 * Initializer for standard Java applications.
 */
public class IDPassLite {
    private static boolean isInitialized = false;
    public static boolean initialize() {
        if (!isInitialized) {
            if (!IDPassLoader.loadLibrary()) {
                throw new RuntimeException("Failed to load libidpasslite.so");
            }
            isInitialized = true;
        }
        return isInitialized;
    }
}
