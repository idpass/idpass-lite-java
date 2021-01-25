package org.idpass.lite.android;

import android.content.res.AssetManager;
import org.idpass.lite.IDPassReader;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Initializer for Android mobile applications.
 *
 * This class is used to copy Dlib's model dat files from asset
 * to cache dir and set environment variables needed by
 * libidpasslite.so.
 */
public class IDPassLite {

    private static final String shapeData = "shape_predictor_5_face_landmarks.dat";
    private static final String faceData = "dlib_face_recognition_resnet_model_v1.dat";
    private static final String SHAPEPREDICTIONDATA = "SHAPEPREDICTIONDATA";
    private static final String FACERECOGNITIONDATA = "FACERECOGNITIONDATA";
    private static boolean isInitialized = false;

    public static boolean initialize(File cachedir, AssetManager am)
    {
        if (!isInitialized) {
            System.loadLibrary("idpasslite");
            isInitialized = true;
        }

        File shapeDataFile = new File(cachedir.getAbsolutePath() + "/" + shapeData);
        File faceDataFile = new File(cachedir.getAbsolutePath() + "/" + faceData);

        try {
            if (!shapeDataFile.exists()) {
                InputStream fis = am.open(shapeData);
                byte[] buf = new byte[fis.available()];
                fis.read(buf);
                fis.close();
                OutputStream fos = new FileOutputStream(shapeDataFile);
                fos.write(buf);
            }

            if (!faceDataFile.exists()) {
                InputStream fis = am.open(faceData);
                byte[] buf = new byte[fis.available()];
                fis.read(buf);
                fis.close();
                OutputStream fos = new FileOutputStream(faceDataFile);
                fos.write(buf);
            }

            IDPassReader.setenv(SHAPEPREDICTIONDATA, cachedir.getAbsolutePath() + "/" + shapeData, true);
            IDPassReader.setenv(FACERECOGNITIONDATA, cachedir.getAbsolutePath() + "/" + faceData, true);

        } catch (IOException e) {
            return false;
        }

        return true;
    }
}
