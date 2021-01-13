package org.idpass.lite;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.system.ErrnoException;
import android.system.Os;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * This Android activity class is responsible for copying the
 * Dlib training data from assets to cache dir and setting the
 * environment variables needed by libidpasslite.so
 */

public class IDPassLiteActivity extends AppCompatActivity {

    private final String shapeData = "shape_predictor_5_face_landmarks.dat";
    private final String faceData = "dlib_face_recognition_resnet_model_v1.dat";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        try {
            File shapeDataFile = new File(getCacheDir() + "/" + shapeData);
            File faceDataFile = new File(getCacheDir() + "/" + faceData);

            if (!shapeDataFile.exists()) {
                InputStream fis = getAssets().open(shapeData);
                byte[] buf = new byte[fis.available()];
                fis.read(buf);
                fis.close();
                OutputStream fos = new FileOutputStream(shapeDataFile);
                fos.write(buf);
            }

            if (!faceDataFile.exists()) {
                InputStream fis = getAssets().open(faceData);
                byte[] buf = new byte[fis.available()];
                fis.read(buf);
                fis.close();
                OutputStream fos = new FileOutputStream(faceDataFile);
                fos.write(buf);
            }

            Os.setenv("SHAPEPREDICTIONDATA", getCacheDir().getAbsolutePath() + "/" + shapeData, true);
            Os.setenv("FACERECOGNITIONDATA",getCacheDir().getAbsolutePath() + "/" + faceData, true);

        } catch (IOException | ErrnoException e) {
            e.printStackTrace();
            Toast.makeText(getApplicationContext(), "Dlib models copy error", Toast.LENGTH_LONG);
        }
    }
}