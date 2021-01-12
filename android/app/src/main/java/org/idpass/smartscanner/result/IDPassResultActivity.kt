package org.idpass.smartscanner.result

import android.app.Activity
import android.os.Bundle
import android.system.Os
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import com.google.protobuf.ByteString
import org.api.proto.KeySet
import org.api.proto.byteArray
import org.idpass.lite.exceptions.CardVerificationException
import org.idpass.lite.exceptions.InvalidCardException
import org.idpass.lite.exceptions.InvalidKeyException
import org.idpass.lite.IDPassHelper
import org.idpass.lite.IDPassReader
import org.idpass.lite.Card
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.*

//class IDPassReaderActivity : AppCompatActivity() {
class IDPassResultActivity : Activity() {

    val shapeData = "shape_predictor_5_face_landmarks.dat"
    val faceData = "dlib_face_recognition_resnet_model_v1.dat"

    companion object {
        /// TODO: To set these three byte arrays with our default demo key values
        var encryptionkey = IDPassHelper.generateEncryptionKey()
        var signaturekey = IDPassHelper.generateSecretSignatureKey()
        var publicVerificationKey: ByteArray = Arrays.copyOfRange(signaturekey, 32, 64)

        var keyset = KeySet.newBuilder()
                .setEncryptionKey(ByteString.copyFrom(encryptionkey))
                .setSignatureKey(ByteString.copyFrom(signaturekey))
                .addVerificationKeys(byteArray.newBuilder()
                .setTyp(byteArray.Typ.ED25519PUBKEY)
                .setVal(ByteString.copyFrom(publicVerificationKey)).build())
                .build()

        private var idPassReader = IDPassReader(keyset, null)
    }

    var m_pincode: String = ""
    var m_qrbytes:ByteArray? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_idpassreader)

        // Copy Dlib's shape and face dat files to cache directory and set env var for each

        val facedata = File(cacheDir.absolutePath + "/" + faceData)
        if (!facedata.exists()) {
            val fis = assets.open(faceData)
            val buf = ByteArray(fis.available())
            fis.read(buf)
            fis.close()
            val fos = FileOutputStream(facedata)
            fos.write(buf)
        }

        val shapedata = File(cacheDir.absolutePath + "/" + shapeData)
        if (!shapedata.exists()) {
            val fis = assets.open(shapeData)
            val buf = ByteArray(fis.available())
            fis.read(buf)
            fis.close()
            val fos = FileOutputStream(shapedata)
            fos.write(buf)
        }

        // Set environment variable for libidpasslite.so to find and load

        Os.setenv("SHAPEPREDICTIONDATA", cacheDir.absolutePath + "/" + shapeData, true)
        Os.setenv("FACERECOGNITIONDATA", cacheDir.absolutePath + "/" + faceData, true)

        val back2camera: Button = findViewById(R.id.back2camera) as Button
        back2camera.setOnClickListener {
            finish()
        }

        val pincodeauth: Button = findViewById(R.id.pincodeauth) as Button
        pincodeauth.setOnClickListener {
            var cardpincode = findViewById(R.id.cardpincode) as EditText
            m_pincode = cardpincode.text.toString()
            m_qrbytes?.let {
                var qrstr = readCard(idPassReader, it)
                var tv =  (findViewById(R.id.hex) as TextView)
                tv.setText("\n\n" + qrstr + "\n")
            }
        }

        val intent = intent
        val qrbytes = intent.getByteArrayExtra("qrbytes")
        var qrstr = readCard(idPassReader, qrbytes)

        var tv =  (findViewById(R.id.hex) as TextView)
        tv.setText("\n\n" + qrstr + "\n")

    }

    private fun readCard(idPassReader: IDPassReader, qrbytes: ByteArray, charsPerLine: Int = 33): String {
        if (charsPerLine < 4 || qrbytes.isEmpty()) {
            return ""
        }

        val dump = StringBuilder()
        var authStatus = "NO"
        var certStatus = ""
        var card: Card? = null

        try {
            try {
                card = idPassReader.open(qrbytes)
                certStatus = if (card.hasCertificate()) "Verified" else "No certificate"
            } catch (ice: InvalidCardException) {
                card = idPassReader.open(qrbytes, true)
                certStatus = if (card.hasCertificate()) "Not Verified" else "No certificate"
            }

            if (card != null) { // or use !!

                if (m_pincode.length > 0) {
                    try {
                        card.authenticateWithPIN(m_pincode)
                        authStatus = "YES"
                        Toast.makeText(getApplicationContext(), "Authenticated", Toast.LENGTH_LONG).show();
                    } catch (ve: CardVerificationException) {
                        Toast.makeText(getApplicationContext(), "Authentication fail", Toast.LENGTH_LONG).show();
                    }
                }

                var sdf = SimpleDateFormat("yyyy/MM/dd")
                var surname = card.surname
                var givenname = card.givenName
                var dob = card.dateOfBirth
                var pob = card.placeOfBirth

                dump.append("Surname: " + surname + "\n")
                dump.append("Given Name: " + givenname + "\n")

                if (dob != null) {
                    dump.append("Date of Birth: " + sdf.format(dob) + "\n")
                }

                if (pob.length > 0) {
                    dump.append("Place of Birth: " + pob + "\n")
                }

                dump.append("\n-------------------------\n\n")

                for ((key, value) in card.cardExtras) {
                    dump.append(key + ": " + value + "\n")
                }

                var address = card.postalAddress
                if (address != null) {
                    var postalCode = address.postalCode
                    var administrativeArea = address.administrativeArea
                    var languageCode = address.languageCode
                    var addressLines = address.addressLinesList.joinToString(",")

                    dump.append("Language Code: " + languageCode)
                    dump.append("Postal Code: " + postalCode)
                    dump.append("Administrative Area: " + administrativeArea)
                    dump.append("Address: " + addressLines)
                }

                dump.append("\n-------------------------\n\n")
                dump.append("Authenticated: " + authStatus + "\n")
                dump.append("Certificate  : " + certStatus + "\n")

                m_qrbytes = qrbytes.clone()

                return dump.toString()

            } else {
                return "nevererror"
            }

        } catch (ike: InvalidKeyException) {
            return "Reader keyset not authorized"
        } catch (e: Exception) {
            return "NOT AN IDPASS CARD"
        }
    }
}
