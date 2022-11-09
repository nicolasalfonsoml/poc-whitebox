package com.example.whitboxwithjni;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import com.example.whitboxwithjni.databinding.ActivityMainBinding;
import java.security.SecureRandom;


public class MainActivity extends AppCompatActivity {

    private ActivityMainBinding binding;

    // hello wbc world
    String plainTextHex = "68656c6c6f2077626320776f726c6420";

    TextView editTextInput;
    TextView editTextEncryptedInput ;
    TextView editTextDecryptedInput;
    TextView editTextIV;
    TextView editTextMsgToHex;
    Button buttonEncrypt;
    Button buttonDecrypt;

    WhiteBox wbc = new WhiteBox();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        editTextInput = binding.editTextInput;
        editTextEncryptedInput = binding.editTextEncryptedInput;
        editTextDecryptedInput = binding.editTextDecryptedInput;
        editTextIV = binding.editTextIV;
        editTextMsgToHex = binding.editTextMsgToHex;
        buttonEncrypt = (Button) binding.buttonEncrypt;
        buttonDecrypt = (Button) binding.buttonDecrypt;

        buttonEncrypt.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                encrypt();
            }
        });

        buttonDecrypt.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                decrypt();
            }
        });

    }

    private void encrypt() {
        String input = editTextInput.getText().toString();

        if(input.length() == 0 || input == ""){
            Toast.makeText(this, "Ingresar entrada para encriptar", Toast.LENGTH_LONG).show();
            return;
        }

        String inputHex = convertStringToHex(input);
        editTextMsgToHex.setText(inputHex);

        SecureRandom random = new SecureRandom();
        byte ivOrNonce[] = new byte[16];
        random.nextBytes(ivOrNonce);
        String ivOrNonceHex = bytesToHex(ivOrNonce);
        editTextIV.setText(ivOrNonceHex);

        System.out.println("WBC inputHex --> " + inputHex.length());
        byte[] cipher = wbc.encrypt(inputHex,ivOrNonceHex);
        String cipherHex = bytesToHex(cipher);
        System.out.println("WBC cipher length --> " + cipher.length);
        System.out.println("WBC cipher --> " + cipher);
        System.out.println("WBC cipherHex --> " + cipherHex);
        editTextEncryptedInput.setText(cipherHex);
    }

    private void decrypt() {

        String inputEncrypted = editTextEncryptedInput.getText().toString();
        if(inputEncrypted.length() == 0 || inputEncrypted == ""){
            Toast.makeText(this, "No se encontro entrada encriptada", Toast.LENGTH_LONG).show();
            return;
        }

        byte[] plain = wbc.decrypt(inputEncrypted,editTextIV.getText().toString());
        String plainHex = bytesToHex(plain);
        editTextDecryptedInput.setText(hexToString(plainHex));
    }

    private static String convertStringToHex(String str) {
        StringBuilder stringBuilder = new StringBuilder();
        char[] charArray = str.toCharArray();
        for (char c : charArray) {
            String charToHex = Integer.toHexString(c);
            stringBuilder.append(charToHex);
        }
        return stringBuilder.toString();
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static String hexToString(String hex) {
        StringBuilder sb = new StringBuilder();
        char[] hexData = hex.toCharArray();
        for (int count = 0; count < hexData.length - 1; count += 2) {
            int firstDigit = Character.digit(hexData[count], 16);
            int lastDigit = Character.digit(hexData[count + 1], 16);
            int decimal = firstDigit * 16 + lastDigit;
            sb.append((char) decimal);
        }
        return sb.toString();
    }

}