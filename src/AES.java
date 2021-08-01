package ir.aut;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AES {

    public static byte[] encrypt (byte[] plaintext,byte[] keyBytes,byte[] IV ) throws Exception
    {

        //  byte[] keyBytes = setSizeOfKey(key);


        //Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");

        //Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

        //Create IvParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        //Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        //Perform Encryption
        byte[] cipherText = cipher.doFinal(plaintext);

        return cipherText;
    }



    public static byte[] decrypt (byte[] cipherText, byte[] keyBytes,byte[] IV) throws Exception
    {

        //   byte[] keyBytes = setSizeOfKey(key);

        //Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");

        //Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

        //Create IvParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        //Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        //Perform Decryption
        byte[] decryptedText = cipher.doFinal(cipherText);

        return  decryptedText;
    }

}
