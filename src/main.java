
/**
 * Imports test
 */

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * Imports ETNA
 */

import java.nio.charset.Charset;
import etna.crypt.algorithms.*;

class Main
{
    public static void main(String[] args)
    {
        testETNA();

        testReference();
    }
    public static void testETNA()
    {
        try
        {
            byte[] cipher;
            byte[] plain;

            System.out.println("Hello World! My name is Said AHEMT"); // Display the string

            cipher = DESAlgorithm.DESencrypt("ABCDEFGH".getBytes(Charset.forName("UTF-8")), "12345678".getBytes(Charset.forName("UTF-8")));

            System.out.println("cipher");
            System.out.println(cipher);

            // plain = DESAlgorithm.DESdecrypt(cipher, "12345678".getBytes(Charset.forName("UTF-8")));
            //
            // System.out.println("plain: " + new String(plain, Charset.forName("UTF-8")));
        }
        catch (DESAlgorithmException e)
        {
            System.err.println(e.getMessage());
        }
    }
    public static void testReference()
    {
        try{

		    KeyGenerator keygenerator = KeyGenerator.getInstance("DES");
            SecretKeySpec myDesKey = new SecretKeySpec("12345678".getBytes(Charset.forName("UTF-8")), "DES");

		    Cipher desCipher;

		    // Create the cipher
		    desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

		    // Initialize the cipher for encryption
		    desCipher.init(Cipher.ENCRYPT_MODE, myDesKey);

		    //sensitive information
		    byte[] text = "ABCDEFGH".getBytes(Charset.forName("UTF-8"));

		    System.out.println("Text [Byte Format] : " + text);
		    System.out.println("Text : " + new String(text));

		    // Encrypt the text
		    byte[] textEncrypted = desCipher.doFinal(text);

		    System.out.println("Text Encryted : " + textEncrypted);

		    // Initialize the same cipher for decryption
		    desCipher.init(Cipher.DECRYPT_MODE, myDesKey);

		    // Decrypt the text
		    byte[] textDecrypted = desCipher.doFinal(textEncrypted);

		    System.out.println("Text Decryted : " + new String(textDecrypted));

		}catch(NoSuchAlgorithmException e){
			e.printStackTrace();
		}catch(NoSuchPaddingException e){
			e.printStackTrace();
		}catch(InvalidKeyException e){
			e.printStackTrace();
		}catch(IllegalBlockSizeException e){
			e.printStackTrace();
		}catch(BadPaddingException e){
			e.printStackTrace();
		}
    }
}
