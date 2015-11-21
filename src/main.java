import java.util.Arrays;
import java.nio.charset.Charset;
import etna.crypt.algorithms.*;

class Main
{
    public static void main(String[] args)
    {
        testETNA();

        // testReference();
    }
    public static void testETNA()
    {
        try
        {
            byte[] cipher;
            byte[] key;
            byte[] plain;
            byte[] outputPlain;

            plain = "ABCDEFGH".getBytes(Charset.forName("UTF-8"));
            key = "12345678".getBytes(Charset.forName("UTF-8"));

            System.out.println("plain:\t\t" + DESAlgorithm.binaryToString(plain, ' '));

            cipher = DESAlgorithm.DESencrypt(plain, key);

            System.out.println("cipher:\t\t" + DESAlgorithm.binaryToString(cipher, ' '));

            outputPlain = DESAlgorithm.DESdecrypt(cipher, key);

            System.out.println("output:\t\t" + DESAlgorithm.binaryToString(outputPlain, ' '));

            if (Arrays.equals(plain, outputPlain))
            {
                System.out.println("Resultat OK");
            }
            else
            {
                System.out.println("Resultat KO");
            }
        }
        catch (DESAlgorithmException e)
        {
            System.err.println(e.getMessage());
        }
    }
}
