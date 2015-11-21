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
            cipher = DESAlgorithm.DESencrypt(plain, key);


        }
        catch (DESAlgorithmException e)
        {
            System.err.println(e.getMessage());
        }
    }
}
