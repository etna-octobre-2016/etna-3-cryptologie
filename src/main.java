import java.lang.*;
import java.util.Arrays;
import java.nio.charset.Charset;
import etna.crypt.algorithms.*;

class Main
{
    public static void main(String[] args)
    {
        testETNA();
    }
    public static void testETNA()
    {
        try
        {
            Charset encoding;
            String key;
            String input;
            byte[] cipher;
            byte[] output;

            encoding = Charset.forName("UTF-8");
            key = "12345678";
            input = "ABCDEFGH";
            cipher = DESAlgorithm.DESencrypt(input.getBytes(encoding), key.getBytes(encoding));
            output = DESAlgorithm.DESdecrypt(cipher, key.getBytes(encoding));
            System.out.println("input:\t" + input);
            System.out.println("cipher:\t" + new String(cipher, encoding));
            System.out.println("output:\t" + new String(output, encoding));
        }
        catch (DESAlgorithmException e)
        {
            System.err.println(e.getMessage());
        }
    }
}
