package etna.crypt.algorithms;

import java.lang.*;

public class DESAlgorithm
{
    ////////////////////////////////////////////////////////////////////////
    // CONSTRUCTORS
    ////////////////////////////////////////////////////////////////////////

    public DESAlgorithm()
    {
        System.out.println("des instanciation");
    }

    ////////////////////////////////////////////////////////////////////////
    // PUBLIC STATIC METHODS
    ////////////////////////////////////////////////////////////////////////

    public static String KeySchedule(String key, Integer round)
    {
        System.out.println(key);
        printBinary(stringToBinary(key));
        return "foobar";
    }

    ////////////////////////////////////////////////////////////////////////
    // PRIVATE STATIC METHODS
    ////////////////////////////////////////////////////////////////////////

    private static byte[] stringToBinary(String str)
    {
        return str.getBytes();
    }
    private static void printBinary(byte[] binaryData)
    {
        String          byteString;
        StringBuilder   output = new StringBuilder();

        for (byte b : binaryData)
        {
            byteString = Integer.toBinaryString(b);
            if (byteString.length() < 8)
            {
                byteString = "0" + byteString;
            }
            output.append(byteString);
            output.append(" ");
        }
        System.out.println(output.toString());
    }
}
