package etna.crypt.algorithms;

import java.lang.*;

public class DESAlgorithm
{
    ////////////////////////////////////////////////////////////////////////
    // ATTRIBUTES
    ////////////////////////////////////////////////////////////////////////
    int ipTable[][] = {
        {58, 50, 42, 34, 26, 18, 10, 2},
        {60, 52, 44, 36, 28, 20, 12, 4},
        {62, 54, 46, 38, 30, 22, 14, 6},
        {64, 56, 48, 40, 32, 24, 16, 8},
        {57, 49, 41, 33, 25, 17, 9,  1},
        {59, 51, 43, 35, 27, 19, 11, 3},
        {61, 53, 45, 37, 29, 21, 13, 5},
        {63, 55, 47, 39, 31, 23, 15, 7}
    };

    ////////////////////////////////////////////////////////////////////////
    // PUBLIC STATIC METHODS
    ////////////////////////////////////////////////////////////////////////

    public static String DESdecrypt(String message, String key)
    {
        return "toto";
    }
    public static String DESencrypt(String message, String key)
    {
        return "toto";
    }
    public static String KeySchedule(String key, Integer round)
    {
        System.out.println(key);
        printBinary(stringToBinary(key));
        return "foobar";
    }

    ////////////////////////////////////////////////////////////////////////
    // PRIVATE STATIC METHODS
    ////////////////////////////////////////////////////////////////////////

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
    private static byte[] stringToBinary(String str)
    {
        return str.getBytes();
    }
}
