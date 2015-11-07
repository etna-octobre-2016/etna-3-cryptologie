package etna.crypt.algorithms;

import java.lang.*;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;

public class DESAlgorithm
{
    ////////////////////////////////////////////////////////////////////////
    // CONSTANTS
    ////////////////////////////////////////////////////////////////////////
    private static int IP_TABLE[][] = {
        {58, 50, 42, 34, 26, 18, 10, 2},
        {60, 52, 44, 36, 28, 20, 12, 4},
        {62, 54, 46, 38, 30, 22, 14, 6},
        {64, 56, 48, 40, 32, 24, 16, 8},
        {57, 49, 41, 33, 25, 17, 9,  1},
        {59, 51, 43, 35, 27, 19, 11, 3},
        {61, 53, 45, 37, 29, 21, 13, 5},
        {63, 55, 47, 39, 31, 23, 15, 7}
    };
    private static int VALID_KEY_NUMBER_OF_BYTES = 8;

    ////////////////////////////////////////////////////////////////////////
    // PUBLIC STATIC METHODS
    ////////////////////////////////////////////////////////////////////////

    public static String DESdecrypt(String message, String key)
    {
        return "toto";
    }
    public static String DESencrypt(String message, String key) throws DESAlgorithmException
    {
        byte[] binaryKey;

        binaryKey = stringToBinary(key);
        validateKey(binaryKey);
        System.out.println(key);
        KeySchedule(binaryKey, 16);
        return "toto";
    }

    ////////////////////////////////////////////////////////////////////////
    // PRIVATE STATIC METHODS
    ////////////////////////////////////////////////////////////////////////

    private static long binaryToLong(byte[] binaryData)
    {
        ByteBuffer buffer;

        buffer = ByteBuffer.wrap(binaryData);
        return buffer.getLong();
    }
    private static byte[] KeySchedule(byte[] binaryKey, Integer round)
    {
        System.out.println("nombre d'octets: " + binaryKey.length);
        System.out.println("nombre de bits: " + (binaryKey.length * 8));
        printBinary(binaryKey);
        System.out.println(Long.toHexString(
                binaryToLong(
                    binaryKey
                )
            )
        );
        return binaryKey;
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
    private static byte[] stringToBinary(String str)
    {
        return str.getBytes(Charset.forName("UTF-8"));
    }
    private static boolean validateKey(byte[] binaryKey) throws DESAlgorithmException
    {
        int numberOfBytes;

        numberOfBytes = binaryKey.length;
        if (numberOfBytes != VALID_KEY_NUMBER_OF_BYTES)
        {
            throw new DESAlgorithmException("Invalid key provided. Must be a " + (VALID_KEY_NUMBER_OF_BYTES * 8) + " bits key.");
        }
        return true;
    }
}
