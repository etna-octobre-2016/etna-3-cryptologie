package etna.crypt.algorithms;

import java.lang.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;

public class DESAlgorithm
{
    ///////////////////////////////////////////////////////////////////////////
    // PRIVATE CONSTANTS
    ///////////////////////////////////////////////////////////////////////////

    private static int          VALID_MESSAGE_NUMBER_OF_BYTES = 8;

    ///////////////////////////////////////////////////////////////////////////
    // PUBLIC STATIC METHODS
    ///////////////////////////////////////////////////////////////////////////

    public static byte[]        DESdecrypt(byte[] message, byte[] key) throws DESAlgorithmException
    {
        return new byte[0];
    }
    public static byte[]        DESencrypt(byte[] message, byte[] key) throws DESAlgorithmException
    {
        byte[] ipResult;

        message = padBinary(message, VALID_MESSAGE_NUMBER_OF_BYTES);
        ipResult = processIP(message);
        System.out.println("Plain:\t" + binaryToString(message, ' '));
        System.out.println("IP:\t" + binaryToString(ipResult, ' '));

        return new byte[0];
    }
    public static byte[]        KeySchedule(byte[] key, Integer round) throws DESAlgorithmException
    {
        return new byte[0];
    }


    ///////////////////////////////////////////////////////////////////////////
    // DES FUNCTIONS
    ///////////////////////////////////////////////////////////////////////////

    private static byte[]       processIP(byte[] bytes) throws DESAlgorithmException
    {
        int[][] table = {
            {58, 50, 42, 34, 26, 18, 10, 2},
            {60, 52, 44, 36, 28, 20, 12, 4},
            {62, 54, 46, 38, 30, 22, 14, 6},
            {64, 56, 48, 40, 32, 24, 16, 8},
            {57, 49, 41, 33, 25, 17, 9,  1},
            {59, 51, 43, 35, 27, 19, 11, 3},
            {61, 53, 45, 37, 29, 21, 13, 5},
            {63, 55, 47, 39, 31, 23, 15, 7}
        };

        if (bytes.length != 8)
        {
            throw new DESAlgorithmException("Invalid IP input. Must be 64 bits long. Number of bits provided: " + (bytes.length * 8));
        }
        return permutate(bytes, table);
    }

    ///////////////////////////////////////////////////////////////////////////
    // UTILITY METHODS
    ///////////////////////////////////////////////////////////////////////////

    private static String       binaryToString(byte[] bytes, char delimiter)
    {
        int           i;
        int           length;
        StringBuilder output;

        length = bytes.length;
        output = new StringBuilder();
        for (i = 0; i < length; i++)
        {
            output.append(byteToString(bytes[i]));
            if (i + 1 < length && delimiter != '\0')
            {
                output.append(delimiter);
            }
        }
        return output.toString();
    }
    private static String       binaryToString(byte[] bytes)
    {
        return binaryToString(bytes, '\0');
    }
    private static String       byteToString(byte b)
    {
        int     byteStringLength;
        long    number;
        String  byteString;

        number = Byte.toUnsignedLong(b);
        byteString = Long.toUnsignedString(number, 2);
        byteStringLength = byteString.length();
        while (byteStringLength < 8)
        {
            byteString = "0" + byteString;
            byteStringLength++;
        }
        return byteString;
    }
    private static byte[]       padBinary(byte[] bytes, int maxLength)
    {
        List<Byte>  bytesFixedList;
        List<Byte>  bytesList;
        int         numberOfBytes;

        bytesFixedList = Arrays.asList(ArrayUtils.toObject(bytes));
        bytesList = new ArrayList<Byte>(bytesFixedList);
        numberOfBytes = bytes.length;
        while (numberOfBytes < maxLength)
        {
            bytesList.add(0, new Byte("0"));
            numberOfBytes++;
        }
        return ArrayUtils.toPrimitive(bytesList.toArray(new Byte[numberOfBytes]));
    }
    private static byte[]       permutate(byte[] bytes, int[][] table)
    {
        int             i;
        int             inputLength;
        int             j;
        int             tableLength;
        int             tableRowLength;
        int[]           tableRow;
        String          input;
        StringBuilder   output;

        input = binaryToString(bytes);
        inputLength = input.length();
        output = new StringBuilder();
        tableLength = table.length;
        for (i = 0; i < tableLength; i++)
        {
            tableRow = table[i];
            tableRowLength = tableRow.length;
            for (j = 0; j < tableRowLength; j++)
            {
                output.append(input.charAt(tableRow[j] - 1));
            }
        }
        return stringToBinary(output.toString());
    }
    private static byte[]       stringToBinary(String str)
    {
        int         byteArrayLength;
        int         numberOfBytes;
        byte[]      byteArray;
        BigInteger  number;
        List<Byte>  subset;

        number = new BigInteger(str, 2);
        numberOfBytes = (int)Math.ceil(str.length() / 8);
        byteArray = number.toByteArray();
        byteArrayLength = byteArray.length;
        if (byteArrayLength > numberOfBytes)
        {
            subset = Arrays.asList(ArrayUtils.toObject(byteArray));
            subset = subset.subList(byteArrayLength - numberOfBytes, subset.size());
            byteArray = ArrayUtils.toPrimitive(subset.toArray(new Byte[numberOfBytes]));
        }
        return byteArray;
    }
}
