package etna.crypt.algorithms;

import java.lang.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import org.apache.commons.lang3.ArrayUtils;

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
    private static int VALID_MESSAGE_MAX_NUMBER_OF_BYTES = 8;

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
        byte[] binaryMessage;

        binaryKey = stringToBinary(key);
        binaryMessage = stringToBinary(message);
        validateKey(binaryKey);
        validateMessage(binaryMessage);

        binaryMessage = padBinaryNumber(binaryMessage, VALID_MESSAGE_MAX_NUMBER_OF_BYTES);
        System.out.println(binaryToString(binaryMessage));
        binaryMessage = swapBits(binaryMessage, 0, 24);
        System.out.println(binaryToString(binaryMessage));

        return "toto";
    }
    public static byte[] KeySchedule(byte[] binaryKey, Integer round)
    {
        System.out.println("nombre d'octets: " + binaryKey.length);
        System.out.println("nombre de bits: " + (binaryKey.length * 8));
        System.out.println(binaryToString(binaryKey));
        System.out.println(Long.toHexString(
                binaryToLong(
                    binaryKey
                )
            )
        );
        return binaryKey;
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
    private static String binaryToString(byte[] binaryData)
    {
        StringBuilder output;

        output = new StringBuilder();
        for (byte b : binaryData)
        {

            output.append(byteToString(b));
            output.append(" ");
        }
        return output.toString();
    }
    private static String byteToString(byte b)
    {
        int     byteStringLength;
        String  byteString;

        byteString = Integer.toBinaryString(b);
        byteStringLength = byteString.length();
        while (byteStringLength < 8)
        {
            byteString = "0" + byteString;
            byteStringLength++;
        }
        return byteString;
    }
    private static int calculateBitRelativeIndex(byte[] bytes, int absoluteIndex) throws DESAlgorithmException
    {
        return 7 - (int)Math.floor(absoluteIndex % bytes.length);
    }
    private static int calculateByteIndex(byte[] bytes, int bitIndex) throws DESAlgorithmException
    {
        int byteIndex;
        int maxByteIndex;

        byteIndex = bytes.length - 1 - (int)Math.floor(bitIndex / 8);
        maxByteIndex = bytes.length - 1;
        if (byteIndex < 0 || byteIndex > maxByteIndex)
        {
            throw new DESAlgorithmException("byte not found for bit index " + bitIndex);
        }
        return byteIndex;
    }
    private static byte findByte(byte[] bytes, int bitIndex) throws DESAlgorithmException
    {
        int byteIndex;

        byteIndex = calculateByteIndex(bytes, bitIndex);
        return bytes[byteIndex];
    }
    private static byte[] padBinaryNumber(byte[] number, int maxLength)
    {
        List<Byte>  bytesFixedList;
        List<Byte>  bytesList;
        int         numberOfBytes;

        bytesFixedList = Arrays.asList(ArrayUtils.toObject(number));
        bytesList = new ArrayList<Byte>(bytesFixedList);
        numberOfBytes = number.length;
        while (numberOfBytes < maxLength)
        {
            bytesList.add(0, new Byte("0"));
            numberOfBytes++;
        }
        return ArrayUtils.toPrimitive(bytesList.toArray(new Byte[numberOfBytes]));
    }
    private static byte[] shiftBinary(byte[] bytes, int count, int maxLength)
    {
        byte[]      result;
        BigInteger  number;

        number = new BigInteger(bytes);
        number = (count < 0) ? number.shiftRight(-count) : number.shiftLeft(count);
        result = number.toByteArray();
        if (result.length < maxLength)
        {
            return padBinaryNumber(result, maxLength);
        }
        return result;
    }
    private static byte[] shiftBinary(byte[] bytes, int count)
    {
        return shiftBinary(bytes, count, -1);
    }
    private static byte[] stringToBinary(String str)
    {
        return str.getBytes(Charset.forName("UTF-8"));
    }
    private static byte[] swapBits(byte[] bytes, int bit1Index, int bit2Index) throws DESAlgorithmException
    {
        char            bit1Value;
        char            bit2Value;
        int             bit1RelativeIndex;
        int             bit2RelativeIndex;
        int             byte1Index;
        int             byte2Index;
        StringBuilder   byte1;
        StringBuilder   byte2;

        // Byte 1 data
        byte1 = new StringBuilder(byteToString(findByte(bytes, bit1Index)));
        byte1Index = calculateByteIndex(bytes, bit1Index);
        bit1RelativeIndex = calculateBitRelativeIndex(bytes, bit1Index);
        bit1Value = byte1.charAt(bit1RelativeIndex);

        // Byte 2 data
        byte2 = new StringBuilder(byteToString(findByte(bytes, bit2Index)));
        byte2Index = calculateByteIndex(bytes, bit2Index);
        bit2RelativeIndex = calculateBitRelativeIndex(bytes, bit2Index);
        bit2Value = byte2.charAt(bit2RelativeIndex);

        // Swap
        byte1.setCharAt(bit1RelativeIndex, bit2Value);
        byte2.setCharAt(bit2RelativeIndex, bit1Value);
        bytes[byte1Index] = Byte.parseByte(byte1.toString(), 2);
        bytes[byte2Index] = Byte.parseByte(byte2.toString(), 2);
        return bytes;
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
    private static boolean validateMessage(byte[] binaryMessage) throws DESAlgorithmException
    {
        int numberOfBytes;

        numberOfBytes = binaryMessage.length;
        if (numberOfBytes > VALID_MESSAGE_MAX_NUMBER_OF_BYTES)
        {
            throw new DESAlgorithmException("Invalid message provided. Must be a " + (VALID_MESSAGE_MAX_NUMBER_OF_BYTES * 8) + " bits message or less.");
        }
        return true;
    }
}
