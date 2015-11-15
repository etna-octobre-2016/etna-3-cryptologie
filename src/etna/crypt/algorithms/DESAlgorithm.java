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
    private static int          VALID_KEY_NUMBER_OF_BYTES = 8;
    private static int          VALID_MESSAGE_MAX_NUMBER_OF_BYTES = 8;

    ////////////////////////////////////////////////////////////////////////
    // PUBLIC STATIC METHODS
    ////////////////////////////////////////////////////////////////////////

    public static String        DESdecrypt(String message, String key)
    {
        return "toto";
    }
    public static String        DESencrypt(String message, String key) throws DESAlgorithmException
    {
        byte[] binaryKey;
        byte[] binaryMessage;
        byte[] roundKey;

        binaryKey = key.getBytes(Charset.forName("UTF-8"));
        binaryMessage = message.getBytes(Charset.forName("UTF-8"));
        validateKey(binaryKey);
        validateMessage(binaryMessage);
        roundKey = KeySchedule(binaryKey, 1);
        return "toto";
    }
    public static byte[]        KeySchedule(byte[] binaryKey, Integer round)
    {
        System.out.println("before pc1: " + binaryToString(binaryKey));
        System.out.println("after pc1: " + binaryToString(processPC1(binaryKey)));
        return binaryKey;
    }

    ////////////////////////////////////////////////////////////////////////
    // PRIVATE STATIC METHODS
    ////////////////////////////////////////////////////////////////////////

    private static long         binaryToLong(byte[] binaryData)
    {
        ByteBuffer buffer;

        buffer = ByteBuffer.wrap(binaryData);
        return buffer.getLong();
    }
    private static String       binaryToString(byte[] binaryData, char delimiter)
    {
        int           i;
        int           length;
        StringBuilder output;

        length = binaryData.length;
        output = new StringBuilder();
        for (i = 0; i < length; i++)
        {
            output.append(byteToString(binaryData[i]));
            if (i + 1 < length && delimiter != '\0')
            {
                output.append(delimiter);
            }
        }
        return output.toString();
    }
    private static String       binaryToString(byte[] binaryData)
    {
        return binaryToString(binaryData, '\0');
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
    private static int          calculateBitRelativeIndex(byte[] bytes, int absoluteIndex) throws DESAlgorithmException
    {
        return 7 - (int)Math.floor(absoluteIndex % bytes.length);
    }
    private static int          calculateByteIndex(byte[] bytes, int bitIndex) throws DESAlgorithmException
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
    private static byte         findByte(byte[] bytes, int bitIndex) throws DESAlgorithmException
    {
        int byteIndex;

        byteIndex = calculateByteIndex(bytes, bitIndex);
        return bytes[byteIndex];
    }
    private static byte[]       padBinaryNumber(byte[] number, int maxLength)
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
    private static byte[]       processPC1(byte[] bytes)
    {
        byte[]          outputBinary;
        int             i;
        int             j;
        int             lTableLength;
        int             lTableRowLength;
        int             rTableLength;
        int             rTableRowLength;
        int[]           lTableRow;
        int[]           rTableRow;
        int[][]         lTable = {
            {57, 49, 41, 33, 25, 17, 9},
            {1,  58, 50, 42, 34, 26, 18},
            {10, 2,  59, 51, 43, 35, 27},
            {19, 11, 3,  60, 52, 44, 36}
        };
        int[][]         rTable = {
            {63, 55, 47, 39, 31, 23, 15},
            {7,  62, 54, 46, 38, 30, 22},
            {14, 6,  61, 53, 45, 37, 29},
            {21, 13, 5,  28, 20, 12, 4}
        };
        List<Byte>      outputList;
        String          input;
        String          output;
        StringBuilder   lOutput;
        StringBuilder   rOutput;

        input = binaryToString(bytes);
        lTableLength = lTable.length;
        lOutput = new StringBuilder();
        for (i = 0; i < lTableLength; i++)
        {
            lTableRow = lTable[i];
            lTableRowLength = lTableRow.length;
            for (j = 0; j < lTableRowLength; j++)
            {
                lOutput.append(input.charAt(lTableRow[j] - 1));
            }
        }
        rTableLength = rTable.length;
        rOutput = new StringBuilder();
        for (i = 0; i < rTableLength; i++)
        {
            rTableRow = rTable[i];
            rTableRowLength = rTableRow.length;
            for (j = 0; j < rTableRowLength; j++)
            {
                rOutput.append(input.charAt(rTableRow[j] - 1));
            }
        }
        output = lOutput.toString() + rOutput.toString();
        outputList = Arrays.asList(ArrayUtils.toObject(stringToBinary(output)));
        return ArrayUtils.toPrimitive(outputList.toArray(new Byte[outputList.size()]));
    }
    private static byte[]       shiftBinary(byte[] bytes, int count, boolean isCircular)
    {
        long        number;
        long        shiftedNumber;
        ByteBuffer  buffer;

        number = binaryToLong(bytes);
        if (isCircular)
        {

            shiftedNumber = (count < 0) ? (number >> (-count) | number << (Long.SIZE + count)) : (number << count | number >> (Long.SIZE - count));
        }
        else
        {
            shiftedNumber = (count < 0) ? number >> (-count) : number << count;
        }
        buffer = ByteBuffer.allocate(bytes.length);
        buffer.putLong(shiftedNumber);
        return buffer.array();
    }
    private static byte[]       shiftBinary(byte[] bytes, int count)
    {
        return shiftBinary(bytes, count, true);
    }
    private static String       shiftBinary(String str, int count, boolean isCircular)
    {
        int           length;
        int           outputLength;
        StringBuilder output;

        length = str.length();
        output = new StringBuilder();
        if (isCircular)
        {
            if (count < 0)
            {
                output.append(str.substring(length + count));
                output.append(str.substring(0, length + count));
            }
            else
            {
                output.append(str.substring(count));
                output.append(str.substring(0, count));
            }
        }
        else
        {
            if (count < 0)
            {
                output.append(str.substring(0, length + count));
            }
            else
            {
                output.append(str.substring(count));
            }
            outputLength = output.length();
            while (outputLength < length)
            {
                if (count < 0)
                {
                    output.insert(0, '0');
                }
                else
                {
                    output.append('0');
                }
                outputLength++;
            }
        }
        return output.toString();
    }
    private static byte[]       stringToBinary(String str)
    {
        BigInteger number;

        number = new BigInteger(str, 2);
        return number.toByteArray();
    }
    private static byte[]       swapBits(byte[] bytes, int bit1Index, int bit2Index) throws DESAlgorithmException
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
    private static boolean      validateKey(byte[] binaryKey) throws DESAlgorithmException
    {
        int numberOfBytes;

        numberOfBytes = binaryKey.length;
        if (numberOfBytes != VALID_KEY_NUMBER_OF_BYTES)
        {
            throw new DESAlgorithmException("Invalid key provided. Must be a " + (VALID_KEY_NUMBER_OF_BYTES * 8) + " bits key.");
        }
        return true;
    }
    private static boolean      validateMessage(byte[] binaryMessage) throws DESAlgorithmException
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
