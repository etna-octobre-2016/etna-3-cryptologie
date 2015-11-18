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
    private static int          ROUNDS = 16;
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
        byte[] binaryMessageIP;
        byte[] roundKey;

        binaryKey = key.getBytes(Charset.forName("UTF-8"));
        binaryMessage = padBinaryNumber(message.getBytes(Charset.forName("UTF-8")), VALID_MESSAGE_MAX_NUMBER_OF_BYTES);
        validateKey(binaryKey);
        validateMessage(binaryMessage);

        System.out.println("P:\t" + binaryToString(binaryMessage, ' '));

        binaryMessageIP = processIP(binaryMessage);

        System.out.println("IP:\t" + binaryToString(binaryMessageIP, ' '));

        System.out.println("FP:\t" + binaryToString(padBinaryNumber(processFP(binaryMessageIP), VALID_MESSAGE_MAX_NUMBER_OF_BYTES), ' '));

        System.out.println("output:\t" + new String(processFP(binaryMessageIP), Charset.forName("UTF-8")));

        System.out.println("S5:\t" + processS5("110000"));

        return "toto";
    }
    public static byte[]        KeySchedule(byte[] binaryKey, Integer round) throws DESAlgorithmException
    {
        int     i;
        String  key;
        String  left;
        String  right;

        if (round < 1 || round > ROUNDS)
        {
            throw new DESAlgorithmException("not valid round number " + round);
        }
        binaryKey = processPC1(binaryKey);
        key = binaryToString(binaryKey);
        left = key.substring(0, 28);
        right = key.substring(28);
        for (i = 1; i < ROUNDS; i++)
        {
            if (i == 1 || i == 2 || i == 9 || i == 16)
            {
                left = shiftBinary(left, 1);
                right = shiftBinary(right, 1);
            }
            else
            {
                left = shiftBinary(left, 2);
                right = shiftBinary(right, 2);
            }
            if (i == round)
            {
                break;
            }
        }
        return processPC2(stringToBinary(left + right));
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
                output.append(input.charAt(inputLength - tableRow[j]));
            }
        }
        return stringToBinary(output.toString());
    }
    private static byte[]       processE(byte[] bytes) throws DESAlgorithmException
    {
        int[][] table = {
            {32, 1,  2,  3,  4,  5},
            {4,  5,  6,  7,  8,  9},
            {8,  9,  10, 11, 12, 13},
            {12, 13, 14, 15, 16, 17},
            {16, 17, 18, 19, 20, 21},
            {20, 21, 22, 23, 24, 25},
            {24, 25, 26, 27, 28, 29},
            {28, 29, 30, 31, 32, 1}
        };

        if (bytes.length != 4)
        {
            throw new DESAlgorithmException("Invalid E input. Must be 32 bits long. Number of bits provided: " + (bytes.length * 8));
        }
        return permutate(bytes, table);
    }
    private static byte[]       processFP(byte[] bytes) throws DESAlgorithmException
    {
        int[][] table = {
            {40, 8, 48, 16, 56, 24, 64, 32},
            {39, 7, 47, 15, 55, 23, 63, 31},
            {38, 6, 46, 14, 54, 22, 62, 30},
            {37, 5, 45, 13, 53, 21, 61, 29},
            {36, 4, 44, 12, 52, 20, 60, 28},
            {35, 3, 43, 11, 51, 19, 59, 27},
            {34, 2, 42, 10, 50, 18, 58, 26},
            {33, 1, 41,  9, 49, 17, 57, 25}
        };

        if (bytes.length != 8)
        {
            throw new DESAlgorithmException("Invalid FP input. Must be 64 bits long. Number of bits provided: " + (bytes.length * 8));
        }
        return permutate(bytes, table);
    }
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
    private static byte[]       processP(byte[] bytes) throws DESAlgorithmException
    {
        int[][] table = {
            {16, 7,  20, 21, 29, 12, 28, 17},
            {1,  15, 23, 26, 5,  18, 31, 10},
            {2,  8,  24, 14, 32, 27, 3,  9},
            {19, 13, 30, 6,  22, 11, 4,  25}
        };

        if (bytes.length != 4)
        {
            throw new DESAlgorithmException("Invalid P input. Must be 32 bits long. Number of bits provided: " + (bytes.length * 8));
        }
        return permutate(bytes, table);
    }
    private static byte[]       processPC1(byte[] bytes) throws DESAlgorithmException
    {
        byte[]          outputBinary;
        int             i;
        int             inputLength;
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

        if (bytes.length != 8)
        {
            throw new DESAlgorithmException("Invalid PC1 input. Must be 64 bits long. Number of bits provided: " + (bytes.length * 8));
        }
        input = binaryToString(bytes);
        inputLength = input.length();
        lTableLength = lTable.length;
        lOutput = new StringBuilder();
        for (i = 0; i < lTableLength; i++)
        {
            lTableRow = lTable[i];
            lTableRowLength = lTableRow.length;
            for (j = 0; j < lTableRowLength; j++)
            {
                lOutput.append(input.charAt(inputLength - lTableRow[j]));
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
                rOutput.append(input.charAt(inputLength - rTableRow[j]));
            }
        }
        output = lOutput.toString() + rOutput.toString();
        outputList = Arrays.asList(ArrayUtils.toObject(stringToBinary(output)));
        return ArrayUtils.toPrimitive(outputList.toArray(new Byte[outputList.size()]));
    }
    private static byte[]       processPC2(byte[] bytes) throws DESAlgorithmException
    {
        int[][] table = {
            {14, 17, 11, 24, 1,  5,  3,  28},
            {15, 6,  21, 10, 23, 19, 12, 4},
            {26, 8,  16, 7,  27, 20, 13, 2},
            {41, 52, 31, 37, 47, 55, 30, 40},
            {51, 45, 33, 48, 44, 49, 39, 56},
            {34, 53, 46, 42, 50, 36, 29, 32}
        };

        if (bytes.length != 7)
        {
            throw new DESAlgorithmException("Invalid PC2 input. Must be 56 bits long. Number of bits provided: " + (bytes.length * 8));
        }
        return permutate(bytes, table);
    }
    private static String       processS1(String binaryString) throws DESAlgorithmException
    {
        int[][] table = {
            {14, 4,  13, 1,  2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0,  7},
            {0,  15, 7,  4,  14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3,  8},
            {4,  1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5,  0},
            {15, 12, 8,  2,  4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6,  13}
        };
        return substitute(binaryString, table);
    }
    private static String       processS2(String binaryString) throws DESAlgorithmException
    {
        int[][] table = {
            {15, 1,  8,  14, 6,  11, 3,  4,  9,  7,  2,  13, 12, 0,  5,  10},
            {3,  13, 4,  7,  15, 2,  8,  14, 12, 0,  1,  10, 6,  9,  11, 5},
            {0,  14, 7,  11, 10, 4,  13, 1,  5,  8,  12, 6,  9,  3,  2,  15},
            {13, 8,  10, 1,  3,  15, 4,  2,  11, 6,  7,  12, 0,  5,  14, 9}
        };
        return substitute(binaryString, table);
    }
    private static String       processS3(String binaryString) throws DESAlgorithmException
    {
        int[][] table = {
            {10, 0,  9,  14, 6,  3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8},
            {13, 7,  0,  9,  3,  4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1},
            {13, 6,  4,  9,  8,  15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7},
            {1,  10, 13, 0,  6,  9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12}
        };
        return substitute(binaryString, table);
    }
    private static String       processS4(String binaryString) throws DESAlgorithmException
    {
        int[][] table = {
            {7,  13, 14, 3,  0,  6,  9,  10, 1,  2,  8,  5,  11, 12, 4,  15},
            {13, 8,  11, 5,  6,  15, 0,  3,  4,  7,  2,  12, 1,  10, 14, 9},
            {10, 6,  9,  0,  12, 11, 7,  13, 15, 1,  3,  14, 5,  2,  8,  4},
            {3,  15, 0,  6,  10, 1,  13, 8,  9,  4,  5,  11, 12, 7,  2,  14}
        };
        return substitute(binaryString, table);
    }
    private static String       processS5(String binaryString) throws DESAlgorithmException
    {
        int[][] table = {
            {2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0,  14, 9},
            {14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9,  8,  6},
            {4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3,  0,  14},
            {11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4,  5,  3}
        };
        return substitute(binaryString, table);
    }
    private static String       processS6(String binaryString) throws DESAlgorithmException
    {
        int[][] table = {
            {12, 1,  10, 15, 9,  2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11},
            {10, 15, 4,  2,  7,  12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8},
            {9,  14, 15, 5,  2,  8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6},
            {4,  3,  2,  12, 9,  5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13}
        };
        return substitute(binaryString, table);
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
    private static String       shiftBinary(String str, int count)
    {
        return shiftBinary(str, count, true);
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
    private static String       substitute(String binaryString, int[][] table) throws DESAlgorithmException
    {
        int     binaryStringLength;
        int     col;
        int     i;
        int     j;
        int     outputLength;
        int     row;
        int     tableLength;
        int     tableRowLength;
        String  output;

        binaryStringLength = binaryString.length();
        if (binaryStringLength != 6)
        {
            throw new DESAlgorithmException("Invalid number of bits. Number of bits required: 6");
        }
        col = Integer.parseInt(binaryString.substring(1, 5), 2);
        row = Integer.parseInt("" + binaryString.charAt(0) + binaryString.charAt(5), 2);
        output = "";
        tableLength = table.length;
        outerloop:
        for (i = 0; i < tableLength; i++)
        {
            if (i == row)
            {
                tableRowLength = table[i].length;
                for (j = 0; j < tableRowLength; j++)
                {
                    if (j == col)
                    {
                        output = Integer.toBinaryString(table[i][j]);
                        break outerloop;
                    }
                }
            }
        }
        outputLength = output.length();
        while (outputLength < 4)
        {
            output = "0" + output;
            outputLength++;
        }
        return output;
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
