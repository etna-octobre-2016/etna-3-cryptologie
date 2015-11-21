package etna.crypt.algorithms;

import java.lang.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;

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
        int     i;
        int     leftBlockInt;
        int     rightBlockInt;
        byte[]  feistelResult;
        byte[]  ipResult;
        byte[]  leftBlock;
        byte[]  rightBlock;
        byte[]  roundKey;
        byte[]  tmp;

        // Expands message to 64 bits
        message = padBinary(message, VALID_MESSAGE_NUMBER_OF_BYTES);

        // Initial Permutation
        ipResult = processIP(message);

        // Left / right split
        leftBlock = Arrays.copyOfRange(ipResult, 0, 4);
        rightBlock = Arrays.copyOfRange(ipResult, 4, 8);

        // Rounds loop
        for (i = 16; i > 0; i--)
        {
            // Round key generation
            roundKey = KeySchedule(key, i);

            // Feistel
            feistelResult = processFeistel(rightBlock, roundKey);

            // XOR
            leftBlockInt = binaryToInt(leftBlock);
            rightBlockInt = binaryToInt(feistelResult);
            leftBlockInt = leftBlockInt ^ rightBlockInt;

            // Swao
            leftBlock = rightBlock;
            rightBlock = intToBinary(leftBlockInt);
        }

        // Last swap before final permutation
        tmp = leftBlock;
        leftBlock = rightBlock;
        rightBlock = tmp;

        // Final permutation
        return processFP(ArrayUtils.addAll(leftBlock, rightBlock));
    }
    public static byte[]        DESencrypt(byte[] message, byte[] key) throws DESAlgorithmException
    {
        int     i;
        int     leftBlockInt;
        int     rightBlockInt;
        byte[]  feistelResult;
        byte[]  ipResult;
        byte[]  leftBlock;
        byte[]  rightBlock;
        byte[]  roundKey;
        byte[]  tmp;

        // Expands message to 64 bits
        message = padBinary(message, VALID_MESSAGE_NUMBER_OF_BYTES);

        // Initial Permutation
        ipResult = processIP(message);

        // Left / right split
        leftBlock = Arrays.copyOfRange(ipResult, 0, 4);
        rightBlock = Arrays.copyOfRange(ipResult, 4, 8);

        // Rounds loop
        for (i = 1; i < 17; i++)
        {
            // Round key generation
            roundKey = KeySchedule(key, i);

            // Feistel
            feistelResult = processFeistel(rightBlock, roundKey);

            // XOR
            leftBlockInt = binaryToInt(leftBlock);
            rightBlockInt = binaryToInt(feistelResult);
            leftBlockInt = leftBlockInt ^ rightBlockInt;

            // Swao
            leftBlock = rightBlock;
            rightBlock = intToBinary(leftBlockInt);
        }

        // Last swap before final permutation
        tmp = leftBlock;
        leftBlock = rightBlock;
        rightBlock = tmp;

        // Final permutation
        return processFP(ArrayUtils.addAll(leftBlock, rightBlock));
    }
    public static byte[]        KeySchedule(byte[] key, Integer round) throws DESAlgorithmException
    {
        int     i;
        String  keyString;
        String  left;
        String  right;

        if (round < 1 || round > 16)
        {
            throw new DESAlgorithmException("not valid round number " + round);
        }
        key = processPC1(key);
        keyString = binaryToString(key);
        left = keyString.substring(0, 28);
        right = keyString.substring(28);
        for (i = 1; i < 17; i++)
        {
            if (i == 1 || i == 2 || i == 9 || i == 16)
            {
                left = shift(left, 1);
                right = shift(right, 1);
            }
            else
            {
                left = shift(left, 2);
                right = shift(right, 2);
            }
            if (i == round)
            {
                break;
            }
        }
        return processPC2(padBinary(stringToBinary(left + right), 7));
    }


    ///////////////////////////////////////////////////////////////////////////
    // DES FUNCTIONS
    ///////////////////////////////////////////////////////////////////////////

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
        return padBinary(permutate(bytes, table), 6);
    }
    private static byte[]       processFeistel(byte[] halfBlockBytes, byte[] subKeyBytes) throws DESAlgorithmException
    {
        byte[]          sOutput;
        int             i;
        int             sBlocksSize;
        int             subKeyParts;
        int             subKeyPartLength;
        int             subKeyPartOutputLength;
        long            halfBlock;
        long            subKey;
        long            xorResult;
        List<String>    sBlocks;
        String          xorResultString;

        subKeyParts = 8;
        subKeyPartLength = 6;
        subKeyPartOutputLength = 4;
        halfBlockBytes = padBinary(processE(halfBlockBytes), subKeyParts);
        halfBlock = binaryToLong(halfBlockBytes);
        subKey = binaryToLong(subKeyBytes);
        xorResult = halfBlock ^ subKey;
        xorResultString = Long.toUnsignedString(xorResult, 2);
        xorResultString = StringUtils.leftPad(xorResultString, (subKeyParts * subKeyPartLength), "0");
        sBlocks = splitString(xorResultString, subKeyPartLength);
        sBlocksSize = sBlocks.size();
        for (i = 0; i < sBlocksSize; i++)
        {
            sBlocks.set(i, processS(sBlocks.get(i), (i + 1)));
        }
        sOutput = padBinary(stringToBinary(String.join("", sBlocks)), subKeyPartOutputLength);
        return processP(sOutput);
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
        int[][] lTable = {
            {57, 49, 41, 33, 25, 17, 9},
            {1,  58, 50, 42, 34, 26, 18},
            {10, 2,  59, 51, 43, 35, 27},
            {19, 11, 3,  60, 52, 44, 36}
        };
        int[][] rTable = {
            {63, 55, 47, 39, 31, 23, 15},
            {7,  62, 54, 46, 38, 30, 22},
            {14, 6,  61, 53, 45, 37, 29},
            {21, 13, 5,  28, 20, 12, 4}
        };

        if (bytes.length != 8)
        {
            throw new DESAlgorithmException("Invalid PC1 input. Must be 64 bits long. Number of bits provided: " + (bytes.length * 8));
        }
        return stringToBinary(permutateToString(bytes, lTable) + permutateToString(bytes, rTable));
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
    private static String       processS(String binaryString, int sBoxID) throws DESAlgorithmException
    {
        switch (sBoxID)
        {
            case 1:
                return processS1(binaryString);
            case 2:
                return processS2(binaryString);
            case 3:
                return processS3(binaryString);
            case 4:
                return processS4(binaryString);
            case 5:
                return processS5(binaryString);
            case 6:
                return processS6(binaryString);
            case 7:
                return processS7(binaryString);
            case 8:
                return processS8(binaryString);
            default:
                throw new DESAlgorithmException("unexpected sBoxID '" + sBoxID + "'");
        }
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
    private static String       processS7(String binaryString) throws DESAlgorithmException
    {
        int[][] table = {
            {4,  11, 2,  14, 15, 0,  8,  13, 3,  12, 9,  7,  5,  10, 6,  1},
            {13, 0,  11, 7,  4,  9,  1,  10, 14, 3,  5,  12, 2,  15, 8,  6},
            {1,  4,  11, 13, 12, 3,  7,  14, 10, 15, 6,  8,  0,  5,  9,  2},
            {6,  11, 13, 8,  1,  4,  10, 7,  9,  5,  0,  15, 14, 2,  3,  12}
        };
        return substitute(binaryString, table);
    }
    private static String       processS8(String binaryString) throws DESAlgorithmException
    {
        int[][] table = {
            {13, 2,  8,  4,  6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7},
            {1,  15, 13, 8,  10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2},
            {7,  11, 4,  1,  9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8},
            {2,  1,  14, 7,  4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11}
        };
        return substitute(binaryString, table);
    }

    ///////////////////////////////////////////////////////////////////////////
    // UTILITY METHODS
    ///////////////////////////////////////////////////////////////////////////

    private static int          binaryToInt(byte[] bytes)
    {
        return Integer.parseUnsignedInt(binaryToString(bytes), 2);
    }
    private static long         binaryToLong(byte[] bytes)
    {
        return Long.parseUnsignedLong(binaryToString(bytes), 2);
    }
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
    private static byte[]       intToBinary(int number)
    {
        return ByteBuffer.allocate(4).putInt(number).array();
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
    private static String       permutateToString(byte[] bytes, int[][] table)
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
        return output.toString();
    }
    private static byte[]       permutate(byte[] bytes, int[][] table)
    {
        return stringToBinary(permutateToString(bytes, table));
    }
    private static String       shift(String str, int count, boolean isCircular)
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
    private static String       shift(String str, int count)
    {
        return shift(str, count, true);
    }
    private static List<String> splitString(String string, int partitionSize)
    {
        int             i;
        int             length;
        List<String>    parts;

        parts = new ArrayList<String>();
        length = string.length();
        for (i = 0; i < length; i += partitionSize)
        {
            parts.add(string.substring(i, Math.min(length, i + partitionSize)));
        }
        return parts;
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
}
