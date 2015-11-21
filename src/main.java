import etna.crypt.algorithms.*;

class Main
{
    public static void main(String[] args)
    {
        try
        {
            System.out.println("Hello World! My name is Said AHEMT"); // Display the string

            System.out.println("cypher: " + DESAlgorithm.DESencrypt("ABCDEFGH", "12345678"));
        }
        catch (DESAlgorithmException e)
        {
            System.err.println(e.getMessage());
        }
    }
}
