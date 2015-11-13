import etna.crypt.algorithms.*;

class Main
{
    public static void main(String[] args)
    {
        try
        {
            System.out.println("Hello World! My name is Said AHEMT"); // Display the string
            DESAlgorithm.DESencrypt(" A  Z", "hello wd");
        }
        catch (DESAlgorithmException e)
        {
            System.err.println(e.getMessage());
        }
    }
}
