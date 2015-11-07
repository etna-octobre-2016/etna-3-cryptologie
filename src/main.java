import etna.crypt.algorithms.*;

class Main
{
    public static void main(String[] args)
    {
        try
        {
            System.out.println("Hello World! My name is Said AHEMT"); // Display the string
            DESAlgorithm.DESencrypt("hello wo", "hello wd");
        }
        catch (DESAlgorithmException e)
        {
            System.err.println(e.getMessage());
        }
    }
}

//
// The converted string is:
//
// 68 65 6C 6C 6F 20 77 6F 72 6C 64
// 68 65 6c 6c 6f 20 77 6f
