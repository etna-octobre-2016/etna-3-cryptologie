package etna.crypt.algorithms;

import java.lang.Exception;
import java.lang.Throwable;

public class DESAlgorithmException extends Exception
{
    public DESAlgorithmException(String message)
    {
        super(message);
    }
    public DESAlgorithmException(String message, Throwable e)
    {
        super(message, e);
    }
}
