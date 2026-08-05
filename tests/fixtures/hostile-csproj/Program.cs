using System;

public static class Hostile
{
    public static int Token()
    {
        var rng = new Random();      // SCS0005: weak random for a token
        return rng.Next();
    }
}
