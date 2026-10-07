using System;
using System.IO;

public static class ChurroE2E
{
    public static void Main()
    {
        WriteMarker(".managed-exe", "managed executable entry");
    }

    public static void Run()
    {
        WriteMarker(".managed-dll", "managed static method");
    }

    private static void WriteMarker(string suffix, string value)
    {
        string prefix = Environment.GetEnvironmentVariable("CHURRO_E2E_PREFIX");
        if (String.IsNullOrEmpty(prefix))
            throw new InvalidOperationException("CHURRO_E2E_PREFIX is empty");
        File.WriteAllText(prefix + suffix, value);
    }
}
