using System;
using System.IO;

public static class ChurroE2E
{
    public static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            WriteMarker(".managed-exe", "managed executable entry");
            return;
        }
        if (args.Length == 2 && args[0] == "quoted value" && args[1] == "tail")
        {
            WriteMarker(".managed-exe-args", "managed executable quoted arguments");
            return;
        }
        throw new ArgumentException("unexpected managed executable arguments");
    }

    public static void Run()
    {
        WriteMarker(".managed-dll", "managed static method");
    }

    public static void RunArgs(string first, string second)
    {
        if (first != "quoted value" || second != "tail")
            throw new ArgumentException("unexpected managed library arguments");
        WriteMarker(".managed-dll-args", "managed static method quoted arguments");
    }

    private static void WriteMarker(string suffix, string value)
    {
        string prefix = Environment.GetEnvironmentVariable("CHURRO_E2E_PREFIX");
        if (String.IsNullOrEmpty(prefix))
            throw new InvalidOperationException("CHURRO_E2E_PREFIX is empty");
        File.WriteAllText(prefix + suffix, value);
    }
}
