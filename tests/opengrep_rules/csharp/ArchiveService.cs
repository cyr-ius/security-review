// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

public class ArchiveService
{
    private readonly Random _random = new Random();

    public string Tokens()
    {
        // ruleid: secreview.csharp.insecure-random-for-secret
        var resetToken = _random.Next().ToString("x");
        // ruleid: secreview.csharp.insecure-random-for-secret
        string apiKey = Convert.ToHexString(BitConverter.GetBytes(Random.Shared.NextInt64()));
        // ok: secreview.csharp.insecure-random-for-secret
        var sessionId = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        // ok: secreview.csharp.insecure-random-for-secret
        var jitter = _random.Next(100);
        return resetToken + apiKey + sessionId + jitter;
    }

    public void Extract(ZipArchive archive, string destination)
    {
        foreach (var entry in archive.Entries)
        {
            // ruleid: secreview.csharp.zip-slip
            entry.ExtractToFile(Path.Combine(destination, entry.FullName), true);
        }
    }

    public void ExtractChecked(ZipArchive archive, string destination)
    {
        var root = Path.GetFullPath(destination) + Path.DirectorySeparatorChar;
        foreach (var entry in archive.Entries)
        {
            // ok: secreview.csharp.zip-slip
            var target = Path.GetFullPath(Path.Combine(root, entry.FullName));
            if (!target.StartsWith(root, StringComparison.Ordinal))
            {
                throw new IOException("Entry outside the target directory");
            }
            entry.ExtractToFile(target, true);
        }
    }
}
