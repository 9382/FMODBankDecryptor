// FMOD Bank Decryptor

public class Program
{
    // Data constants
    static byte[] fourbitreverse =
    {
        0b0000, 0b1000, 0b0100, 0b1100,
        0b0010, 0b1010, 0b0110, 0b1110,
        0b0001, 0b1001, 0b0101, 0b1101,
        0b0011, 0b1011, 0b0111, 0b1111,
    };
    // this repeated type casting is stupid but that's what you get when you put a lua dev on C#
    static byte[] BankHeader = {
        (byte)'R', (byte)'I', (byte)'F', (byte)'F'
    };
    static byte[] SNDHeader = {
        0, 0, (byte)'S', (byte)'N', (byte)'D', (byte)' '
    };
    static byte[] SNDExpectedFormat =
    {
        (byte)'F', (byte)'S', (byte)'B', (byte)'5'
    };

    // Config stuff (Modified by cli args)
    static string encryptionKey = "";
    static string outputPath = "";
    static bool verbose = false;
    static bool guessingKey = false;

    // Generic helper functions
    public static void DebugLog(string text)
    {
        if (verbose) Console.WriteLine("[Verbose] " + text);
    }
    public static int? FindInArray(byte[] data, byte[] searchTerm)
    {
        if (searchTerm.Length == 0 || searchTerm.Length > data.Length) return null;
        for (int i = 0; i < data.Length - searchTerm.Length + 1; i++)
        {
            bool matches = true;
            for (int j = 0; j < searchTerm.Length; j++)
            {
                if (data[i+j] != searchTerm[j]) {
                    matches = false;
                    break;
                }
            }
            if (matches) return i;
        }
        return null;
    }

    // The code that actually works on the bank files
    public static void WriteDecryptedBankFile(string filePath, byte[] contents)
    {
        string destination = (outputPath != "") ? outputPath : Path.GetDirectoryName(filePath);
        string newFileName = destination + "\\" + Path.GetFileNameWithoutExtension(filePath) + ".decrypted.bank";
        Console.WriteLine($"Writing decrypted bank file to {newFileName}");
        File.WriteAllBytes(newFileName, contents);
    }
    public static void DecryptBankFile(string filePath)
    {
        // Get the contents
        Console.WriteLine($"Working on bank file \"{filePath}\" now...");
        byte[] fileContents;
        try
        {
            fileContents = File.ReadAllBytes(filePath);
        }
        catch (Exception exc)
        {
            Console.WriteLine($"ERROR: Unable to read \"{filePath}\": {exc.Message}");
            return;
        }
        DebugLog("File contents size: " + fileContents.Length);
        if (!fileContents.AsSpan(0, 4).SequenceEqual(BankHeader))
        {
            Console.WriteLine($"[!] Bank \"{filePath}\" does not have the expected header, ignoring...");
            return;
        }

        // Locate the SND header (the only data that gets encrypted)
        int SNDHeaderPosition = FindInArray(fileContents, SNDHeader).GetValueOrDefault(-1); // eh
        if (SNDHeaderPosition <= 0 || SNDHeaderPosition + 10 >= fileContents.Length)
        {
            Console.WriteLine($"[!] Bank \"{filePath}\" doesn't have a valid SND marker in it, so no encrypted content can be located");
            return;
        }

        // Read that size uint32
        uint SNDDataSize = (uint)(
            fileContents[SNDHeaderPosition + 6]
            + (fileContents[SNDHeaderPosition + 7] << 8)
            + (fileContents[SNDHeaderPosition + 8] << 16)
            + (fileContents[SNDHeaderPosition + 9] << 24)
        );
        uint expectedFileSize = (uint)SNDHeaderPosition + 10 + SNDDataSize;
        DebugLog("SND section size: " + SNDDataSize);
        DebugLog("Expected filesize: " + expectedFileSize);
        if (expectedFileSize != fileContents.Length)
        {
            Console.WriteLine($"[!] Bank \"{filePath}\" has an invalid SND section size (expected {SNDDataSize}, actually {fileContents.Length - 10 - SNDHeaderPosition})");
            return;
        }

        // Skip past the random whitespace padding (why)
        // NOTE: If the encryption key starts with an F, this can be wrong, but that's a rare case and I really don't care right now
        // TODO: Actually do alignment logic instead of just finding the first non-null (pretty sure it's some sort of 16 or 32byte alignment)
        uint SNDPadding = 0;
        while (fileContents[SNDHeaderPosition + 10 + SNDPadding] == 0) SNDPadding += 1;
        uint SNDDataOffset = (uint)SNDHeaderPosition + 10 + SNDPadding;
        DebugLog("Padding: " + SNDPadding);

        // Quick sanity check
        if (fileContents.AsSpan((int)SNDDataOffset, 4).SequenceEqual(SNDExpectedFormat))
        {
            Console.WriteLine($"WARNING: Bank \"{filePath}\" does not appear to be encrypted. Decryption will still occur, but expect strange results");
        }

        // Now it's decrypting time
        /* The encryption process:
         * For each byte X in the data,
         *   XOR it with index (i % len(s)) of encryption string s...
         *   ...And then swap the first 4 and last 4 bits and reverse both 4 bit groups
         */
        // The encryption key won't begin rotating until after the padding, so we don't need to do any special handling there (thanks --guess)
        if (guessingKey)
        {
            // Normally starts "FSB5" (and honestly there could be even more beyond that but im not sure how consistent it is), so abuse that
            int guessLength = SNDExpectedFormat.Length;
            char[] guessedKey = new char[guessLength];
            for (int i = 0; i < guessLength; i++)
            {
                byte b = fileContents[SNDDataOffset + i];
                byte reversed = (byte)(fourbitreverse[b >> 4] | ((fourbitreverse[b % 16]) << 4));
                guessedKey[i] = (char)(reversed ^ SNDExpectedFormat[i]);
            }
            Console.WriteLine($"Predicted encryption key start: {new string(guessedKey)}");
        }
        else
        {
            // Modify it in-place since it's the simplest way
            for (int i = 0; i < SNDDataSize - SNDPadding; i++)
            {
                byte b = fileContents[SNDDataOffset + i];
                byte reversed = (byte)(fourbitreverse[b >> 4] | ((fourbitreverse[b % 16]) << 4));
                fileContents[SNDDataOffset + i] = (byte)(reversed ^ encryptionKey[i % encryptionKey.Length]);
            }
            if (!fileContents.AsSpan((int)SNDDataOffset, 4).SequenceEqual(SNDExpectedFormat))
            {
                Console.WriteLine($"WARNING: Bank \"{filePath}\" appears to have not decrypted correctly - double-check the output");
            }
            WriteDecryptedBankFile(filePath, fileContents);
        }
    }
    public static void CheckPathForBanks(string path)
    {
        if (File.Exists(path)) DecryptBankFile(path);
        else if (Directory.Exists(path))
        {
            foreach (string file in Directory.GetFiles(path))
            {
                if (file.EndsWith(".bank") && !file.EndsWith(".decrypted.bank")) DecryptBankFile(file);
            }
        }
        else Console.WriteLine($"[!] Path \"{path}\" doesn't exist");
    }
    public static void Main(string[] args)
    {
        List<string> bankLocationList = new List<string>();
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (arg == "--key")
            {
                if (args.Length > i + 1)
                {
                    encryptionKey = args[i + 1];
                    i++;
                }
                else
                {
                    Console.WriteLine("No key provided in --key");
                    return;
                }
            }
            else if (arg == "--output-folder")
            {
                if (args.Length > i + 1) {
                    outputPath = args[i + 1];
                    i++;
                }
                else
                {
                    Console.WriteLine("No output path provided in --output");
                    return;
                }
            }
            else if (arg == "--verbose")
            {
                verbose = true;
                Console.WriteLine("Verbose enabled");
            }
            else if (arg == "--guess")
            {
                guessingKey = true;
            }
            else if (arg == "--help" || arg == "-h" || arg == "-?")
            {
                Console.WriteLine("usage: FMODBankDecryptor [--key key] [--output-folder folder] [--guess] [--verbose] bank_paths");
                Console.WriteLine("If no output folder is specified, decrypted banks will be placed in the same folder as their encrypted version");
                Console.WriteLine("\"--guess\" will make the program solve what the encryption key likely starts with. No decryption files will be made");
                return;
            }
            else if (arg.StartsWith("-"))
            {
                Console.WriteLine($"Unrecognised argument \"{args[i]}\"");
                Console.WriteLine("Use --help for usage instructions");
                return;
            }
            else
            {
                bankLocationList.Add(arg);
            }
        }

        string[] bankLocations = bankLocationList.ToArray();
        if (bankLocations.Length == 0)
        {
            Console.WriteLine("[!] No bank locations provided");
            return;
        }
        if (!guessingKey && encryptionKey == "")
        {
            Console.WriteLine("[!] An encryption key must be specified when not guessing");
            return;
        }
        if (outputPath != "" && !Directory.Exists(outputPath))
        {
            DebugLog("Making output directory since it doesn't exist");
            Directory.CreateDirectory(outputPath);
        }

        DebugLog($"Looking at {bankLocations.Length} potential bank(s) from cli args");
        foreach (string location in bankLocations)
        {
            CheckPathForBanks(location);
        }
    }
}