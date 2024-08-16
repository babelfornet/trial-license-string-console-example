using System;
using System.Reflection;
using System.Runtime.Versioning;
using Babel.Licensing;

using Newtonsoft.Json;

class Program
{
    /// <summary>
    /// Public key used to validate the license signature.
    /// </summary>
    static void Main(string[] args)
    {
        var program = new Program();

        try
        {
            program.Run();            
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }

        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
    }

    private void Run()
    {
        while (true)
        {
            Console.WriteLine("Choose an option:");

            Console.WriteLine("1. Create serial");
            Console.WriteLine("2. Validate serial");
            Console.WriteLine("3. Execute encrypted code");
            Console.WriteLine("4. Delete serial");
            Console.WriteLine("5. Exit");
            Console.Write("Enter your choice: ");

            string choice = Console.ReadLine();

            switch (choice)
            {
                case "1":
                    Try(() => CreateSerial());
                    break;
                case "2":
                    Try(() => ValidateSerial());
                    break;
                case "3":
                    Try(() => ExecuteEncryptedCode());
                    break;
                case "4":
                    Try(() => DeleteSerial());
                    break;
                case "5":
                    return;
                default:
                    Console.WriteLine("Invalid choice. Please try again.");
                    break;
            }

            Console.WriteLine();
        }
    }

    private void Try(Action action)
    {
        try
        {
            action();
        }
        catch (Exception ex)
        {
            Console.WriteLine("Exception {0} thrown: {1}", ex, ex.Message);            
        }
    }

    [Obfuscation(Feature = "msil encryption:source=source1;password=p@ssw0rd1;internal=true", Exclude = false)]
    private void ExecuteEncryptedCode()
    {
        Console.WriteLine("Encrypted code running");
    }

    [Obfuscation(Feature = "msil encryption", Exclude = false)]
    internal void CreateSerial()
    {
        if (!File.Exists("Keys.pem"))
        {
            // Create a new key pair and save it to a file
            var rsa = new RSASignature();
            rsa.CreateKeyPair();
            rsa.WritePem("Keys.pem", false);
        }

        // Note that this is only an example.
        // The key file should not be deployed with the application.
        // The key file should be kept in a safe place and used only to sign the serial.
        string hardwareKey = HardwareId.Create().ToMachineKey();

        var sign = (RSASignature)Pem.ReadSignature("Keys.pem");

        var lic = new StringLicense()       // Create a new string license
            .ForAssembly(Assembly.GetExecutingAssembly()) // The license is for this assembly
            .WithUniqueId()                 // Unique ID for the license
            .WithHardwareKey(hardwareKey)   // Lock to the current machine
            .WithTrialDays(2)               // Give 2 days trial
            .WithMaximumRunCount(3)         // Allow 3 runs
            .WithField("source1", "p@ssw0rd1".Encrypt("!sEcr3tp@sswOrD!"))  // Set the encrypted code password            
            .SignWith(sign);                // Sign the license with the private key

        // Convert the license object to an ASCII string
        string serial = lic.ToReadableString("ASCII");

        // Save the current license information to a specified file path        
        var store = new LicenseStore(serial, sign.ExportKeys(true).Encrypt("pk_p@sswOrd"));
        store.Save();

        Console.WriteLine("Serial created:");
        Console.WriteLine(serial);
    }

    public void ValidateSerial()
    {
        var store = new LicenseStore();
        store.Load();
        if (store.Serial == null)
        {
            Console.WriteLine("No serial found");
            return;
        }

        // Get the public key from the key to validate the license signature
        string publicKey = Convert.ToString(store.Key).Decrypt("pk_p@sswOrd");

        var manager = new StringLicenseManager();

        // The public key is used to validate the license signature
        manager.SignatureProvider = RSASignature.FromKeys(publicKey);

        // Validate the serial
        // A license object is returned if the serial is valid and all license restrictions are met
        Babel.Licensing.ILicense license = manager.Validate(store.Serial);

        Console.WriteLine("Serial {0} is valid", license.Id);
        var trial = license.Restrictions.OfType<TrialRestriction>().FirstOrDefault();

        if (trial != null)
        {
            Console.WriteLine("Trial time left: {0}", trial.TimeLeft);
            Console.WriteLine("Runs left: {0}", trial.RunCountLeft);
        }
    }
    
    private void DeleteSerial()
    {
        new LicenseStore().Delete();
        Console.WriteLine("Serial deleted");
    }
    
    [Obfuscation(Feature = "msil encryption get password", Exclude = false)]
    internal static string GetEncryptedCodePassword(string source)
    {
        return EncryptedGetEncryptedCodePassword(source);
    }

    [Obfuscation(Feature = "msil encryption", Exclude = false)]
    private static string EncryptedGetEncryptedCodePassword(string source)
    {
        var store = new LicenseStore();
        store.Load();

        if (store.Serial == null)
        {
            throw new Exception("No serial found");
        }

        // Get the public key from the key to validate the license signature
        string publicKey = Convert.ToString(store.Key).Decrypt("pk_p@sswOrd");

        var manager = new StringLicenseManager();

        // The public key is used to validate the license signature
        manager.SignatureProvider = RSASignature.FromKeys(publicKey);

        // Validate the serial
        // A license object is returned if the serial is valid and all license restrictions are met
        Babel.Licensing.ILicense license = manager.Validate(store.Serial);

        // Reuse the same secret used to decrypt the code password
        return license.Fields.First(item => item.Name == source).Value.Decrypt("!sEcr3tp@sswOrD!");
    }
}

class LicenseStore {
    public string Serial { get; set; }
    public string Key { get; set; }

    public LicenseStore() {
    }

    public LicenseStore(string serial, string key) {
        Serial = serial;
        Key = key;
    }

    public void Save() {
        File.WriteAllText("license.json", JsonConvert.SerializeObject(this));
    }

    public void Load() {
        try {
            var store = JsonConvert.DeserializeObject<LicenseStore>(File.ReadAllText("license.json"));
            Serial = store.Serial;
            Key = store.Key;
        } catch {
            Serial = null;
            Key = null;
        }
    }

    public void Delete() {
        try {
            File.Delete("license.json");
        } catch { }
    }
}