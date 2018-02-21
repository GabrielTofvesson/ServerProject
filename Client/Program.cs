using System;
using System.Net;
using System.Text;
using Tofvesson.Crypto;

namespace Client
{
    class Program
    {
        static void Main(string[] args)
        {
            Rijndael128 symcrypt = new Rijndael128("Eyy");
            byte[] testMSG = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
            string cryptres = symcrypt.DecryptString(symcrypt.EncryptString("Hello!"), 6);

            RandomProvider provider = new CryptoRandomProvider();
            byte[] test = KDF.PBKDF2(KDF.HMAC_SHA1, Encoding.UTF8.GetBytes("Hello there!"), new byte[] { 1, 2, 3, 4 }, 4096, 128);
            Console.WriteLine(Support.ToHexString(test));
            Galois2 gal = Galois2.FromValue(33);
            Console.WriteLine(gal.ToString());
            Console.WriteLine(gal.InvMul().Multiply(gal).ToString());

            bool connected = false;

            AES symCrypto = LoadAES();
            if (symCrypto == null)
            {
                Console.Write("Enter AES password: ");
                symCrypto = new AES(Console.ReadLine());
                Console.Write("Would you like to save the generated AES keys? (y/N): ");
                if (Console.In.ReadYNBool("y"))
                {
                    Console.Write("Enter the base file name to be used: ");
                    try
                    {
                        symCrypto.Save(Console.ReadLine(), true);
                    }
                    catch (Exception) { Console.WriteLine("An error ocurred while attempting to save keys!"); }
                }
            }

            NetClient client = new NetClient(symCrypto, ParseIP(), ParsePort(), (string message, out bool keepAlive) =>
            {
                Console.Write("Got message: "+message+"\nResponse (blank to exit): ");
                string response = Console.ReadLine();
                keepAlive = response.Length!=0;
                return keepAlive?response:null;
            }, cli =>
            {
                Console.WriteLine("Connected to server!");
                connected = true;
            });
            client.Connect();

            Console.WriteLine("Connecting...");
            while (!connected) System.Threading.Thread.Sleep(125);

            Console.Write("Message to send to server: ");
            string s = Console.ReadLine();
            if (s.Length == 0) s += '\0';
            client.Send(s);

            while (client.IsAlive) System.Threading.Thread.Sleep(250);
        }

        public static IPAddress ParseIP()
        {
            IPAddress addr = IPAddress.None;
            do
            {
                Console.Write("Enter server IP: ");
            } while (!IPAddress.TryParse(Console.ReadLine(), out addr));
            return addr;
        }

        public static short ParsePort()
        {
            short s;
            do
            {
                Console.Write("Enter server port: ");
            } while (!short.TryParse(Console.ReadLine(), out s));
            return s;
        }


        
        static AES LoadAES()
        {
            AES sym = null;
            Console.Write("Would you like to load AES keys from files? (y/N): ");
            while (Console.In.ReadYNBool("y"))
            {
                try
                {
                    Console.Write("Enter base file name: ");
                    sym = AES.Load(Console.ReadLine());
                    Console.WriteLine("Sucessfully loaded keys!");
                    break;
                }
                catch (Exception)
                {
                    Console.Write("One or more of the required key files could not be located. Would you like to retry? (y/N): ");
                }
            }
            return sym;
        }
    }
}
