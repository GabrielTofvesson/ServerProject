using System;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Tofvesson.Crypto;

namespace Client
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Write("Enter your personal password: ");
            string key = ReadLineHidden();

            Console.WriteLine("Generating authentication code...");

            // Generate a password-based Message Authentication Code (with salt to prevent rainbowtables) to verify the user identity against the server
            // This string will be used as our database key: a (pseudo-)unique identifier which, for all intents and purposes, can be as public as we like since it doesn't do an attacker any good to know it
            string auth = Support.ToHexString(KDF.PBKDF2(KDF.HMAC_SHA1, key.ToUTF8Bytes(), "NoRainbow".ToUTF8Bytes(), 8192, 128));

            // Create private encryption/decryption algorithm for processing private (encrypted) data stored on server
            Rijndael128 privCrypt = new Rijndael128(key);
            RandomProvider provider = new CryptoRandomProvider();

            bool connected = false;
            bool load = false;
            // AES key used for communication is randomly chosen by generating anywhere between 1 and 511 random bytes as the password for PBKDF2-HMAC-SHA1
            NetClient client = new NetClient(new Rijndael128(provider.GetBytes(provider.NextInt(511)+1).ToUTF8String()), ParseIP(), ParsePort(), (string message, out bool keepAlive) =>
            {
                if (message.StartsWith("M-"))
                {
                    // Handle a blank response
                    if (message.Length == 2) Console.WriteLine("No messages exist with your password");
                    else
                    {
                        string[] msgs = null;
                        try
                        {
                            msgs = Support.DeserializeString(message.Substring(2));
                        }
                        catch (Exception) { Console.WriteLine("The server seems to have sent an incorrect message. The stored messages could not be read!"); }

                        foreach(var cmsg in msgs)
                            try
                            {
                                // Decrypt each message with the supplied decryptor
                                byte[] messages_pad = privCrypt.Decrypt(Convert.FromBase64String(cmsg));
                                int len = Support.ReadInt(messages_pad, 0);
                                string messages = messages_pad.SubArray(4, len + 4).ToUTF8String();
                                Console.WriteLine(messages);
                            }
                            catch (Exception) { /* Ignore corrupt message (maybe do something else here?) */ }
                        

                        Console.WriteLine("\nPress any key to continue...");
                        Console.ReadKey();
                        Console.Clear();
                    }
                    load = false;
                }

                // Tell the client object to keep the connection alive
                keepAlive = true;

                // Don't respond
                return null;
            }, cli =>
            {
                Console.WriteLine("Connected to server!");
                connected = true;
            });

            // Server-connection-attempt loop (mostly just UI/UX stuff)
            do
            {
                try
                {
                    Console.WriteLine("Connecting to server...");
                    client.Connect(); // <----- Only important line in this entire loop
                    break;
                }
                catch (Exception)
                {
                    Console.Write("The server rejected the connection (probably because the server isn't running). Try again? (Y/n): ");
                    if (Console.In.ReadYNBool("n"))
                    {
                        Console.WriteLine("OK. Exiting...");
                        Thread.Sleep(2500);
                        Environment.Exit(0);
                    }
                    Console.Clear();
                }
            } while (true);

            while (!connected) Thread.Sleep(125);

            Console.WriteLine();

            bool alive = true;
            while(alive)
                // Show selection menu
                switch (DoSelect())
                {
                    case 1:
                        {
                            // Get and send a message to the server
                            Console.Clear();
                            Console.Write("Message to send to server: ");
                            string message = Console.ReadLine();
                            if (message.Length == 0) message = "\0"; // Blank messages are parsed as a null byte

                            // Encrypt the message with our personal AES object (which hopefully only we know)
                            byte[] toSend = privCrypt.Encrypt(NetSupport.WithHeader(message.ToUTF8Bytes()));

                            // Send to the server
                            if (!client.TrySend("S-"+auth+"-"+Convert.ToBase64String(toSend))) Console.WriteLine("Unfortunately, an error ocurred when attempting to send your message to the server :(");
                            break;
                        }

                    case 2:
                        {
                            // Send a request to the server for a list of all messages associated with the hex key we generated in the beginning
                            Console.Clear();
                            Console.WriteLine("Loading messages...");

                            // Send the "Load" command along with our db key
                            if (!client.TrySend("L-" + auth)) Console.WriteLine("Unfortunately, an error ocurred when attempting to send your message to the server :(");
                            load = true;
                            while (load) Thread.Sleep(125);
                            break;
                        }
                    case 3:
                        Console.WriteLine("Exiting...");

                        // Await client disconnection
                        try { client.Disconnect(); }
                        catch (Exception) { }

                        // Stop program
                        Environment.Exit(0);
                        break;
                }

            while (client.IsAlive) Thread.Sleep(250);
        }

        /// <summary>
        /// Show action selection menu
        /// </summary>
        /// <returns>The selection</returns>
        static int DoSelect()
        {
            int read = -1;
            Console.WriteLine("What would you like to do?\n1: Store a message on the server\n2: Show all messages\n3: Exit");
            do
            {
                Console.Write("Selection: ");
                int.TryParse(Console.ReadLine(), out read);
            } while (read < 1 && read < 4);
            return read;
            
        }

        /// <summary>
        /// Read an ip from the standard input stream
        /// </summary>
        /// <returns>A parsed IP</returns>
        public static IPAddress ParseIP()
        {
            IPAddress addr = IPAddress.None;
            do
            {
                Console.Write("Enter server IP: ");
            } while (!IPAddress.TryParse(Console.ReadLine(), out addr));
            return addr;
        }

        /// <summary>
        /// Read a port number from the standard input stream
        /// </summary>
        /// <returns>Internet protocol port number</returns>
        public static short ParsePort()
        {
            short s;
            do
            {
                Console.Write("Enter server port: ");
            } while (!short.TryParse(Console.ReadLine(), out s));
            return s;
        }

        /// <summary>
        /// Read a single keystroke from the keyboard and cover it up so that shoulder-surfers don't collect sensitive information
        /// </summary>
        /// <param name="backMax">Backspace tracking</param>
        /// <returns>The typed character</returns>
        static char ReadKeyHidden(ref int backMax)
        {
            char c = Console.ReadKey().KeyChar;
            if (c != '\b')
            {
                if (c != '\n' && c!='\r')
                {
                    ++backMax;
                    Console.CursorLeft -= 1;
                    Console.Write('*');
                }
            }
            else if (backMax > 0)
            {
                --backMax;
                Console.Write(' ');
                Console.CursorLeft -= 1;
            }
            else Console.CursorLeft += 1;
            return c;
        }

        // Same as above but for a whole line :)
        static string ReadLineHidden()
        {
            StringBuilder builder = new StringBuilder();
            char read;
            int backMax = 0;
            while ((read = ReadKeyHidden(ref backMax)) != '\r')
                if (read == '\b' && builder.Length > 0) builder.Remove(builder.Length - 1, 1);
                else if(read!='\b') builder.Append(read);
            Console.Clear();
            return builder.ToString();
        }
    }
}
