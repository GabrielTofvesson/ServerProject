using Tofvesson.Crypto;
using System;
using System.Xml;
using System.Collections.Generic;

namespace Server
{
    class Program
    {
        // Constants used for the server (duh)
        private const string db = "db.xml";
        private const short port = 1337;


        static void Main(string[] args)
        {
            bool verbose = true;

            // Prepare crypto
            RandomProvider provider = new RegularRandomProvider();
            RSA func = LoadRSA(provider);
            if (func == null) func = GenerateRSA();

            Console.WriteLine("Server starting!\nType \"help\" for a list of serverside commands");

            XmlDocument doc = new XmlDocument();
            try { doc.Load(db); } // Attempt to load the xml document
            catch (Exception)
            {
                // If the xml-document doesn't exist, start building one
                XmlDeclaration declaration = doc.CreateXmlDeclaration("1.0", "utf-8", null);
                doc.AppendChild(declaration);
            }
            

            // Create a server with the given RSA function
            NetServer server = new NetServer(func, port, (string message, out bool keepAlive) =>
            {
                if(verbose) Console.WriteLine("Got message from client: " + message);
                keepAlive = true;

                // Check if the message sent was a "Store" command
                if (message.StartsWith("S-") && message.Substring(2).Contains("-"))
                {
                    // Split up the message into its relevant parts: Sender and Message
                    string data = message.Substring(2);
                    string auth = data.Substring(0, data.IndexOf('-'));
                    string msg = data.Substring(data.IndexOf('-') + 1);

                    // Look up some stuff
                    XmlNodeList lst_u = doc.SelectNodes("users");
                    XmlElement users;
                    if (lst_u.Count == 0)
                    {
                        users = doc.CreateElement("users");
                        doc.AppendChild(users);
                    }
                    else users = (XmlElement) lst_u.Item(0);

                    XmlElement userSet = null;
                    foreach (var child in users.ChildNodes)
                        if (child is XmlElement && ((XmlElement)child).Name.Equals("U"+auth))
                        {
                            userSet = (XmlElement) child;
                            break;
                        }

                    // If a node doesn't exist for the user, create it
                    if (userSet == null)
                    {
                        userSet = doc.CreateElement("U"+auth);
                        users.AppendChild(userSet);
                    }
                    
                    // Store the message and save
                    XmlElement messageNode = doc.CreateElement("msg");
                    messageNode.InnerText = msg;
                    userSet.AppendChild(messageNode);

                    if (verbose) Console.WriteLine("Saving document...");
                    doc.Save(db);
                }
                // Check if the message was a "Load" command
                else if (message.StartsWith("L-"))
                {
                    // Get the authentication code
                    string auth = message.Substring(2);

                    // Load some xml stuff
                    XmlNode users = doc.SelectSingleNode("users");

                    XmlNodeList elements = null;
                    foreach(var user in users.ChildNodes)
                        if(user is XmlElement && ((XmlElement) user).Name.Equals("U"+auth))
                        {
                            elements = ((XmlElement) user).ChildNodes;
                            break;
                        }

                    // There are no stored messages for the given auth. code: respond with a blank message
                    if (elements == null) return "M-";

                    if (elements.Count != 0)
                    {
                        List<string> collect = new List<string>();
                        foreach(var element in elements)
                            if (element is XmlElement)
                                collect.Add(((XmlElement)element).InnerText);

                        // Respond with all the elements (conveniently serialized)
                        return "M-"+Support.SerializeStrings(collect.ToArray());
                    }
                }

                // No response
                return null;
            },
            client =>
            {
                // Notify the console of the new client
                if (verbose) Console.WriteLine($"Client has connected: {client.ToString()}");
            });
            server.StartListening();

            // Server terminal command loop
            while (server.Running)
            {
                string s = Console.ReadLine().ToLower();
                if (s.Equals("help"))
                    Console.WriteLine("Available commands:\n\tcount\t\t-\tShow active client count\n\tstop\t\t-\tStop server\n\ttv\t\t-\tToggle server verbosity\n\tsv\t\t-\tDisplay current server verbosity setting");
                else if (s.Equals("count"))
                    Console.WriteLine("Active client count: " + server.Count);
                else if (s.Equals("stop"))
                {
                    Console.WriteLine("Stopping server...");
                    server.StopRunning();
                }
                else if (s.Equals("tv")) Console.WriteLine("Set verbosity to: " + (verbose = !verbose));
                else if (s.Equals("sv")) Console.WriteLine("Current server verbosity: " + verbose);
            }
        }

        // Load RSA data from a file
        public static RSA LoadRSA(RandomProvider provider)
        {
            RSA func = null;
            Console.Write("Would you like to load RSA keys from files? (y/N): ");
            while (Console.In.ReadYNBool("y"))
            {
                try
                {
                    Console.Write("Enter base file name: ");
                    func = RSA.TryLoad(Console.ReadLine());
                    if (func.GetPubK() == null) throw new NullReferenceException();
                    Console.WriteLine("Sucessfully loaded keys!");
                    break;
                }
                catch (Exception)
                {
                    Console.Write("One or more of the required key files could not be located. Would you like to retry? (y/N): ");
                }
            }
            return func;
        }

        // Generate RSA data
        public static RSA GenerateRSA()
        {
            RSA func;
            int read;
            do
            {
                Console.Write("Enter encryption key size (bytes >= 96): ");
            } while (!int.TryParse(Console.ReadLine(), out read) || read < 96);

            Console.WriteLine("Generating keys...");

            // Always use 8 thread to generate the primes and whatnot. Use a certainty of 20 to minimize any posibility of false primes. 20 is pretty good...
            func = new RSA(read, 4, 8, 20);

            Console.Write("Done! Would you like to save the keys? (y/N): ");
            if (Console.In.ReadYNBool("y"))
            {
                Console.Write("Enter the base file name to be used: ");
                try
                {
                    func.Save(Console.ReadLine(), true);
                }
                catch (Exception) { Console.WriteLine("An error ocurred while attempting to save keys!"); }
            }
            return func;
        }
    }
}
