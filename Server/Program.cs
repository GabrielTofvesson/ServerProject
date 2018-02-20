using Tofvesson.Crypto;
using System;

namespace Server
{
    class Program
    {
        static void Main(string[] args)
        {
            bool verbose = false;
            // Prepare crypto
            RandomProvider provider = new RegularRandomProvider();
            RSA func = LoadRSA(provider);
            if (func == null) func = GenerateRSA();

            Console.WriteLine("Server starting!\nType \"help\" for a list of serverside commands");

            NetServer server = new NetServer(func, 1337, (string message, out bool keepAlive) =>
            {
                if(verbose) Console.WriteLine("Got message from client: " + message);
                keepAlive = true;
                return "Alright!";
            },
            client =>
            {
                if (verbose) Console.WriteLine($"Client has connected: {client.ToString()}");
            });
            server.StartListening();

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
                    if (func.GetPK() == null) throw new NullReferenceException();
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

        public static RSA GenerateRSA()
        {
            RSA func;
            int read;
            do
            {
                Console.Write("Enter encryption key size (bytes >= 96): ");
            } while (!int.TryParse(Console.ReadLine(), out read) || read < 96);

            Console.WriteLine("Generating keys...");

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
