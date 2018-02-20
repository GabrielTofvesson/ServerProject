using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Tofvesson.Crypto
{
    public delegate string OnMessageRecieved(string request, out bool stayAlive);
    public delegate void OnClientConnect(NetClient client);
    public sealed class NetServer
    {
        private readonly short port;
        private readonly object state_lock = new object();
        private readonly List<ClientStateObject> clients = new List<ClientStateObject>();
        private readonly OnMessageRecieved callback;
        private readonly OnClientConnect onConn;
        private readonly IPAddress ipAddress;
        private Socket listener;
        private readonly RSA crypto;
        private readonly byte[] ser_cache;
        private readonly int bufSize;

        private bool state_running = false;
        private Thread listenerThread;


        public int Count
        {
            get
            {
                return clients.Count;
            }
        }

        public bool Running
        {
            get
            {
                lock (state_lock) return state_running;
            }

            private set
            {
                lock (state_lock) state_running = value;
            }
        }

        public NetServer(RSA crypto, short port, OnMessageRecieved callback, OnClientConnect onConn, int bufSize = 16384)
        {
            this.callback = callback;
            this.onConn = onConn;
            this.bufSize = bufSize;
            this.crypto = crypto;
            this.port = port;
            this.ser_cache = crypto.Serialize(); // Keep this here so we don't wastefully re-serialize every time we get a new client

            IPHostEntry ipHostInfo = Dns.GetHostEntry(Dns.GetHostName());
            this.ipAddress = ipHostInfo.GetIPV4();
            if (ipAddress == null)
                ipAddress = IPAddress.Parse("127.0.0.1"); // If there was no IPv4 result in dns lookup, use loopback address
        }

        public void StartListening()
        {
            bool isAlive = false;
            object lock_await = new object();
            if(!Running && (listenerThread==null || !listenerThread.IsAlive))
            {
                Running = true;
                listenerThread = new Thread(() =>
                {

                    this.listener = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                    {
                        Blocking = false // When calling Accept() with no queued sockets, listener throws an exception
                    };
                    IPEndPoint localEndPoint = new IPEndPoint(ipAddress, port);
                    listener.Bind(localEndPoint);
                    listener.Listen(100);

                    byte[] buffer = new byte[bufSize];
                    lock (lock_await) isAlive = true;
                    while (Running)
                    {
                        // Accept clients
                        try
                        {
                            Socket s = listener.Accept();
                            s.Blocking = false;
                            clients.Add(new ClientStateObject(new NetClient(s, crypto, callback, onConn), buffer));
                        }
                        catch (Exception)
                        {
                            if(clients.Count==0)
                                Thread.Sleep(25); // Wait a bit before trying to accept another client
                        }

                        // Update clients
                        foreach (ClientStateObject cli in clients.ToArray())
                            // Ensure we are still connected to client
                            if (!(cli.IsConnected() && !cli.Update()))
                            {
                                clients.Remove(cli);
                                continue;
                            }
                    }
                })
                {
                    Priority = ThreadPriority.Highest,
                    Name = $"NetServer-${port}"
                };
                listenerThread.Start();
            }

            bool rd;
            do
            {
                Thread.Sleep(25);
                lock (lock_await) rd = isAlive;
            } while (!rd);
        }

        public Task<object> StopRunning()
        {
            Running = false;
            
            return new TaskFactory().StartNew<object>(() =>
            {
                listenerThread.Join();
                return null;
            });
        }

        private class ClientStateObject
        {
            private NetClient client;
            private bool hasCrypto = false;                  // Whether or not encrypted communication has been etablished
            private Queue<byte> buffer = new Queue<byte>();  // Incoming data buffer
            public long lastComm;                            // Latest comunication event (in ticks)
            private int expectedSize = 0;                    // Expected size of next message
            private readonly byte[] buf;

            public ClientStateObject(NetClient client, byte[] buf)
            {
                this.client = client;
                this.buf = buf;
                lastComm = DateTime.UtcNow.Ticks; // 1/10,000,000 seconds
            }

            public bool Update()
            {
                bool stop = client.SyncListener(hasCrypto, expectedSize, out hasCrypto, out expectedSize, out bool read, buffer, buf);
                if (read) lastComm = DateTime.UtcNow.Ticks;
                return stop;
            }
            public bool IsConnected() => client.IsConnected;
        }
    }
    
    public class NetClient
    {
        // Thread state lock for primitive values
        private readonly object state_lock = new object();

        // Primitive state values
        private bool state_running = false;

        // Socket event listener
        private Thread eventListener;

        // Communication parameters
        protected readonly Queue<byte[]> messageBuffer = new Queue<byte[]>();
        protected readonly OnMessageRecieved handler;
        protected readonly OnClientConnect onConn;
        protected readonly IPAddress target;
        protected readonly int bufSize;
        protected readonly RSA decrypt;

        // Connection to peer
        protected Socket Connection { get; private set; }

        // State/connection parameters
        protected AES Crypto { get; private set; }
        public short Port { get; }
        protected bool Running
        {
            get
            {
                lock (state_lock) return state_running;
            }
            private set
            {
                lock (state_lock) state_running = value;
            }
        }

        protected internal bool IsConnected
        {
            get
            {
                return Connection != null && Connection.Connected && !(Connection.Poll(1, SelectMode.SelectRead) && Connection.Available == 0);
            }
        }

        public bool IsAlive
        {
            get
            {
                return Running || (Connection != null && Connection.Connected) || (eventListener != null && eventListener.IsAlive);
            }
        }

        protected bool ServerSide { get; private set; }


        public NetClient(AES crypto, IPAddress target, short port, OnMessageRecieved handler, OnClientConnect onConn, int bufSize = 16384)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            if (target.AddressFamily==AddressFamily.InterNetwork && target.Address == 16777343)
#pragma warning restore CS0618 // Type or member is obsolete
            {
                IPAddress addr = Dns.GetHostEntry(Dns.GetHostName()).GetIPV4();
                if (addr != null) target = addr;
            }
            this.target = target;
            Crypto = crypto;
            this.bufSize = bufSize;
            this.handler = handler;
            this.onConn = onConn;
            Port = port;
            ServerSide = false;
        }

        internal NetClient(Socket sock, RSA crypto, OnMessageRecieved handler, OnClientConnect onConn)
            : this(null, ((IPEndPoint)sock.RemoteEndPoint).Address, (short) ((IPEndPoint)sock.RemoteEndPoint).Port, handler, onConn, -1)
        {
            decrypt = crypto;
            Connection = sock;
            Running = true;
            ServerSide = true;

            // Initiate crypto-handshake by sending public keys
            Connection.Send(NetSupport.WithHeader(crypto.Serialize()));
        }

        public virtual void Connect()
        {
            if (ServerSide) throw new SystemException("Serverside socket cannot connect to a remote peer!");
            NetSupport.DoStateCheck(IsAlive || (eventListener != null && eventListener.IsAlive), false);
            Running = true;
            Connection = new Socket(SocketType.Stream, ProtocolType.Tcp);
            Connection.Connect(target, Port);
            eventListener = new Thread(() =>
            {
                bool cryptoEstablished = false;
                int mLen = 0;
                Queue<byte> ibuf = new Queue<byte>();
                byte[] buffer = new byte[bufSize];
                while (Running)
                    if (SyncListener(cryptoEstablished, mLen, out cryptoEstablished, out mLen, out bool _, ibuf, buffer))
                        break;
                if (ibuf.Count != 0) Console.WriteLine("Client socket closed with unread data!");
            })
            {
                Priority = ThreadPriority.Highest,
                Name = $"NetClient-${target}:${Port}"
            };
            eventListener.Start();
        }

        protected internal bool SyncListener(bool cryptoEstablished, int mLen, out bool cE, out int mL, out bool acceptedData, Queue<byte> ibuf, byte[] buffer)
        {
            cE = cryptoEstablished;
            mL = mLen;
            if (cryptoEstablished)
            {
                lock (messageBuffer)
                {
                    foreach (byte[] message in messageBuffer) Connection.Send(NetSupport.WithHeader(message));
                    messageBuffer.Clear();
                }
            }
            if (acceptedData = Connection.Available > 0)
            {
                int read = Connection.Receive(buffer);
                ibuf.EnqueueAll(buffer, 0, read);
            }
            if (mLen == 0 && ibuf.Count >= 4)
                mL = mLen = Support.ReadInt(ibuf.Dequeue(4), 0);
            if (mLen != 0 && ibuf.Count >= mLen)
            {
                // Got a full message. Parse!
                byte[] message = ibuf.Dequeue(mLen);

                if (!cryptoEstablished)
                {
                    if (ServerSide)
                    {
                        Crypto = AES.Deserialize(decrypt.Decrypt(message), out int _);
                    }
                    else
                    {
                        // Reconstruct RSA object from remote public keys and use it to encrypt our serialized AES key/iv
                        byte[] b1 = NetSupport.WithHeader(RSA.Deserialize(message, out int _).Encrypt(Crypto.Serialize()));
                        Connection.Send(b1);
                    }
                    cE = true;
                    onConn(this);
                }
                else
                {
                    string response = handler(Crypto.DecryptString(message), out bool live);
                    if (response != null) Connection.Send(NetSupport.WithHeader(Crypto.Encrypt(response)));
                    if (!live)
                    {
                        Running = false;
                        try
                        {
                            Connection.Close();
                        }
                        catch (Exception) { }
                        return true;
                    }
                }

                // Reset expexted message length
                mL = 0;
            }
            return false;
        }

        public virtual async Task<object> Disconnect()
        {
            NetSupport.DoStateCheck(IsAlive, true);
            Running = false;
            

            return await new TaskFactory().StartNew<object>(() => { eventListener.Join(); return null; });
        }

        public bool TrySend(string message) => TrySend(Encoding.UTF8.GetBytes(message));
        public bool TrySend(byte[] message)
        {
            try
            {
                Send(message);
                return true;
            }
            catch (InvalidOperationException) { return false; }
        }
        public virtual void Send(string message) => Send(Encoding.UTF8.GetBytes(message));
        public virtual void Send(byte[] message) {
            NetSupport.DoStateCheck(IsAlive, true);
            lock (messageBuffer) messageBuffer.Enqueue(Crypto.Encrypt(message, new PassthroughPadding()));
        }
    }

    public static class NetSupport
    {
        internal static byte[] WithHeader(string message) => WithHeader(Encoding.UTF8.GetBytes(message));
        internal static byte[] WithHeader(byte[] message)
        {
            byte[] nmsg = new byte[message.Length + 4];
            Support.WriteToArray(nmsg, message.Length, 0);
            Array.Copy(message, 0, nmsg, 4, message.Length);
            return nmsg;
        }

        internal static void DoStateCheck(bool state, bool target) {
            if (state != target) throw new InvalidOperationException("Bad state!");
        }
    }
}
