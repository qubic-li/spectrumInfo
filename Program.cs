using System.Net.Sockets;
using System.Net;
using System.Runtime.InteropServices;

namespace li.qubic.community.spectrumInfo
{
    internal class Program
    {
        public static int BUFFER_SIZE = 1048576 * 4;
        public static byte[] receiveBuffer = new byte[BUFFER_SIZE];
        public static bool _finished = false;
        public static string _ip;
        public static string _id;


        public static byte[] GetPublicKeyFromIdentity(string identity)
        {
            var publicKeyBuffer = new byte[32];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 14; j-- > 0;)
                {
                    if (identity[i * 14 + j] < 'A' || identity[i * 14 + j] > 'Z')
                    {
                        throw new Exception("Invalid Character");
                    }

                    var currentValue = BitConverter.ToUInt64(publicKeyBuffer.AsSpan(i * 8, 8)) * 26 + (ulong)(identity[i * 14 + j] - 'A');

                    BitConverter.TryWriteBytes(publicKeyBuffer.AsSpan(i * 8, 8), currentValue);

                    }
            }
            return publicKeyBuffer;
        }

        static void Main(string[] args)
        {
            if(args.Length < 2)
            {
                Console.WriteLine("Usage: spectrumInfo.exe <IP_ADDRESS_OF_COMPUTOR> <60-CHAR-ID>");
                Console.WriteLine("Example: spectrumInfo.exe 11.25.154.34 SLDFHLKJLKJFDLSKJHLSKDHJFLKHJSDFSDFSDFSDFS");
                return;
            }

            _ip = args[0];
            _id = args[1];

            AskPeer(_ip);

            Console.ReadLine();
        }

        public static void AskPeer(string ip)
        {
            _finished = false;

            var publicKey = GetPublicKeyFromIdentity(_id);

            IPAddress ipAddress = IPAddress.Parse(_ip);
            int port = 21841;
            IPEndPoint remoteEP = new IPEndPoint(ipAddress, port);


            Socket clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            byte[] package = new byte[40]; // creates an empty data array all byte 0

            var rand = new Random();
            
            package[0] = 40; // define size of package
            package[3] = 31; // request type REQUEST_ENTITY
            package[4] = (byte)rand.Next();
            package[5] = (byte)rand.Next();
            package[6] = (byte)rand.Next();
            package[7] = 31; // deprecatedType


            // copy public key to package
            Array.Copy(publicKey, 0, package, 8, 32);


            // Connect to the remote endpoint
            clientSocket.Connect(remoteEP);

            // listen to what the peer
            clientSocket.BeginReceive(receiveBuffer, 0, BUFFER_SIZE, 0,
                new AsyncCallback(ReceiveCallback), clientSocket);

            // Send the binary package to the remote endpoint
            clientSocket.Send(package);

            Thread.Sleep(1000); // wait a second

            // Close the socket
            clientSocket.Shutdown(SocketShutdown.Both);
            clientSocket.Close();

            var start = DateTime.UtcNow;
            while (!_finished && start.AddSeconds(10) > DateTime.UtcNow)
            {
                // wait until we got entity information
                Thread.Sleep(100);
            }

            if (!_finished)
            {
                Console.WriteLine("Looks like there was an error. Please try it again or use another Peer");
            }
        }

        public static void ReceiveCallback(IAsyncResult ar)
        {
            Socket socket = ar.AsyncState as Socket;
            if (socket == null)
                return;

            if (socket.SafeHandle.IsInvalid)
                return;

            // Read data from the remote device.  
            int bytesRead = 0;
            
            bytesRead = socket.EndReceive(ar);
            
            if (bytesRead > 0)
            {
                // find the RESPOND_ENTITY
                var offset = 0;
                while(offset < bytesRead)
                {
                    var size = (receiveBuffer[offset] | (receiveBuffer[offset + 1] << 8) | (receiveBuffer[offset + 2] << 16));
                    if(size == 848) // 848 is the size of the result
                    {
                        // we just load the entity and we do not verify the blockchain
                        var entity = Deserialize<Entity>(receiveBuffer.Skip(offset + 8).Take(64).ToArray());
                        var tick = BitConverter.ToUInt32(receiveBuffer.Skip(offset + 8 + 64).Take(4).ToArray());
                        Console.WriteLine($"{_ip} Reported a Total Value of {entity.incomingAmount - entity.outgoingAmount} in Tick {tick} for the id {_id}");
                        _finished = true;
                        offset = bytesRead;
                    }
                    else
                    {
                        offset += size;
                    }
                }
            }
        }


        public static T Deserialize<T>(byte[] array, int skip = 0, int? fixedSize = null)
            where T : struct
        {
            var size = fixedSize ?? Marshal.SizeOf(typeof(T));
            using (var handle = new ByteArraySafeHandle(Marshal.AllocHGlobal(size), true))
            {
                Marshal.Copy(array, skip, handle.DangerousGetHandle(), size);
                var s = (T)Marshal.PtrToStructure(handle.DangerousGetHandle(), typeof(T));
                return s;
            }
        }

        public class ByteArraySafeHandle : SafeHandle
        {
            public ByteArraySafeHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle) { }

            public override bool IsInvalid => handle == IntPtr.Zero;

            protected override bool ReleaseHandle()
            {
                Marshal.FreeHGlobal(handle);
                return true;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct Entity
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] publicKey;
            public long incomingAmount;
            public long outgoingAmount;
            public uint numberOfIncomingTransfers;
            public uint numberOfOutgoingTransfers;
            public uint latestIncomingTransferTick;
            public uint latestOutgoingTransferTick;
        }
    }
}
