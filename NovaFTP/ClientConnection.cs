using FixedSslLib;
using FtpServer;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NovaFTP
{
    public class ClientConnection
    {
        #region Connection Related
        private TcpClient Client;

        // Control Connection
        private NetworkStream ControlStream;
        private FixedSslStream SslControlStream;
        private StreamReader ControlReader;
        private StreamWriter ControlWriter;

        // Data Connection
        private TcpListener DataPassive;
        private TcpClient DataActive;
        private IPEndPoint ActiveEP;
        private StreamReader DataReader;
        private StreamWriter DataWriter;

        // Connection Type's
        private TypeCode TypeCode;
        private ConnectionType DataConnectionType;
        private Protocol Protocol;

        // Other Connection Options
        private bool UseImplicit;
        private X509Certificate2 X509;
        #endregion

        // User Related
        private string Username;
        private string Root;
        private string CurrentDir;

        // Storage
        private string renameFrom;

        
        public ClientConnection(TcpClient client, X509Certificate2 x509, bool useImplicit)
        {
            Client = client;
            X509 = x509;
            UseImplicit = useImplicit;

            ControlStream = Client.GetStream();

            if (UseImplicit)
            {
                SslControlStream = new FixedSslStream(ControlStream);
                SslControlStream.AuthenticateAsServer(X509);

                ControlReader = new StreamReader(SslControlStream);
                ControlWriter = new StreamWriter(SslControlStream);
            }
            else
            {
                ControlReader = new StreamReader(ControlStream);
                ControlWriter = new StreamWriter(ControlStream);
            }

            ThreadPool.QueueUserWorkItem(HandleControl, null);
        }

        private void HandleControl(object state)
        {
            ControlWriter.WriteLine("220 Ready As I'll Ever Be");
            ControlWriter.Flush();

            string line = null;

            while (!string.IsNullOrEmpty(line = ControlReader.ReadLine()))
            {
                string response = null;
                bool authTls = false;

                string[] command = line.Split(' ');
                string cmd = command[0].ToUpperInvariant();
                string args = command.Length > 1 ? line.Substring(command[0].Length + 1) : null;

                if (response == null)
                {
                    switch (cmd)
                    {
                        case "USER":
                        case "PASS":
                            response = Login(args);
                            break;
                        case "AUTH":
                            if (args == "TLS" || args == "SSL")
                            {
                                response = "234 Enable TLS/SSL Connection";
                                authTls = true;
                                break;
                            }
                            response = $"502 Unknown Argument '{args}'";
                            break;
                        // File Commands
                        case "CDUP":
                            response = ChangeWD("..");
                            break;
                        case "CWD":
                            response = ChangeWD(args);
                            break;
                        case "PWD":
                            string cur = CurrentDir.Replace(Root, string.Empty).Replace('\\', '/');
                            response = cur.Length > 0 ? cur : "/";
                            break;
                        case "TYPE":
                            string[] splitArgs = args.Split(' ');
                            response = Type(splitArgs[0], splitArgs.Length > 1 ? splitArgs[1] : null);
                            break;
                        case "PASV":
                            response = Passive();
                            break;
                        case "LIST":
                            response = List(args ?? CurrentDir);
                            break;
                        case "RETR":
                            response = Retrieve(args);
                            break;
                        default:
                            response = $"502 Command '{line}' Not Implemented";
                            break;
                    }

                    ControlWriter.WriteLine(response);
                    ControlWriter.Flush();

                    if (response.StartsWith("221"))
                    {
                        Client.Close();
                        break;
                    }
                    if (authTls)
                    {
                        SslControlStream = new FixedSslStream(ControlStream);
                        SslControlStream.AuthenticateAsServer(X509, false, SslProtocols.Default, false);
                        ControlWriter = new StreamWriter(SslControlStream);
                        ControlReader = new StreamReader(SslControlStream);
                    }
                }
            }
        }

        private string Login(string args)
        {
            if (string.IsNullOrEmpty(Username)) 
            {
                if (UserManager.UserExsits(args)) 
                {
                    Username = args;
                    return "331 Username ok, need password";
                }
                return $"530 Username {args} doesn't exsite";
            }
            else
            {
                UserInfo user = UserManager.GetUser(Username);
                if(args == user.Password)
                {
                    Root = user.RootDirectory;
                    CurrentDir = Root;
                    return "230 User logged in";
                }
                else
                {
                    return "530 Not logged in";
                }
            }
        }

        private string ChangeWD(string directory)
        {
            if (directory == "/")
            {
                CurrentDir = Root;
            }
            else
            {
                string newDir;

                if (directory.StartsWith("/"))
                {
                    directory = directory.Substring(1).Replace('/', '\\');
                    newDir = Path.Combine(Root, directory);
                }
                else
                {
                    directory = directory.Replace('/', '\\');
                    newDir = Path.Combine(CurrentDir, directory);
                }

                if (Directory.Exists(newDir))
                {
                    CurrentDir = new DirectoryInfo(newDir).FullName;

                    if (!Helpers.IsValidPath(CurrentDir, Root))
                    {
                        CurrentDir = Root;
                    }
                }
                else
                {
                    CurrentDir = Root;
                }
            }
            return "250 Changed to new directory";
        }

        private string Type(string typeCode, string formatControl)
        {
            string response = "";

            switch (typeCode)
            {
                case "I":
                    TypeCode = TypeCode.Image;
                    response = "200 OK";
                    break;
                case "A":
                    TypeCode = TypeCode.ASCII;
                    response = "200 OK";
                    break;
                case "E":
                    response = $"504 Command Not Implemented With Parameter '{typeCode}'";
                    break;
                case "L":
                    response = $"504 Command Not Implemented With Parameter '{typeCode}'";
                    break;
            }

            if (formatControl != null)
            {
                switch (formatControl)
                {
                    case "N":
                        response = "200 OK";
                        break;
                    case "T":
                        response = $"504 Command Not Implemented With Parameter '{formatControl}'";
                        break;
                    case "C":
                        response = $"504 Command Not Implemented With Parameter '{formatControl}'";
                        break;
                }
            }
            return response;
        }

        private string Passive()
        {
            int avPort = Helpers.GetAvailablePort(49152);
            IPAddress local = ((IPEndPoint)Client.Client.LocalEndPoint).Address;
            DataPassive = new TcpListener(local, avPort);
            DataPassive.Start();

            byte[] addr = Helpers.GetExternalIPv4(avPort).Address.GetAddressBytes();
            byte[] port = BitConverter.GetBytes((short)avPort);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(port);

            DataConnectionType = ConnectionType.Passive;
            return $"227 Entering Passive Mode ({addr[0]},{addr[1]},{addr[2]},{addr[3]},{port[0]},{port[1]})";
        }

        private string List(string pathname)
        {
            if (pathname == null)
                pathname = string.Empty;

            pathname = new DirectoryInfo(Path.Combine(CurrentDir, pathname)).FullName;

            if (pathname.StartsWith(Root))
            {
                if(DataConnectionType == ConnectionType.Active)
                {
                    DataActive = new TcpClient(ActiveEP.AddressFamily);
                    DataActive.BeginConnect(ActiveEP.Address, ActiveEP.Port, HandleList, pathname);
                }
                else
                {
                    DataPassive.BeginAcceptTcpClient(HandleList, pathname);
                }
                return $"150 Opening {DataConnectionType} mode data transfer for LIST";
            }
            return $"450 Requested action on '{pathname}' not taken";
        }

        private string Retrieve(string pathname)
        {
            pathname = Helpers.NormalizeFilename(pathname, Root, CurrentDir);
            if(Helpers.IsValidPath(pathname, Root))
            {
                if(DataConnectionType == ConnectionType.Active)
                {
                    if (DataConnectionType == ConnectionType.Active)
                    {
                        DataActive = new TcpClient(ActiveEP.AddressFamily);
                        DataActive.BeginConnect(ActiveEP.Address, ActiveEP.Port, HandleList, pathname);
                    }
                    else
                    {
                        DataPassive.BeginAcceptTcpClient(HandleRetr, pathname);
                    }
                    return $"250 Opening {DataConnectionType} mode for data transfer for RETR";
                }
            }
            return "550 Error retrieving file";
        }

        private string Store(string pathname)
        {
            pathname = Helpers.NormalizeFilename(pathname, Root, CurrentDir);

            if (Helpers.IsValidPath(pathname, Root))
            {
                if (DataConnectionType == ConnectionType.Active)
                {
                    if (DataConnectionType == ConnectionType.Active)
                    {
                        DataActive = new TcpClient(ActiveEP.AddressFamily);
                        DataActive.BeginConnect(ActiveEP.Address, ActiveEP.Port, HandleList, pathname);
                    }
                    else
                    {
                        DataPassive.BeginAcceptTcpClient(HandleStor, pathname);
                    }
                    return $"250 Opening {DataConnectionType} mode for data transfer for STOR";
                }
            }
            return "550 Error storing file";
        }

        // Handlers
        private void HandleList(IAsyncResult ar)
        {
            if(DataConnectionType == ConnectionType.Active)
            {
                DataActive.EndConnect(ar);
            }
            else
            {
                DataActive = DataPassive.EndAcceptTcpClient(ar);
            }

            string pathname = (string)ar.AsyncState;

            FixedSslStream ssl = null;
            NetworkStream stream = null;

            if(Protocol == Protocol.P || UseImplicit)
            {
                ssl = new FixedSslStream(DataActive.GetStream());
                ssl.AuthenticateAsServer(X509, false, SslProtocols.Default, false);
                DataReader = new StreamReader(ssl, Encoding.ASCII);
                DataWriter = new StreamWriter(ssl, Encoding.ASCII);
            }
            else
            {
                stream = DataActive.GetStream();
                DataReader = new StreamReader(stream, Encoding.ASCII);
                DataWriter = new StreamWriter(stream, Encoding.ASCII);
            }

            IEnumerable<string> directories = Directory.EnumerateDirectories(pathname);
            foreach (string dir in directories)
            {
                DirectoryInfo d = new DirectoryInfo(dir);
                string line = string.Format("drwxr-xr-x    2 2003     2003     {0,8} {1} {2}", "4096", d.LastWriteTime.ToString("MMM dd  yyyy"), d.Name);

                DataWriter.WriteLine(line);
                DataWriter.Flush();
            }
            IEnumerable<string> files = Directory.EnumerateFiles(pathname);
            foreach (string file in files)
            {
                FileInfo f = new FileInfo(file);

                string line = string.Format("-rw-r--r--    2 2003     2003     {0,8} {1} {2}", f.Length, f.LastWriteTime.ToString("MMM dd  yyyy"), f.Name);

                DataWriter.WriteLine(line);
                DataWriter.Flush();
            }

            if (ssl != null)
                ssl.Dispose();

            if (stream != null)
                stream.Dispose();

            DataActive.Close();
            DataActive = null;

            ControlWriter.WriteLine("226 List complete");
            ControlWriter.Flush();
        }

        private void HandleRetr(IAsyncResult ar)
        {
            if (DataConnectionType == ConnectionType.Active)
            {
                DataActive.EndConnect(ar);
            }
            else
            {
                DataActive = DataPassive.EndAcceptTcpClient(ar);
            }

            string pathname = (string)ar.AsyncState;

            FixedSslStream ssl = null;
            NetworkStream stream = null;

            if (Protocol == Protocol.P || UseImplicit)
            {
                ssl = new FixedSslStream(DataActive.GetStream());
                ssl.AuthenticateAsServer(X509, false, SslProtocols.Default, false);
                DataReader = new StreamReader(ssl, Encoding.ASCII);
                DataWriter = new StreamWriter(ssl, Encoding.ASCII);

                using (FileStream fs = new FileStream(pathname, FileMode.Open, FileAccess.Read))
                {
                    CopyStream(fs, ssl);
                }
            }
            else
            {
                stream = DataActive.GetStream();
                DataReader = new StreamReader(stream, Encoding.ASCII);
                DataWriter = new StreamWriter(stream, Encoding.ASCII);

                using (FileStream fs = new FileStream(pathname, FileMode.Open, FileAccess.Read))
                {
                    CopyStream(fs, stream);
                }
            }

            if (ssl != null)
                ssl.Dispose();

            if (stream != null)
                stream.Dispose();

            DataActive.Close();
            DataActive = null;

            ControlWriter.WriteLine("226 Closing data connection, file transfer successful");
            ControlWriter.Flush();
        }

        private void HandleStor(IAsyncResult ar)
        {
            if (DataConnectionType == ConnectionType.Active)
            {
                DataActive.EndConnect(ar);
            }
            else
            {
                DataActive = DataPassive.EndAcceptTcpClient(ar);
            }

            string pathname = (string)ar.AsyncState;

            FixedSslStream ssl = null;
            NetworkStream stream = null;

            if (Protocol == Protocol.P || UseImplicit)
            {
                ssl = new FixedSslStream(DataActive.GetStream());
                ssl.AuthenticateAsServer(X509, false, SslProtocols.Default, false);
                DataReader = new StreamReader(ssl, Encoding.ASCII);
                DataWriter = new StreamWriter(ssl, Encoding.ASCII);

                using (FileStream fs = new FileStream(pathname, FileMode.Open, FileAccess.Read))
                {
                    CopyStream(ssl, fs);
                }
            }
            else
            {
                stream = DataActive.GetStream();
                DataReader = new StreamReader(stream, Encoding.ASCII);
                DataWriter = new StreamWriter(stream, Encoding.ASCII);

                using (FileStream fs = new FileStream(pathname, FileMode.Open, FileAccess.Read))
                {
                    CopyStream(stream, fs);
                }
            }

            if (ssl != null)
                ssl.Dispose();

            if (stream != null)
                stream.Dispose();

            DataActive.Close();
            DataActive = null;

            ControlWriter.WriteLine("226 Closing data connection, file transfer successful");
            ControlWriter.Flush();
        }

        private long CopyStream(Stream input, Stream output)
        {
            if (TypeCode == TypeCode.Image)
            {
                return Helpers.CopyStream(input, output, 4096);
            }
            else
            {
                return Helpers.CopyStreamAscii(input, output, 4096);
            }
        }
    }
}
