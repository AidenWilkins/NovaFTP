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
        private readonly TcpClient Client;

        // Control Connection
        private readonly NetworkStream ControlStream;
        private FixedSslStream SslControlStream;
        private StreamReader ControlReader;
        private StreamWriter ControlWriter;

        // Data Connection
        private TcpListener DataPassive;
        private TcpClient DataActive;
        private IPEndPoint ActiveEP;
        private StreamWriter DataWriter;

        // Connection Type's
        private TypeCode TypeCode;
        private ConnectionType DataConnectionType;
        private Protocol Protocol;

        // Other Connection Options
        private readonly bool UseImplicit;
        private readonly X509Certificate2 X509;
        #endregion

        // User Related
        private string Username;
        private string Root;
        private string CurrentDir;
        private LogUser user;
        private bool LoggedIn;

        // Storage
        private string renameFrom;
        
        public ClientConnection(TcpClient client, X509Certificate2 x509, bool useImplicit)
        {
            Client = client;
            X509 = x509;
            UseImplicit = useImplicit;

            ControlStream = Client.GetStream();

            user = new LogUser();
            Logger.RegisterUser(user);
            LoggedIn = false;

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
            try
            {
                user.Address = Client.Client.RemoteEndPoint.ToString();
                user.LogMsg($"220 Ready As I'll Ever Be");
                ControlWriter.WriteLine("220 Ready As I'll Ever Be");
                ControlWriter.Flush();

                string line = null;

                while (!string.IsNullOrEmpty(line = ControlReader.ReadLine()))
                {
                    user.LogMsg($"Command: {line}");
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
                                if (LoggedIn)
                                {
                                    response = "230 User already logged in";
                                    break;
                                }
                                response = Login(args);
                                break;
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
                                try
                                {
                                    string cur = CurrentDir.Replace(Root, string.Empty).Replace('\\', '/');
                                    response = cur.Length > 0 ? cur : "257 \"/\" is current directory";
                                }
                                catch 
                                {
                                    response = "550 PWD Failed Sucessfully";
                                }
                                break;
                            case "TYPE":
                                string[] splitArgs = args.Split(' ');
                                response = Type(splitArgs[0], splitArgs.Length > 1 ? splitArgs[1] : null);
                                break;
                            case "PASV":
                                response = Passive();
                                break;
                            case "PORT":
                                response = Port(args);
                                break;
                            case "LIST":
                                response = List(args ?? CurrentDir);
                                break;
                            case "RETR":
                                response = Retrieve(args);
                                break;
                            case "STOR":
                                response = Store(args);
                                break;
                            case "RNFR":
                                renameFrom = args;
                                response = "350 Requested file action pending further information";
                                break;
                            case "RNTO":
                                response = Rename(renameFrom, args);
                                break;
                            case "PBSZ":
                                response = $"200 PBSZ={args}";
                                break;
                            case "PROT":
                                response = $"200 Protection level set to {args}";
                                Protocol = (args == "P") ? Protocol.P : Protocol.C;
                                break;
                            case "MLSD":
                                response = MLSD(args);
                                break;
                            case "NLSD":
                                response = NLST(args);
                                break;
                            case "SIZE":
                                args = Helpers.NormalizeFilename(args, Root, CurrentDir);
                                if (!Helpers.IsValidPath(args, Root))
                                {
                                    response = "550 File Not Found";
                                    break;
                                }
                                response = (File.Exists(args)) ? $"213 {new FileInfo(args).Length}" : "550 File Not Found";
                                break;
                            case "MDTM":
                                args = Helpers.NormalizeFilename(args, Root, CurrentDir);
                                if (!Helpers.IsValidPath(args, Root))
                                {
                                    response = "550 File Not Found";
                                    break;
                                }
                                response = (File.Exists(args)) ? $"213 {new FileInfo(args).LastWriteTime:yyyyMMddHHmmss.fff}" : "550 File Not Found";
                                break;
                            case "QUIT":
                                response = "221 Goodbye";
                                break;
                            case "DELE":
                                response = Delete(args);
                                break;
                            case "RMD":
                                response = RemoveDir(args);
                                break;
                            case "MKD":
                                response = CreateDir(args);
                                break;
                            case "SYST":
                                response = "215 UNIX Type: L8";
                                break;
                            default:
                                response = $"502 Command '{line}' Not Implemented";
                                break;
                        }

                        try
                        {
                            user.LogMsg($"Response: {response}");
                            ControlWriter.WriteLine(response);
                            ControlWriter.Flush();
                        }
                        catch { }

                        if (response.StartsWith("221"))
                        {
                            if (SslControlStream != null)
                                SslControlStream.Dispose();
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
                Logger.UnregisterUser(user);
            }
            catch (Exception e)
            {
                Logger.Log($"Client {Client.Client.RemoteEndPoint} disconnected due to an error ({e.Message})");
                Client.Close();
                Logger.UnregisterUser(user);
            }
        }

        private string Login(string args)
        {
            if (string.IsNullOrEmpty(Username)) 
            {
                if (UserManager.UserExsits(args)) 
                {
                    Username = args;
                    user.Name = Username;
                    return "331 Username ok, need password";
                }
                return $"530 Username {args} doesn't exist";
            }
            else
            {
                UserInfo user = UserManager.GetUser(Username);
                if(args == user.Password)
                {
                    Root = user.RootDirectory;
                    CurrentDir = Root;
                    LoggedIn = true;
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
                else if (File.Exists(newDir))
                {
                    return $"550 CWD failed. \"{newDir}\": directory not found.";
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

            string intPathname = new DirectoryInfo(Path.Combine(CurrentDir, pathname)).FullName;

            if (Helpers.IsValidPath(intPathname, Root))
            {
                if(DataConnectionType == ConnectionType.Active)
                {
                    DataActive = new TcpClient(ActiveEP.AddressFamily);
                    DataActive.BeginConnect(ActiveEP.Address, ActiveEP.Port, HandleList, intPathname);
                }
                else
                {
                    DataPassive.BeginAcceptTcpClient(HandleList, intPathname);
                }
                return $"150 Opening {DataConnectionType} mode data transfer for LIST";
            }
            else
            {
                intPathname = new DirectoryInfo(Helpers.NormalizeFilename(pathname, Root, CurrentDir)).FullName;
                if (Helpers.IsValidPath(intPathname, Root))
                {
                    if (DataConnectionType == ConnectionType.Active)
                    {
                        DataActive = new TcpClient(ActiveEP.AddressFamily);
                        DataActive.BeginConnect(ActiveEP.Address, ActiveEP.Port, HandleList, intPathname);
                    }
                    else
                    {
                        DataPassive.BeginAcceptTcpClient(HandleList, intPathname);
                    }
                    return string.Format("150 Opening {0} mode data transfer for MLSD", DataConnectionType);
                }
            }
            return $"450 Requested action on '{pathname}' not taken";
        }

        private string Retrieve(string pathname)
        {
            pathname = Helpers.NormalizeFilename(pathname, Root, CurrentDir);
            if(Helpers.IsValidPath(pathname, Root))
            {
                if (DataConnectionType == ConnectionType.Active)
                {
                    DataActive = new TcpClient(ActiveEP.AddressFamily);
                    DataActive.BeginConnect(ActiveEP.Address, ActiveEP.Port, HandleRetr, pathname);
                }
                else
                {
                    DataPassive.BeginAcceptTcpClient(HandleRetr, pathname);
                }
                return $"150 Opening {DataConnectionType} mode for data transfer for RETR";
            }
            return $"550 Error retrieving file {pathname}";
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
                        DataActive.BeginConnect(ActiveEP.Address, ActiveEP.Port, HandleStor, pathname);
                    }
                    else
                    {
                        DataPassive.BeginAcceptTcpClient(HandleStor, pathname);
                    }
                    return $"150 Opening {DataConnectionType} mode for data transfer for STOR";
                }
            }
            return "550 Error storing file";
        }

        private string Rename(string renameFrom, string renameTo)
        {
            if (string.IsNullOrWhiteSpace(renameFrom) || string.IsNullOrWhiteSpace(renameTo))
            {
                return "450 Requested file action not taken";
            }

            renameFrom = Helpers.NormalizeFilename(renameFrom, Root, CurrentDir);
            renameTo = Helpers.NormalizeFilename(renameTo, Root, CurrentDir);

            if(renameFrom != null && renameTo != null)
            {
                if (File.Exists(renameFrom))
                {
                    File.Move(renameFrom, renameTo);
                }
                else if (Directory.Exists(renameFrom))
                {
                    Directory.Move(renameFrom, renameTo);
                }
                else
                {
                    return "450 Requested file action not taken";
                }
                return "250 Requested file action okday, completed";
            }
            return "450 Requested file action not taken";
        }

        private string MLSD(string pathname)
        {
            if (pathname == null)
                pathname = string.Empty;

            string intPathname = new DirectoryInfo(Path.Combine(CurrentDir, pathname)).FullName;

            if (Helpers.IsValidPath(intPathname, Root))
            {
                if (DataConnectionType == ConnectionType.Active)
                {
                    DataActive = new TcpClient(ActiveEP.AddressFamily);
                    DataActive.BeginConnect(ActiveEP.Address, ActiveEP.Port, HandleMLSD, intPathname);
                }
                else
                {
                    DataPassive.BeginAcceptTcpClient(HandleMLSD, intPathname);
                }
                return $"150 Opening {DataConnectionType} mode data transfer for LIST";
            }
            else
            {
                intPathname = new DirectoryInfo(Helpers.NormalizeFilename(pathname, Root, CurrentDir)).FullName;
                if (Helpers.IsValidPath(intPathname, Root))
                {
                    if (DataConnectionType == ConnectionType.Active)
                    {
                        DataActive = new TcpClient(ActiveEP.AddressFamily);
                        DataActive.BeginConnect(ActiveEP.Address, ActiveEP.Port, HandleMLSD, intPathname);
                    }
                    else
                    {
                        DataPassive.BeginAcceptTcpClient(HandleMLSD, intPathname);
                    }
                    return string.Format("150 Opening {0} mode data transfer for MLSD", DataConnectionType);
                }
            }
            return $"450 Requested action on '{pathname}' not taken";
        }

        private string Delete(string pathname)
        {
            pathname = Helpers.NormalizeFilename(pathname, Root, CurrentDir);
            if (Helpers.IsValidPath(pathname, Root))
            {
                if (File.Exists(pathname))
                {
                    File.Delete(pathname);
                    return string.Format("250 File Deleted Successfully");
                }
            }
            return "550 File Not Found";
        }

        private string Port(string args)
        {
            string[] ipAndPort = args.Split(',');

            byte[] ipAddress = new byte[4];
            byte[] port = new byte[2];

            for (int i = 0; i < 4; i++)
            {
                ipAddress[i] = Convert.ToByte(ipAndPort[i]);
            }

            for (int i = 4; i < 6; i++)
            {
                port[i - 4] = Convert.ToByte(ipAndPort[i]);
            }

            if (BitConverter.IsLittleEndian)
                Array.Reverse(port);

            ActiveEP = new IPEndPoint(new IPAddress(ipAddress), BitConverter.ToInt16(port, 0));

            return "200 Data Connection Established";
        }

        private string RemoveDir(string pathname)
        {
            pathname = Helpers.NormalizeFilename(pathname, Root, CurrentDir);
            if(pathname == null)
                return "550 Unable to complete request";
            if (Helpers.IsValidPath(pathname, Root))
            {
                if (Directory.Exists(pathname))
                {
                    Directory.Delete(pathname);
                    return "250 Requested file action okay, completed";
                }
            }
            return "550 Directory Not Found";
        }

        private string CreateDir(string pathname)
        {
            pathname = Helpers.NormalizeFilename(pathname, Root, CurrentDir);
            if (pathname == null)
                return "550 Unable to complete request";
            if (Helpers.IsValidPath(pathname, Root))
            {
                if (!Directory.Exists(pathname))
                {
                    Directory.CreateDirectory(pathname);
                    return "250 Requested file action okay, completed";
                }
            }
            return "550 Directory already exists or path is invalid";
        }

        private string NLST(string pathname)
        {
            if (pathname == null)
            {
                pathname = string.Empty;
            }

            pathname = new DirectoryInfo(Path.Combine(CurrentDir, pathname)).FullName;

            if (Helpers.IsValidPath(pathname, Root))
            {
                if (DataConnectionType == ConnectionType.Active)
                {
                    DataActive = new TcpClient(ActiveEP.AddressFamily);
                    DataActive.BeginConnect(ActiveEP.Address, ActiveEP.Port, HandleNLST, pathname);
                }
                else
                {
                    DataPassive.BeginAcceptTcpClient(HandleNLST, pathname);
                }
                return string.Format("150 Opening {0} mode data transfer for MLSD", DataConnectionType);
            }
            return "450 Requested file action not taken";
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
            pathname = pathname.Replace("-l", "").Replace("-a", "");

            FixedSslStream ssl = null;
            NetworkStream stream = null;

            if(Protocol == Protocol.P || UseImplicit)
            {
                ssl = new FixedSslStream(DataActive.GetStream());
                ssl.AuthenticateAsServer(X509, false, SslProtocols.Default, false);
                DataWriter = new StreamWriter(ssl, Encoding.ASCII);
            }
            else
            {
                stream = DataActive.GetStream();
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

            user.LogMsg("226 List complete");
            ControlWriter.WriteLine("226 List complete");
            ControlWriter.Flush();
        }

        private void HandleRetr(IAsyncResult ar)
        {
            try
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
                    DataWriter = new StreamWriter(ssl, Encoding.ASCII);

                    using (FileStream fs = new FileStream(pathname, FileMode.Open, FileAccess.Read))
                    {
                        CopyStream(fs, ssl);
                    }
                }
                else
                {
                    stream = DataActive.GetStream();
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

                try
                {
                    user.LogMsg("226 Closing data connection, file transfer successful");
                    ControlWriter.WriteLine("226 Closing data connection, file transfer successful");
                    ControlWriter.Flush();
                }
                catch { }
            }
            catch
            {
                try
                {
                    user.LogMsg("550 Closing data connection, file transfer failed successfully");
                    ControlWriter.WriteLine("550 Closing data connection, file transfer failed successfully");
                    ControlWriter.Flush();
                }
                catch { }
            }
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
                DataWriter = new StreamWriter(ssl, Encoding.ASCII);

                using (FileStream fs = new FileStream(pathname, FileMode.Open, FileAccess.Read))
                {
                    CopyStream(ssl, fs);
                }
            }
            else
            {
                stream = DataActive.GetStream();
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

            user.LogMsg("226 Closing data connection, file transfer successful");
            ControlWriter.WriteLine("226 Closing data connection, file transfer successful");
            ControlWriter.Flush();
        }

        private void HandleMLSD(IAsyncResult ar)
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

            if (Protocol == Protocol.P)
            {
                ssl = new FixedSslStream(DataActive.GetStream());
                ssl.AuthenticateAsServer(X509, false, SslProtocols.Default, false);
                DataWriter = new StreamWriter(ssl, Encoding.ASCII);
            }
            else
            {
                stream = DataActive.GetStream();
                DataWriter = new StreamWriter(stream, Encoding.ASCII);
            }

            IEnumerable<string> directories = Directory.EnumerateDirectories(pathname);
            foreach (string dir in directories)
            {
                DirectoryInfo d = new DirectoryInfo(dir);
                string date = d.LastWriteTime.ToString("yyyyMMddHHmmss");
                string line = $"type=cdir;modify={date};perm=el; {d.Name}";

                DataWriter.WriteLine(line);
                DataWriter.Flush();
            }

            IEnumerable<string> files = Directory.EnumerateFiles(pathname);

            foreach (string file in files)
            {
                FileInfo f = new FileInfo(file);

                string date = f.LastWriteTime.ToString("yyyyMMddHHmmss");

                string line = $"type=file;size={f.Length};modify={date};perm=r; {f.Name}";

                DataWriter.WriteLine(line);
                DataWriter.Flush();
            }

            ssl.Dispose();

            DataActive.Close();
            DataActive = null;

            user.LogMsg("226 MLSD complete");
            ControlWriter.WriteLine("226 MLSD complete");
            ControlWriter.Flush();
        }

        private void HandleNLST(IAsyncResult ar)
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

            if (Protocol == Protocol.P)
            {
                ssl = new FixedSslStream(DataActive.GetStream());
                ssl.AuthenticateAsServer(X509, false, SslProtocols.Default, false);
                DataWriter = new StreamWriter(ssl, Encoding.ASCII);
            }
            else
            {
                stream = DataActive.GetStream();
                DataWriter = new StreamWriter(stream, Encoding.ASCII);
            }

            IEnumerable<string> directories = Directory.EnumerateDirectories(pathname);
            foreach (string dir in directories)
            {
                DirectoryInfo d = new DirectoryInfo(dir);
                string line = d.Name;

                DataWriter.WriteLine(line);
                DataWriter.Flush();
            }

            IEnumerable<string> files = Directory.EnumerateFiles(pathname);
            foreach (string file in files)
            {
                FileInfo f = new FileInfo(file);
                string line = f.Name;

                DataWriter.WriteLine(line);
                DataWriter.Flush();
            }

            ssl.Dispose();

            DataActive.Close();
            DataActive = null;

            user.LogMsg("226 NLST complete");
            ControlWriter.WriteLine("226 NLST complete");
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
