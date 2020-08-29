using FixedSslLib;
using FtpServer;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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
        private TcpListener DataActive;
        private TcpClient DataPassive;
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
                            response = Login(args);
                            break;
                        case "PASS":
                            response = Login(args);
                            break;
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
                
                }
            }
        }
    }
}
