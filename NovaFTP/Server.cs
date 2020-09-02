using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NovaFTP
{
    class Server
    {
        static X509Certificate2 X509 = new X509Certificate2("certificate.pfx");
        static void Main(string[] args)
        {
            UserManager.LoadUsers("User.xml");
            Logger.StartLogger(DateTime.Now.ToString("yyyy-MM-dd") + ".txt", true);

            // Explicit and Unencrypted Connections
            TcpListener Explicit = new TcpListener(IPAddress.Any, 21);
            Explicit.Start();
            Explicit.BeginAcceptTcpClient(AcceptExplicit, Explicit);

            // Implicit
            TcpListener Implicit = new TcpListener(IPAddress.Any, 990);
            Implicit.Start();
            Implicit.BeginAcceptTcpClient(AcceptImplicit, Implicit);

            while (true) { Thread.Sleep(10); }
        }

        private static void AcceptExplicit(IAsyncResult ar)
        {
            try
            {
                TcpListener ex = (TcpListener)ar.AsyncState;
                TcpClient client = ex.EndAcceptTcpClient(ar);
                ex.BeginAcceptTcpClient(AcceptExplicit, ex);

                ClientConnection c = new ClientConnection(client, X509, false);
            }
            catch { }
        }

        private static void AcceptImplicit(IAsyncResult ar)
        {
            try
            {
                TcpListener im = (TcpListener)ar.AsyncState;
                TcpClient client = im.EndAcceptTcpClient(ar);
                im.BeginAcceptTcpClient(AcceptImplicit, im);

                ClientConnection c = new ClientConnection(client, X509, true);
            }
            catch { }
        }
    }
}
