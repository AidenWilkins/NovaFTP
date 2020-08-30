using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace NovaFTP
{
    public static class Helpers
    {
        // https://gist.github.com/jrusbatch/4211535
        public static int GetAvailablePort(int startingPort)
        {
            var properties = IPGlobalProperties.GetIPGlobalProperties();

            //getting active connections
            var tcpConnectionPorts = properties.GetActiveTcpConnections()
                                .Where(n => n.LocalEndPoint.Port >= startingPort)
                                .Select(n => n.LocalEndPoint.Port);

            //getting active tcp listners - WCF service listening in tcp
            var tcpListenerPorts = properties.GetActiveTcpListeners()
                                .Where(n => n.Port >= startingPort)
                                .Select(n => n.Port);

            //getting active udp listeners
            var udpListenerPorts = properties.GetActiveUdpListeners()
                                .Where(n => n.Port >= startingPort)
                                .Select(n => n.Port);

            var port = Enumerable.Range(startingPort, ushort.MaxValue)
                .Where(i => !tcpConnectionPorts.Contains(i))
                .Where(i => !tcpListenerPorts.Contains(i))
                .Where(i => !udpListenerPorts.Contains(i))
                .FirstOrDefault();

            return port;
        }

        public static IPEndPoint GetExternalIPv4(int port)
        {
            string externalip = new WebClient().DownloadString("http://ipinfo.io/ip").Replace("\n", "");
            return new IPEndPoint(IPAddress.Parse(externalip), port);
        }

        public static long CopyStream(Stream input, Stream output, int bufferSize)
        {
            byte[] buffer = new byte[bufferSize];
            int count = 0;
            long total = 0;

            while ((count = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, count);
                total += count;
            }

            return total;
        }

        public static long CopyStreamAscii(Stream input, Stream output, int bufferSize)
        {
            char[] buffer = new char[bufferSize];
            int count = 0;
            long total = 0;

            using (StreamReader rdr = new StreamReader(input))
            {
                using (StreamWriter wtr = new StreamWriter(output, Encoding.ASCII))
                {
                    while ((count = rdr.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        wtr.Write(buffer, 0, count);
                        total += count;
                    }
                }
            }

            return total;
        }

        public static bool IsValidPath(string path, string root)
        {
            return path.StartsWith(root);
        }

        public static string NormalizeFilename(string path, string root, string currentDir)
        {
            if (path == null)
            {
                path = string.Empty;
            }

            if (path == "/")
            {
                return root;
            }
            else if (path.StartsWith("/"))
            {
                path = new FileInfo(Path.Combine(root, path.Substring(1))).FullName;
            }
            else
            {
                path = new FileInfo(Path.Combine(currentDir, path)).FullName;
            }

            return IsValidPath(path, root) ? path : null;
        }
    }
}
