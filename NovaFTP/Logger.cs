using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NovaFTP
{
    public static class Logger
    {
        private static FileStream fs;
        private static StreamWriter LogWriter;
        private static bool UseTimestamps;
        public static void StartLogger(string file, bool useTimestamps)
        {
            fs = new FileStream(file, FileMode.Append, FileAccess.Write, FileShare.Read);
            LogWriter = new StreamWriter(fs);
        }

        public static void Log(string msg)
        {
            string log = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss} {msg}";
            if (fs != null)
            {
                LogWriter.WriteLine(log);
                LogWriter.Flush();
            }
            Console.WriteLine(log);
        }

        public static void RegisterUser(LogUser user)
        {
            user.OnLog += Log;
        }

        public static void UnregisterUser(LogUser user)
        {
            user.OnLog -= Log;
        }
    }
}
