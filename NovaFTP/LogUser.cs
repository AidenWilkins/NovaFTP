using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NovaFTP
{
    public class LogUser
    {
        public string Name { get; set; }
        public string Address { get; set; }

        public delegate void Log(string log);
        public event Log OnLog;

        public void LogMsg(string message)
        {
            if (!string.IsNullOrEmpty(Name))
            {
                OnLog?.Invoke($"({Name}@{Address})] {message}");
            }
            else
            {
                OnLog?.Invoke($"({Address})] {message}");
            }
        }
    }
}
