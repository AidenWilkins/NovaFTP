using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FtpServer
{
    public struct UserInfo
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string RootDirectory { get; set; }

        public UserInfo(string username, string password, string rootDirectory)
        {
            Username = username;
            Password = password;
            RootDirectory = rootDirectory;
        }
    }
}
