using NovaFTP;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NovaFTP
{
    public struct UserInfo
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public List<VirtualDirectory> Directories { get; set; }

        public UserInfo(string username, string password, List<VirtualDirectory> directories)
        {
            Username = username;
            Password = password;
            Directories = directories;
        }
    }
}
