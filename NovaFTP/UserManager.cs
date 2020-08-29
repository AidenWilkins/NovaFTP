using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace FtpServer
{
    public static class UserManager
    {
        private static List<UserInfo> Users = new List<UserInfo>();
        public static bool LoadUsers(string filename)
        {
            XmlDocument user = new XmlDocument();
            try
            {
                user.Load(filename);
            }
            catch
            {
                return false;
            }

            XmlNodeList users = user.SelectNodes("Users/User");
            foreach (XmlNode node in users)
            {
                UserInfo u = new UserInfo();
                u.Username = node.SelectSingleNode("Username").InnerText;
                u.Password = node.SelectSingleNode("Password").InnerText;
                u.RootDirectory = node.SelectSingleNode("RootDirectory").InnerText;
                Users.Add(u);
            }

            return true;
        }

        public static bool UserExsits(string username)
        {
            return Users.Any(x => x.Username == username);
        }

        public static UserInfo GetUser(string username)
        {
            return Users.First(x => x.Username == username);
        }
    }
}
