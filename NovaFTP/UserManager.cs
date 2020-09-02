using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Markup;
using System.Xml;

namespace NovaFTP
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
                XmlNodeList vDirs = node.SelectNodes("VirtualDirectories/Directory");
                List<VirtualDirectory> vd = new List<VirtualDirectory>();
                foreach (XmlNode vDir in vDirs)
                {
                    if(vDir.Attributes.Count == 1)
                    {
                        if(vDir.Attributes[0].Name == "root")
                        {
                            string path = vDir.SelectSingleNode("Path").InnerText;
                            string dPerms = vDir.SelectSingleNode("DirectoryPerms").InnerText;
                            string fPerms = vDir.SelectSingleNode("FilePerms").InnerText;
                            VirtualDirectory v = new VirtualDirectory("", path, true, ParseDirectoryPerms(dPerms), ParseFilePerms(fPerms));
                            vd.Add(v);
                        }
                    }
                    else
                    {
                        string alias = vDir.SelectSingleNode("Alias").InnerText;
                        string path = vDir.SelectSingleNode("Path").InnerText;
                        string dPerms = vDir.SelectSingleNode("DirectoryPerms").InnerText;
                        string fPerms = vDir.SelectSingleNode("FilePerms").InnerText;
                        VirtualDirectory v = new VirtualDirectory(alias, path, false, ParseDirectoryPerms(dPerms), ParseFilePerms(fPerms));
                        vd.Add(v);
                    }
                }
                u.Directories = vd;
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

        private static DirectoryPerms ParseDirectoryPerms(string directoryPerms)
        {
            DirectoryPerms dp = DirectoryPerms.None;
            string[] perms = directoryPerms.Split('|');
            foreach (string p in perms)
            {
                if(p == "Create")
                {
                    dp |= DirectoryPerms.Create;
                }
                else if(p == "Delete")
                {
                    dp |= DirectoryPerms.Delete;
                }
                else if(p == "List")
                {
                    dp |= DirectoryPerms.List;
                }
                else if(p == "ListSub")
                {
                    dp |= DirectoryPerms.ListSub;
                }
            }
            return dp;
        }

        private static FilePerms ParseFilePerms(string filePerms)
        {
            FilePerms dp = FilePerms.None;
            string[] perms = filePerms.Split('|');
            foreach (string p in perms)
            {
                if (p == "Read")
                {
                    dp |= FilePerms.Read;
                }
                else if (p == "Delete")
                {
                    dp |= FilePerms.Delete;
                }
                else if (p == "List")
                {
                    dp |= FilePerms.Write;
                }
                else if (p == "ListSub")
                {
                    dp |= FilePerms.Append;
                }
            }
            return dp;
        }
    }
}
