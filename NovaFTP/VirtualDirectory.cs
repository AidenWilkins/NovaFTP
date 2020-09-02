using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NovaFTP
{
    public class VirtualDirectory
    {
        public string Alias { get; private set; }
        public string Path { get; private set; }
        public bool IsRoot { get; private set; }
        public DirectoryPerms DirectoryPerms { get; private set; }
        public FilePerms FilePerms { get; private set; }

        public VirtualDirectory(string alias, string path, bool isRoot, DirectoryPerms directoryPerms, FilePerms filePerms)
        {
            Alias = alias;
            Path = path;
            IsRoot = isRoot;
            DirectoryPerms = directoryPerms;
            FilePerms = filePerms;
        }
    }
}
