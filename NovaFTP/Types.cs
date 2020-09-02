using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NovaFTP
{
    public enum TypeCode { ASCII, Image, EBCDIC, Local }
    public enum ConnectionType { Active, Passive }
    public enum Protocol { C, P }

    [Flags]
    public enum FilePerms { Read, Write, Delete, Append, None }

    [Flags]
    public enum DirectoryPerms { Create, Delete, List, ListSub, None }
}
