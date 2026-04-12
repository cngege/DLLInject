using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DLLInject.data {
    internal class FileItem {
        public string FileName { get; set; }
        public string FilePath { get; set; }

        public FileItem(string name, string path) {
            FileName = name;
            FilePath = path;
        }

        public FileItem(string path) {
            FilePath = path;
            FileName = Path.GetFileName(path);
        }
    }
}
