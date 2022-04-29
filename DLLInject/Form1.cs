using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using Tools.Address;
using Tools.Fileoperate;
using System.Runtime.InteropServices;

namespace DLLInject
{
    public partial class Form1 : Form
    {

        [DllImport("kernel32.dll")]
        public static extern int CreateRemoteThread(IntPtr hwnd, int attrib, int size, IntPtr address, IntPtr par, int flags, int threadid);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hwnd, string lpname);

        InIFile config;
        string[] args;
        public Form1(string[] args)
        {
            this.args = args;
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            this.MinimumSize = this.Size;
            this.MaximumSize = this.Size;
            config = new InIFile(Application.StartupPath + "config.ini");
            textBox1.Text = config.Read("Inject","Filename","Minecraft.Windows");
            label1.Text = config.Read("DLLPath","PATH","未选择DLL");
            if(args.Length >= 1)
            {
                if (args[0].ToLower().EndsWith(".dll"))
                {
                    label1.Text = args[0];
                    config.Write("DLLPath", "PATH", args[0]);
                }
            }
        }

        //选择DLL
        private void button2_Click(object sender, EventArgs e)
        {
            OpenFileDialog loadFile = new OpenFileDialog();
            loadFile.Filter = "所有DLL文件|*.dll";//设置文件类型
            loadFile.Title = "选择要注入的dll";//设置标题
            //loadFile.AddExtension = true;//是否自动增加所辍名
            loadFile.AutoUpgradeEnabled = true;//是否随系统升级而升级外观
            loadFile.Multiselect = false;       //是否可以多选
            if (loadFile.ShowDialog() == DialogResult.OK)
            {
                label1.Text = loadFile.FileName;
                config.Write("DLLPath","PATH", loadFile.FileName);
            }
        }

        //注入 按钮
        private void button1_Click(object sender, EventArgs e)
        {
            config.Write("Inject", "Filename", textBox1.Text);
            if (textBox1.Text != "" && File.Exists(label1.Text))
            {
                Inject();
            }
        }

        //注入处理函数
        void Inject()
        {
            try
            {
                int pid = Address.GetPid(textBox1.Text);
                if (pid == 0)
                {
                    label2.Text = $"未找到和{textBox1.Text}有关的程序";
                }
                else
                {
                    label2.Text = $"找到进程|{textBox1.Text}|PID:{pid}|尝试注入...";
                    IntPtr hProcess = Address.OpenProcess(0x1F0FFF, false, pid);
                    if (hProcess == IntPtr.Zero)
                    {
                        label2.Text = $"找到进程|{textBox1.Text}|PID:{pid}|创建进程句柄失败";
                        Address.CloseHandle(hProcess);
                        return;
                    }

                    IntPtr applyptr = Address.VirtualAllocEx(hProcess, IntPtr.Zero, label1.Text.Length + 1, Address.MEM_COMMIT | Address.MEM_RESERVE, Address.PAGE_READWRITE);
                    if (applyptr == IntPtr.Zero)
                    {
                        label2.Text = $"找到进程|{textBox1.Text}|PID:{pid}|申请一段内存失败";
                        Address.CloseHandle(hProcess);
                        return;
                    }

                    //byte[] dllpath = Encoding.ASCII.GetBytes(label1.Text);
                    byte[] dllpath = Encoding.Default.GetBytes(label1.Text);
                    Address.WriteValue_bytes(applyptr, dllpath, hProcess);
                    if (CreateRemoteThread(hProcess, 0, 0, GetProcAddress(Address.GetModuleHandleA("Kernel32"), "LoadLibraryA"), applyptr, 0, 0) == 0)
                    {
                        label2.Text = $"找到进程|{textBox1.Text}|PID:{pid}|创建远程线程失败";
                        Address.CloseHandle(hProcess);
                        return;
                    }
                    //这里不要释放  不要释放，你刚启动线程就释放了，你怎么知道人家有没有开始读取
                    //Address.VirtualFreeEx(hProcess,applyptr,0,Address.MEM_RELEASE);
                    Address.CloseHandle(hProcess);
                    label2.Text = $"找到进程|{textBox1.Text}|PID:{pid}|注入成功";
                }
            }
            catch (Exception e)
            {

                MessageBox.Show(e.Message, "注入错误");
            }

        }

        private void label1_DragDrop(object sender, DragEventArgs e)
        {
            string path = ((System.Array)e.Data.GetData(DataFormats.FileDrop)).GetValue(0).ToString();       //获得路径
            if (path.ToLower().EndsWith(".dll"))
            {
                label1.Text = path;
                config.Write("DLLPath", "PATH", path);
            }
        }

        private void label1_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string path = ((System.Array)e.Data.GetData(DataFormats.FileDrop)).GetValue(0).ToString();       //获得路径
                if (path.ToLower().EndsWith(".dll")) e.Effect = DragDropEffects.Link;
            }
            else
            {
                e.Effect = DragDropEffects.None;
            }
        }
    }
}
