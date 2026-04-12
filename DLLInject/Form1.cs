using DLLInject.data;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Tools.Address;
using Tools.Fileoperate;
using static System.Windows.Forms.VisualStyles.VisualStyleElement;

namespace DLLInject
{
    public partial class Form1 : Form {
        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint PAGE_READWRITE = 0x04;
        // Win32 API声明
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr GetModuleHandleA(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out int lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetExitCodeThread(IntPtr hThread, out IntPtr lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint GetLastError();

        // 封装WriteValue_bytes（补全你缺失的实现）
        public static bool WriteValue_bytes(IntPtr address, byte[] data, IntPtr hProcess) {
            return WriteProcessMemory(hProcess, address, data, (uint)data.Length, out _);
        }

        InIFile config;
        BindingList<FileItem> dll_lists = new();
        readonly string[] args;


        public Form1(string[] args) {
            this.args = args;
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e) {
            this.MinimumSize = this.Size;
            this.MaximumSize = this.Size;
            if (File.Exists(Path.Combine(Application.StartupPath, "config.ini"))) {
                config = new InIFile(Path.Combine(Application.StartupPath, "config.ini"));
                textBox1.Text = config.Read("Main", "Filename", "Minecraft.Windows");
                label1.Text = config.Read("Main", "PATH", "未选择DLL");
            } else {
                config = new InIFile(Path.Combine(System.Environment.GetEnvironmentVariable("TEMP"), "config.ini"));
                //Application.ExecutablePath
                textBox1.Text = config.Read(Application.ExecutablePath, "Filename", "Minecraft.Windows");
                label1.Text = config.Read(Application.ExecutablePath, "PATH", "未选择DLL");
            }
            // 读取列表
            string lists_ = config.Read(Application.ExecutablePath, "DllLists", "");
            string select_ = config.Read(Application.ExecutablePath, "CurrentSelect", "0");
            int select = int.Parse(select_);

            dll_lists = new BindingList<FileItem>(lists_.Split(",").Where(path => !string.IsNullOrWhiteSpace(path)).Select(path => new FileItem(path)).ToList());

            if (args.Length >= 1) {
                if (args[0].ToLower().EndsWith(".dll")) {
                    if (!dll_lists.Contains(new FileItem(args[0]))) {
                        dll_lists.Add(new FileItem(args[0]));
                        config.Write(Application.ExecutablePath, "DllLists", string.Join(",", dll_lists.Select(item => item.FilePath)));
                        //更新下拉列表框
                    }
                    label1.Text = args[0];
                    if (File.Exists(Path.Combine(Application.StartupPath, "config.ini"))) {
                        config.Write("Main", "PATH", args[0]);
                    } else {
                        config.Write(Application.ExecutablePath, "PATH", args[0]);
                    }
                }
            }
            combo_box_dll_lists.DataSource = dll_lists;
            if (select < dll_lists.Count) {
                combo_box_dll_lists.SelectedIndex = select;
            } else {
                combo_box_dll_lists.SelectedIndex = dll_lists.Count - 1;
            }
        }

        // 选择按钮点击事件 选择DLL
        private void button2_Click(object sender, EventArgs e) {
            var loadFile = new OpenFileDialog();
            loadFile.Filter = "所有DLL文件|*.dll";//设置文件类型
            loadFile.Title = "选择要注入的dll";//设置标题
            //loadFile.AddExtension = true;//是否自动增加所辍名
            loadFile.AutoUpgradeEnabled = true;//是否随系统升级而升级外观
            loadFile.Multiselect = false;       //是否可以多选
            if (loadFile.ShowDialog() == DialogResult.OK) {
                label1.Text = loadFile.FileName;
                if (File.Exists(Path.Combine(Application.StartupPath, "config.ini"))) {
                    config.Write("Main", "PATH", loadFile.FileName);
                } else {
                    config.Write(Application.ExecutablePath, "PATH", loadFile.FileName);
                }
                var index = dll_lists.ToList().FindIndex(item => item.FilePath == loadFile.FileName);
                if (index == -1) {
                    index = dll_lists.Count;
                    dll_lists.Add(new FileItem(loadFile.FileName));
                    config.Write(Application.ExecutablePath, "DllLists", string.Join(",", dll_lists.Select(item => item.FilePath)));
                }
                if (dll_lists.Count > 0) combo_box_dll_lists.SelectedIndex = index;
                config.Write(Application.ExecutablePath, "CurrentSelect", index.ToString());
            }
        }

        //注入 按钮
        private void button1_Click(object sender, EventArgs e) {
            if (File.Exists(Path.Combine(Application.StartupPath, "config.ini"))) {
                config.Write("Main", "Filename", textBox1.Text);
            } else {
                config.Write(Application.ExecutablePath, "Filename", textBox1.Text);
            }
            if (textBox1.Text != "" && File.Exists(label1.Text)) {
                Inject();
            }
        }

        //判断鼠标右键
        private void button1_MouseDown(object sender, MouseEventArgs e) {
            if (e.Button == MouseButtons.Right) {
                if (MessageBox.Show("是否要从目标进程中卸载该dll", "", MessageBoxButtons.OKCancel, MessageBoxIcon.Warning) == DialogResult.OK) {
                    UnInject();
                    MessageBox.Show("已经尝试卸载dll");
                }
            }
        }

        //注入处理函数
        void Inject() {
            try {
                int pid = Address.GetPid(textBox1.Text);
                if (pid == 0) {
                    label2.Text = $"未找到和{textBox1.Text}有关的程序";
                } else {
                    // 检查是否是UWP程序
                    CheckUWP(Process.GetProcessById(pid).MainModule.FileName, label1.Text);

                    label2.Text = $"找到进程|PID:{pid}|尝试注入...";
                    IntPtr hProcess = Address.OpenProcess(0x1F0FFF, false, pid);
                    if (hProcess == IntPtr.Zero) {
                        label2.Text = $"找到进程|PID:{pid}|错误码:{GetLastError()}";
                        Address.CloseHandle(hProcess);
                        return;
                    }


                    if (CheckExistUnicode(label1.Text)) {
                        byte[] dllpath = Encoding.Unicode.GetBytes(label1.Text);
                        IntPtr applyptr = Address.VirtualAllocEx(hProcess, IntPtr.Zero, dllpath.Length + 1, Address.MEM_COMMIT, Address.PAGE_READWRITE);
                        if (applyptr == IntPtr.Zero) {
                            label2.Text = $"找到进程|PID:{pid}|申请一段内存失败";
                            Address.CloseHandle(hProcess);
                            return;
                        }
                        Address.WriteValue_bytes(applyptr, dllpath, hProcess);
                        IntPtr Thread_LLW = CreateRemoteThread(hProcess, IntPtr.Zero, 0, GetProcAddress(Address.GetModuleHandleA("Kernel32"), "LoadLibraryW"), applyptr, 0, out int threadid);
                        if (Thread_LLW == IntPtr.Zero) {
                            label2.Text = $"找到进程|PID:{pid}|创建远程线程失败";
                            Address.CloseHandle(hProcess);
                            return;
                        }
                        _ = WaitForSingleObject(Thread_LLW, int.MaxValue);
                        if (!GetExitCodeThread(Thread_LLW, out IntPtr ExitCode)) {
                            label2.Text = $"找到进程|PID:{pid}|获取退出代码失败";
                            Address.CloseHandle(hProcess);
                            return;
                        }
                        if (ExitCode == IntPtr.Zero) {
                            label2.Text = $"找到进程|PID:{pid}|远程调用LoadLibraryW错误";
                            Address.CloseHandle(hProcess);
                            MessageBox.Show("GetLastError :" + GetLastError());
                            return;
                        }
                    } else {
                        //byte[] dllpath = Encoding.Default.GetBytes(label1.Text);
                        byte[] dllpath = Encoding.UTF8.GetBytes(label1.Text.Trim());

                        byte[] dllPathWithNull = new byte[dllpath.Length + 1];
                        Array.Copy(dllpath, dllPathWithNull, dllpath.Length);
                        dllPathWithNull[dllpath.Length] = 0;

                        IntPtr applyptr = Address.VirtualAllocEx(hProcess, IntPtr.Zero, dllPathWithNull.Length, Address.MEM_COMMIT | Address.MEM_RESERVE, Address.PAGE_READWRITE);
                        if (applyptr == IntPtr.Zero) {
                            label2.Text = $"找到进程|PID:{pid}|申请一段内存失败|错误码:{GetLastError()}";
                            Address.CloseHandle(hProcess);
                            return;
                        }

                        Address.WriteValue_bytes(applyptr, dllPathWithNull, hProcess);
                        IntPtr Thread_LLA = CreateRemoteThread(hProcess, IntPtr.Zero, 0, GetProcAddress(Address.GetModuleHandleA("Kernel32"), "LoadLibraryA"), applyptr, 0, out int threadid);
                        if (Thread_LLA == IntPtr.Zero) {
                            label2.Text = $"找到进程|PID:{pid}|创建远程线程失败";
                            Address.CloseHandle(hProcess);
                            return;
                        }
                        _ = WaitForSingleObject(Thread_LLA, int.MaxValue);
                        if (!GetExitCodeThread(Thread_LLA, out IntPtr ExitCode)) {
                            label2.Text = $"找到进程|PID:{pid}|获取退出代码失败";
                            Address.CloseHandle(hProcess);
                            return;
                        }
                        if (ExitCode == IntPtr.Zero) {
                            label2.Text = $"找到进程|PID:{pid}|远程调用LoadLibraryA错误";
                            Address.CloseHandle(hProcess);
                            MessageBox.Show("GetLastError :" + GetLastError());
                            return;
                        }
                    }

                    //这里不要释放  不要释放，你刚启动线程就释放了，你怎么知道人家有没有开始读取
                    //Address.VirtualFreeEx(hProcess,applyptr,0,Address.MEM_RELEASE);
                    Address.CloseHandle(hProcess);
                    label2.Text = $"找到进程|PID:{pid}|注入成功";
                }
            } catch (Exception e) {

                MessageBox.Show(e.Message, "注入错误");
            }

        }

        //卸载处理函数
        void UnInject() {
            try {
                int pid = Address.GetPid(textBox1.Text);
                if (pid == 0) {
                    label2.Text = $"未找到和{textBox1.Text}有关的程序";
                } else {
                    label2.Text = $"找到进程|PID:{pid}|尝试卸载...";
                    IntPtr hProcess = Address.OpenProcess(0x1F0FFF, false, pid);
                    if (hProcess == IntPtr.Zero) {
                        label2.Text = $"找到进程|PID:{pid}|创建进程句柄失败";
                        Address.CloseHandle(hProcess);
                        return;
                    }

                    IntPtr ModulePtr = GetModuleAddr(pid, label1.Text);

                    if (ModulePtr == IntPtr.Zero) {
                        label2.Text = $"找到进程|PID:{pid}|获取模块地址失败";
                        Address.CloseHandle(hProcess);
                        return;
                    }
                    IntPtr ThreadFree = CreateRemoteThread(hProcess, IntPtr.Zero, 0, GetProcAddress(Address.GetModuleHandleA("Kernel32"), "FreeLibrary"), ModulePtr, 0, out int threadidfree);
                    if (ThreadFree == IntPtr.Zero) {
                        label2.Text = $"找到进程|PID:{pid}|创建远程线程B失败";
                        Address.CloseHandle(hProcess);
                        return;
                    }

                    _ = WaitForSingleObject(ThreadFree, int.MaxValue);
                    if (!GetExitCodeThread(ThreadFree, out IntPtr ExitCode_Free)) {
                        label2.Text = $"找到进程|PID:{pid}|无法获得线程退出代码";
                        Address.CloseHandle(hProcess);
                        return;
                    }
                    if (ExitCode_Free == IntPtr.Zero) {
                        label2.Text = $"找到进程|PID:{pid}|远程调用FreeLibrary错误";
                        Address.CloseHandle(hProcess);
                        return;
                    }

                    //这里不要释放  不要释放，你刚启动线程就释放了，你怎么知道人家有没有开始读取
                    //Address.VirtualFreeEx(hProcess,applyptr,0,Address.MEM_RELEASE);
                    Address.CloseHandle(hProcess);
                    label2.Text = $"找到进程|PID:{pid}|卸载成功";
                }
            } catch (Exception e) {
                MessageBox.Show(e.Message, "远程卸载错误");
            }

        }

        private void label1_DragDrop(object sender, DragEventArgs e) {
            string path = ((System.Array)e.Data.GetData(DataFormats.FileDrop)).GetValue(0).ToString();       //获得路径
            if (path.ToLower().EndsWith(".dll")) {
                label1.Text = path;
                if (File.Exists(Application.StartupPath + "config.ini")) {
                    config.Write("Main", "PATH", path);
                } else {
                    config.Write(Application.ExecutablePath, "PATH", path);
                }
                dll_lists.Add(new FileItem(path));
                config.Write(Application.ExecutablePath, "DllLists", string.Join(",", dll_lists));
            }
        }

        static void CheckUWP(string exePath, string dllPath) {
            //C:\Program Files\WindowsApps\Microsoft.MinecraftUWP_1.20.1201.0_x64__8wekyb3d8bbwe
            if (exePath.IndexOf("\\WindowsApps\\") > 0) {
                // 是UWP程序
                FileInfo fileInfo = new FileInfo(dllPath);
                var fileSecurity = fileInfo.GetAccessControl();
                fileSecurity.AddAccessRule(new FileSystemAccessRule("ALL APPLICATION PACKAGES", FileSystemRights.FullControl, AccessControlType.Allow));
                fileInfo.SetAccessControl(fileSecurity);
            }
        }

        private void label1_DragEnter(object sender, DragEventArgs e) {
            if (e.Data.GetDataPresent(DataFormats.FileDrop)) {
                string path = ((System.Array)e.Data.GetData(DataFormats.FileDrop)).GetValue(0).ToString();       //获得路径
                if (path.ToLower().EndsWith(".dll")) e.Effect = DragDropEffects.Link;
            } else {
                e.Effect = DragDropEffects.None;
            }
        }

        /// <summary>
        /// 检查字符串是否是 Unicode格式
        /// </summary>
        /// <param name="strInput"></param>
        /// <returns></returns>
        public static bool CheckExistUnicode(string strInput) {
            int i = strInput.Length;
            if (i == 0)
                return false;
            int j = System.Text.Encoding.Default.GetBytes(strInput).Length;
            if (i != j)
                return true;
            else
                return false;
        }

        /// <summary>
        /// 跨进程获取其中的模块地址
        /// </summary>
        /// <param name="pid">进程PID</param>
        /// <param name="path">模块路径名,或单独的名字</param>
        /// <returns></returns>
        public static IntPtr GetModuleAddr(int pid, string path) {
            Process processById = Process.GetProcessById(pid);      // 如果没有这样的一个进程 则抛出一个异常
            for (int i = 0; i < processById.Modules.Count; i++) {
                if (processById.Modules[i].FileName == path || processById.Modules[i].ModuleName == path) {
                    return processById.Modules[i].BaseAddress;
                }
            }

            return IntPtr.Zero;
        }

        // 托盘右键菜单，注入按钮事件
        private void InjectToolStripMenuItem_Click(object sender, EventArgs e) {
            Inject();

        }
        // 托盘右键菜单，加载按钮事件
        private void LoadDllFileToolStripMenuItem_Click(object sender, EventArgs e) {
            button2_Click(null, null);
        }
        // 托盘右键菜单，卸载按钮事件
        private void UnInjectToolStripMenuItem_Click(object sender, EventArgs e) {
            if (MessageBox.Show("是否要从目标进程中卸载该dll", "", MessageBoxButtons.OKCancel, MessageBoxIcon.Warning) == DialogResult.OK) {
                UnInject();
            }
        }
        // 托盘右键菜单，退出按钮事件
        private void ExitToolStripMenuItem_Click(object sender, EventArgs e) {
            Application.Exit();
        }
        // 点击最小化时的事件
        protected override void WndProc(ref Message m) {
            if (m.WParam.ToInt64() == 0xF020)                //最小化
            {
                this.Hide();
                return;
            }
            base.WndProc(ref m);
        }

        //点击托盘图标
        private void notifyIcon1_Click(object sender, EventArgs e) {
            var Mouseevent = (MouseEventArgs)e;
            if (Mouseevent.Button == MouseButtons.Left) {
                if (this.Visible) {
                    this.Hide();
                } else {
                    this.Show();
                }
            }
        }

        /// <summary>
        /// 当下拉列表的值更改时触发
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void combo_box_dll_lists_SelectedIndexChanged(object sender, EventArgs e) {
            label1.Text = dll_lists[combo_box_dll_lists.SelectedIndex].FilePath;
            config.Write(Application.ExecutablePath, "CurrentSelect", combo_box_dll_lists.SelectedIndex.ToString());
        }
    }
}
