
namespace DLLInject
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent() {
            components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            button1 = new System.Windows.Forms.Button();
            button2 = new System.Windows.Forms.Button();
            textBox1 = new System.Windows.Forms.TextBox();
            label1 = new System.Windows.Forms.Label();
            label2 = new System.Windows.Forms.Label();
            notifyIcon1 = new System.Windows.Forms.NotifyIcon(components);
            contextMenuStrip1 = new System.Windows.Forms.ContextMenuStrip(components);
            InjectToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            LoadDllFileToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            UnInjectToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            ExitToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            combo_box_dll_lists = new System.Windows.Forms.ComboBox();
            contextMenuStrip1.SuspendLayout();
            SuspendLayout();
            // 
            // button1
            // 
            button1.Location = new System.Drawing.Point(12, 12);
            button1.Name = "button1";
            button1.Size = new System.Drawing.Size(75, 23);
            button1.TabIndex = 0;
            button1.Text = "注入";
            button1.UseVisualStyleBackColor = true;
            button1.Click += button1_Click;
            button1.MouseDown += button1_MouseDown;
            // 
            // button2
            // 
            button2.Location = new System.Drawing.Point(12, 41);
            button2.Name = "button2";
            button2.Size = new System.Drawing.Size(75, 23);
            button2.TabIndex = 0;
            button2.Text = "DLL选择";
            button2.UseVisualStyleBackColor = true;
            button2.Click += button2_Click;
            // 
            // textBox1
            // 
            textBox1.Location = new System.Drawing.Point(93, 12);
            textBox1.Name = "textBox1";
            textBox1.Size = new System.Drawing.Size(211, 23);
            textBox1.TabIndex = 1;
            // 
            // label1
            // 
            label1.AllowDrop = true;
            label1.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            label1.Location = new System.Drawing.Point(12, 67);
            label1.Name = "label1";
            label1.Size = new System.Drawing.Size(292, 38);
            label1.TabIndex = 2;
            label1.Text = "未选择DLL 可尝试拖放";
            label1.DragDrop += label1_DragDrop;
            label1.DragEnter += label1_DragEnter;
            // 
            // label2
            // 
            label2.Font = new System.Drawing.Font("Microsoft YaHei UI", 9F, System.Drawing.FontStyle.Bold);
            label2.Location = new System.Drawing.Point(12, 112);
            label2.Name = "label2";
            label2.Size = new System.Drawing.Size(292, 23);
            label2.TabIndex = 3;
            label2.Text = "未发现被注入程序";
            label2.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // notifyIcon1
            // 
            notifyIcon1.ContextMenuStrip = contextMenuStrip1;
            notifyIcon1.Icon = (System.Drawing.Icon)resources.GetObject("notifyIcon1.Icon");
            notifyIcon1.Text = "PalletsIcon";
            notifyIcon1.Visible = true;
            notifyIcon1.Click += notifyIcon1_Click;
            // 
            // contextMenuStrip1
            // 
            contextMenuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] { InjectToolStripMenuItem, LoadDllFileToolStripMenuItem, UnInjectToolStripMenuItem, ExitToolStripMenuItem });
            contextMenuStrip1.Name = "contextMenuStrip1";
            contextMenuStrip1.Size = new System.Drawing.Size(101, 92);
            // 
            // InjectToolStripMenuItem
            // 
            InjectToolStripMenuItem.Name = "InjectToolStripMenuItem";
            InjectToolStripMenuItem.Size = new System.Drawing.Size(100, 22);
            InjectToolStripMenuItem.Text = "注入";
            InjectToolStripMenuItem.Click += InjectToolStripMenuItem_Click;
            // 
            // LoadDllFileToolStripMenuItem
            // 
            LoadDllFileToolStripMenuItem.Name = "LoadDllFileToolStripMenuItem";
            LoadDllFileToolStripMenuItem.Size = new System.Drawing.Size(100, 22);
            LoadDllFileToolStripMenuItem.Text = "载入";
            LoadDllFileToolStripMenuItem.Click += LoadDllFileToolStripMenuItem_Click;
            // 
            // UnInjectToolStripMenuItem
            // 
            UnInjectToolStripMenuItem.Name = "UnInjectToolStripMenuItem";
            UnInjectToolStripMenuItem.Size = new System.Drawing.Size(100, 22);
            UnInjectToolStripMenuItem.Text = "卸载";
            UnInjectToolStripMenuItem.Click += UnInjectToolStripMenuItem_Click;
            // 
            // ExitToolStripMenuItem
            // 
            ExitToolStripMenuItem.Name = "ExitToolStripMenuItem";
            ExitToolStripMenuItem.Size = new System.Drawing.Size(100, 22);
            ExitToolStripMenuItem.Text = "退出";
            ExitToolStripMenuItem.Click += ExitToolStripMenuItem_Click;
            // 
            // combo_box_dll_lists
            // 
            combo_box_dll_lists.DisplayMember = "FileName";
            combo_box_dll_lists.FormattingEnabled = true;
            combo_box_dll_lists.Location = new System.Drawing.Point(93, 39);
            combo_box_dll_lists.Name = "combo_box_dll_lists";
            combo_box_dll_lists.Size = new System.Drawing.Size(211, 25);
            combo_box_dll_lists.TabIndex = 4;
            combo_box_dll_lists.ValueMember = "FilePath";
            combo_box_dll_lists.SelectedIndexChanged += combo_box_dll_lists_SelectedIndexChanged;
            // 
            // Form1
            // 
            AutoScaleDimensions = new System.Drawing.SizeF(7F, 17F);
            AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            ClientSize = new System.Drawing.Size(316, 138);
            Controls.Add(combo_box_dll_lists);
            Controls.Add(label2);
            Controls.Add(label1);
            Controls.Add(textBox1);
            Controls.Add(button2);
            Controls.Add(button1);
            Icon = (System.Drawing.Icon)resources.GetObject("$this.Icon");
            MaximizeBox = false;
            Name = "Form1";
            ShowInTaskbar = false;
            StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            Text = "DLL注入器";
            TopMost = true;
            Load += Form1_Load;
            contextMenuStrip1.ResumeLayout(false);
            ResumeLayout(false);
            PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.Button button2;
        private System.Windows.Forms.TextBox textBox1;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.NotifyIcon notifyIcon1;
        private System.Windows.Forms.ContextMenuStrip contextMenuStrip1;
        private System.Windows.Forms.ToolStripMenuItem InjectToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem LoadDllFileToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem UnInjectToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem ExitToolStripMenuItem;
        private System.Windows.Forms.ComboBox combo_box_dll_lists;
    }
}

