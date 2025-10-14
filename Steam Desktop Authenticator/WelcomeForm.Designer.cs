namespace Steam_Desktop_Authenticator
{
    partial class WelcomeForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
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
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(WelcomeForm));
            label1 = new System.Windows.Forms.Label();
            btnImportConfig = new System.Windows.Forms.Button();
            label2 = new System.Windows.Forms.Label();
            btnJustStart = new System.Windows.Forms.Button();
            tableLayoutPanel1 = new System.Windows.Forms.TableLayoutPanel();
            tableLayoutPanel1.SuspendLayout();
            SuspendLayout();
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Dock = System.Windows.Forms.DockStyle.Fill;
            label1.Font = new System.Drawing.Font("Segoe UI", 18F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            label1.Location = new System.Drawing.Point(3, 0);
            label1.MinimumSize = new System.Drawing.Size(500, 100);
            label1.Name = "label1";
            label1.Size = new System.Drawing.Size(532, 100);
            label1.TabIndex = 0;
            label1.Text = "Welcome to\r\nSteam Desktop Authenticator";
            label1.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // btnImportConfig
            // 
            btnImportConfig.Anchor = System.Windows.Forms.AnchorStyles.None;
            btnImportConfig.AutoSize = true;
            btnImportConfig.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            btnImportConfig.Font = new System.Drawing.Font("Segoe UI", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            btnImportConfig.Location = new System.Drawing.Point(61, 135);
            btnImportConfig.MinimumSize = new System.Drawing.Size(400, 100);
            btnImportConfig.Name = "btnImportConfig";
            btnImportConfig.Size = new System.Drawing.Size(416, 100);
            btnImportConfig.TabIndex = 1;
            btnImportConfig.Text = "I already setup Steam Desktop Authenticator \r\nin another location on this PC and \r\nI want to import its account(s).";
            btnImportConfig.UseVisualStyleBackColor = true;
            btnImportConfig.Click += btnImportConfig_Click;
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Dock = System.Windows.Forms.DockStyle.Fill;
            label2.Font = new System.Drawing.Font("Segoe UI", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            label2.Location = new System.Drawing.Point(3, 100);
            label2.MinimumSize = new System.Drawing.Size(300, 32);
            label2.Name = "label2";
            label2.Size = new System.Drawing.Size(532, 32);
            label2.TabIndex = 2;
            label2.Text = "Select an item to get started:";
            label2.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // btnJustStart
            // 
            btnJustStart.Anchor = System.Windows.Forms.AnchorStyles.None;
            btnJustStart.AutoSize = true;
            btnJustStart.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            btnJustStart.Font = new System.Drawing.Font("Segoe UI", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            btnJustStart.Location = new System.Drawing.Point(65, 253);
            btnJustStart.MinimumSize = new System.Drawing.Size(400, 75);
            btnJustStart.Name = "btnJustStart";
            btnJustStart.Size = new System.Drawing.Size(407, 75);
            btnJustStart.TabIndex = 4;
            btnJustStart.Text = "This is my first time and \r\nI just want to sign into my Steam Account(s).";
            btnJustStart.UseVisualStyleBackColor = true;
            btnJustStart.Click += btnJustStart_Click;
            // 
            // tableLayoutPanel1
            // 
            tableLayoutPanel1.AutoSize = true;
            tableLayoutPanel1.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            tableLayoutPanel1.ColumnCount = 1;
            tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            tableLayoutPanel1.Controls.Add(label1, 0, 0);
            tableLayoutPanel1.Controls.Add(btnJustStart, 0, 3);
            tableLayoutPanel1.Controls.Add(label2, 0, 1);
            tableLayoutPanel1.Controls.Add(btnImportConfig, 0, 2);
            tableLayoutPanel1.Dock = System.Windows.Forms.DockStyle.Fill;
            tableLayoutPanel1.Location = new System.Drawing.Point(0, 0);
            tableLayoutPanel1.Name = "tableLayoutPanel1";
            tableLayoutPanel1.RowCount = 4;
            tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanel1.Size = new System.Drawing.Size(538, 344);
            tableLayoutPanel1.TabIndex = 5;
            // 
            // WelcomeForm
            // 
            AutoScaleDimensions = new System.Drawing.SizeF(144F, 144F);
            AutoScaleMode = System.Windows.Forms.AutoScaleMode.Dpi;
            AutoSize = true;
            AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            ClientSize = new System.Drawing.Size(538, 344);
            Controls.Add(tableLayoutPanel1);
            Font = new System.Drawing.Font("Segoe UI", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            Icon = (System.Drawing.Icon)resources.GetObject("$this.Icon");
            MaximizeBox = false;
            Name = "WelcomeForm";
            StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            Text = "Steam Desktop Authenticator";
            tableLayoutPanel1.ResumeLayout(false);
            tableLayoutPanel1.PerformLayout();
            ResumeLayout(false);
            PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Button btnImportConfig;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Button btnJustStart;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel1;
    }
}