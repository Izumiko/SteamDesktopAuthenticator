namespace Steam_Desktop_Authenticator
{
    partial class SettingsForm
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(SettingsForm));
            chkPeriodicChecking = new System.Windows.Forms.CheckBox();
            btnSave = new System.Windows.Forms.Button();
            numPeriodicInterval = new System.Windows.Forms.NumericUpDown();
            label1 = new System.Windows.Forms.Label();
            chkCheckAll = new System.Windows.Forms.CheckBox();
            chkConfirmMarket = new System.Windows.Forms.CheckBox();
            chkConfirmTrades = new System.Windows.Forms.CheckBox();
            tableLayoutPanel1 = new System.Windows.Forms.TableLayoutPanel();
            flowLayoutPanel1 = new System.Windows.Forms.FlowLayoutPanel();
            ((System.ComponentModel.ISupportInitialize)numPeriodicInterval).BeginInit();
            tableLayoutPanel1.SuspendLayout();
            flowLayoutPanel1.SuspendLayout();
            SuspendLayout();
            // 
            // chkPeriodicChecking
            // 
            chkPeriodicChecking.Anchor = System.Windows.Forms.AnchorStyles.Left;
            chkPeriodicChecking.AutoSize = true;
            chkPeriodicChecking.Location = new System.Drawing.Point(3, 3);
            chkPeriodicChecking.Name = "chkPeriodicChecking";
            chkPeriodicChecking.Size = new System.Drawing.Size(340, 50);
            chkPeriodicChecking.TabIndex = 0;
            chkPeriodicChecking.Text = "Periodically check for new confirmations\r\nand show a popup when they arrive";
            chkPeriodicChecking.UseVisualStyleBackColor = true;
            chkPeriodicChecking.CheckedChanged += chkPeriodicChecking_CheckedChanged;
            // 
            // btnSave
            // 
            btnSave.Anchor = System.Windows.Forms.AnchorStyles.None;
            btnSave.AutoSize = true;
            btnSave.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            btnSave.Font = new System.Drawing.Font("Segoe UI", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            btnSave.Location = new System.Drawing.Point(152, 210);
            btnSave.Name = "btnSave";
            btnSave.Size = new System.Drawing.Size(74, 42);
            btnSave.TabIndex = 1;
            btnSave.Text = "Save";
            btnSave.UseVisualStyleBackColor = true;
            btnSave.Click += btnSave_Click;
            // 
            // numPeriodicInterval
            // 
            numPeriodicInterval.Anchor = System.Windows.Forms.AnchorStyles.Left;
            numPeriodicInterval.Location = new System.Drawing.Point(3, 8);
            numPeriodicInterval.Minimum = new decimal(new int[] { 5, 0, 0, 0 });
            numPeriodicInterval.Name = "numPeriodicInterval";
            numPeriodicInterval.Size = new System.Drawing.Size(60, 29);
            numPeriodicInterval.TabIndex = 2;
            numPeriodicInterval.Value = new decimal(new int[] { 5, 0, 0, 0 });
            // 
            // label1
            // 
            label1.Anchor = System.Windows.Forms.AnchorStyles.Left;
            label1.AutoSize = true;
            label1.Location = new System.Drawing.Point(69, 0);
            label1.Name = "label1";
            label1.Size = new System.Drawing.Size(220, 46);
            label1.TabIndex = 3;
            label1.Text = "Seconds between checking \r\nfor confirmations";
            // 
            // chkCheckAll
            // 
            chkCheckAll.Anchor = System.Windows.Forms.AnchorStyles.Left;
            chkCheckAll.AutoSize = true;
            chkCheckAll.Location = new System.Drawing.Point(3, 111);
            chkCheckAll.Name = "chkCheckAll";
            chkCheckAll.Size = new System.Drawing.Size(312, 27);
            chkCheckAll.TabIndex = 4;
            chkCheckAll.Text = "Check all accounts for confirmations";
            chkCheckAll.UseVisualStyleBackColor = true;
            // 
            // chkConfirmMarket
            // 
            chkConfirmMarket.Anchor = System.Windows.Forms.AnchorStyles.Left;
            chkConfirmMarket.AutoSize = true;
            chkConfirmMarket.Location = new System.Drawing.Point(3, 144);
            chkConfirmMarket.Name = "chkConfirmMarket";
            chkConfirmMarket.Size = new System.Drawing.Size(293, 27);
            chkConfirmMarket.TabIndex = 5;
            chkConfirmMarket.Text = "Auto-confirm market transactions";
            chkConfirmMarket.UseVisualStyleBackColor = true;
            chkConfirmMarket.CheckedChanged += chkConfirmMarket_CheckedChanged;
            // 
            // chkConfirmTrades
            // 
            chkConfirmTrades.Anchor = System.Windows.Forms.AnchorStyles.Left;
            chkConfirmTrades.AutoSize = true;
            chkConfirmTrades.Location = new System.Drawing.Point(3, 177);
            chkConfirmTrades.Name = "chkConfirmTrades";
            chkConfirmTrades.Size = new System.Drawing.Size(190, 27);
            chkConfirmTrades.TabIndex = 6;
            chkConfirmTrades.Text = "Auto-confirm trades";
            chkConfirmTrades.UseVisualStyleBackColor = true;
            chkConfirmTrades.CheckedChanged += chkConfirmTrades_CheckedChanged;
            // 
            // tableLayoutPanel1
            // 
            tableLayoutPanel1.AutoSize = true;
            tableLayoutPanel1.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            tableLayoutPanel1.ColumnCount = 1;
            tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            tableLayoutPanel1.Controls.Add(btnSave, 0, 5);
            tableLayoutPanel1.Controls.Add(chkCheckAll, 0, 2);
            tableLayoutPanel1.Controls.Add(chkConfirmMarket, 0, 3);
            tableLayoutPanel1.Controls.Add(chkConfirmTrades, 0, 4);
            tableLayoutPanel1.Controls.Add(chkPeriodicChecking, 0, 0);
            tableLayoutPanel1.Controls.Add(flowLayoutPanel1, 0, 1);
            tableLayoutPanel1.Dock = System.Windows.Forms.DockStyle.Fill;
            tableLayoutPanel1.Location = new System.Drawing.Point(0, 0);
            tableLayoutPanel1.Name = "tableLayoutPanel1";
            tableLayoutPanel1.RowCount = 6;
            tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanel1.Size = new System.Drawing.Size(378, 254);
            tableLayoutPanel1.TabIndex = 7;
            // 
            // flowLayoutPanel1
            // 
            flowLayoutPanel1.AutoSize = true;
            flowLayoutPanel1.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            flowLayoutPanel1.Controls.Add(numPeriodicInterval);
            flowLayoutPanel1.Controls.Add(label1);
            flowLayoutPanel1.Dock = System.Windows.Forms.DockStyle.Fill;
            flowLayoutPanel1.Location = new System.Drawing.Point(3, 59);
            flowLayoutPanel1.Name = "flowLayoutPanel1";
            flowLayoutPanel1.Size = new System.Drawing.Size(372, 46);
            flowLayoutPanel1.TabIndex = 7;
            // 
            // SettingsForm
            // 
            AutoScaleDimensions = new System.Drawing.SizeF(144F, 144F);
            AutoScaleMode = System.Windows.Forms.AutoScaleMode.Dpi;
            AutoSize = true;
            AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            ClientSize = new System.Drawing.Size(378, 254);
            Controls.Add(tableLayoutPanel1);
            Font = new System.Drawing.Font("Segoe UI", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            Icon = (System.Drawing.Icon)resources.GetObject("$this.Icon");
            MaximizeBox = false;
            Name = "SettingsForm";
            StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            Text = "Settings";
            ((System.ComponentModel.ISupportInitialize)numPeriodicInterval).EndInit();
            tableLayoutPanel1.ResumeLayout(false);
            tableLayoutPanel1.PerformLayout();
            flowLayoutPanel1.ResumeLayout(false);
            flowLayoutPanel1.PerformLayout();
            ResumeLayout(false);
            PerformLayout();

        }

        #endregion

        private System.Windows.Forms.CheckBox chkPeriodicChecking;
        private System.Windows.Forms.Button btnSave;
        private System.Windows.Forms.NumericUpDown numPeriodicInterval;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.CheckBox chkCheckAll;
        private System.Windows.Forms.CheckBox chkConfirmMarket;
        private System.Windows.Forms.CheckBox chkConfirmTrades;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel1;
        private System.Windows.Forms.FlowLayoutPanel flowLayoutPanel1;
    }
}