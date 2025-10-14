namespace Steam_Desktop_Authenticator
{
    partial class TradePopupForm
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(TradePopupForm));
            lblDesc = new System.Windows.Forms.Label();
            btnDeny = new System.Windows.Forms.Button();
            btnAccept = new System.Windows.Forms.Button();
            lblStatus = new System.Windows.Forms.Label();
            lblAccount = new System.Windows.Forms.Label();
            tableLayoutPanel1 = new System.Windows.Forms.TableLayoutPanel();
            tableLayoutPanel1.SuspendLayout();
            SuspendLayout();
            // 
            // lblDesc
            // 
            lblDesc.AutoSize = true;
            tableLayoutPanel1.SetColumnSpan(lblDesc, 2);
            lblDesc.Dock = System.Windows.Forms.DockStyle.Fill;
            lblDesc.Font = new System.Drawing.Font("Segoe UI", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            lblDesc.Location = new System.Drawing.Point(3, 36);
            lblDesc.Name = "lblDesc";
            lblDesc.Size = new System.Drawing.Size(174, 36);
            lblDesc.TabIndex = 1;
            lblDesc.Text = "trade description";
            lblDesc.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // btnDeny
            // 
            btnDeny.Anchor = System.Windows.Forms.AnchorStyles.None;
            btnDeny.AutoSize = true;
            btnDeny.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            btnDeny.BackColor = System.Drawing.Color.FromArgb(255, 192, 192);
            btnDeny.Font = new System.Drawing.Font("Segoe UI", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            btnDeny.Location = new System.Drawing.Point(15, 111);
            btnDeny.Name = "btnDeny";
            btnDeny.Size = new System.Drawing.Size(59, 30);
            btnDeny.TabIndex = 2;
            btnDeny.Text = "Deny";
            btnDeny.UseVisualStyleBackColor = false;
            btnDeny.Click += btnDeny_Click;
            // 
            // btnAccept
            // 
            btnAccept.Anchor = System.Windows.Forms.AnchorStyles.None;
            btnAccept.AutoSize = true;
            btnAccept.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            btnAccept.BackColor = System.Drawing.Color.FromArgb(192, 255, 192);
            btnAccept.Font = new System.Drawing.Font("Segoe UI", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            btnAccept.Location = new System.Drawing.Point(99, 111);
            btnAccept.Name = "btnAccept";
            btnAccept.Size = new System.Drawing.Size(72, 30);
            btnAccept.TabIndex = 2;
            btnAccept.Text = "Accept";
            btnAccept.UseVisualStyleBackColor = false;
            btnAccept.Click += btnAccept_Click;
            // 
            // lblStatus
            // 
            tableLayoutPanel1.SetColumnSpan(lblStatus, 2);
            lblStatus.Dock = System.Windows.Forms.DockStyle.Fill;
            lblStatus.Font = new System.Drawing.Font("Segoe UI", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            lblStatus.Location = new System.Drawing.Point(3, 72);
            lblStatus.Name = "lblStatus";
            lblStatus.Size = new System.Drawing.Size(174, 36);
            lblStatus.TabIndex = 3;
            lblStatus.Text = "status";
            lblStatus.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // lblAccount
            // 
            lblAccount.AutoSize = true;
            tableLayoutPanel1.SetColumnSpan(lblAccount, 2);
            lblAccount.Dock = System.Windows.Forms.DockStyle.Fill;
            lblAccount.Font = new System.Drawing.Font("Segoe UI", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            lblAccount.Location = new System.Drawing.Point(3, 0);
            lblAccount.Name = "lblAccount";
            lblAccount.Size = new System.Drawing.Size(174, 36);
            lblAccount.TabIndex = 4;
            lblAccount.Text = "account name";
            lblAccount.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // tableLayoutPanel1
            // 
            tableLayoutPanel1.AutoSize = true;
            tableLayoutPanel1.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            tableLayoutPanel1.ColumnCount = 2;
            tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 50F));
            tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 50F));
            tableLayoutPanel1.Controls.Add(lblAccount, 0, 0);
            tableLayoutPanel1.Controls.Add(btnAccept, 1, 3);
            tableLayoutPanel1.Controls.Add(lblStatus, 0, 2);
            tableLayoutPanel1.Controls.Add(btnDeny, 0, 3);
            tableLayoutPanel1.Controls.Add(lblDesc, 0, 1);
            tableLayoutPanel1.Dock = System.Windows.Forms.DockStyle.Fill;
            tableLayoutPanel1.Location = new System.Drawing.Point(0, 0);
            tableLayoutPanel1.Name = "tableLayoutPanel1";
            tableLayoutPanel1.RowCount = 4;
            tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 25F));
            tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 25F));
            tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 25F));
            tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 25F));
            tableLayoutPanel1.Size = new System.Drawing.Size(180, 144);
            tableLayoutPanel1.TabIndex = 5;
            // 
            // TradePopupForm
            // 
            AutoScaleDimensions = new System.Drawing.SizeF(144F, 144F);
            AutoScaleMode = System.Windows.Forms.AutoScaleMode.Dpi;
            AutoSize = true;
            AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            ClientSize = new System.Drawing.Size(180, 144);
            Controls.Add(tableLayoutPanel1);
            Font = new System.Drawing.Font("Segoe UI", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedToolWindow;
            Icon = (System.Drawing.Icon)resources.GetObject("$this.Icon");
            Name = "TradePopupForm";
            Text = "New confirmation";
            TopMost = true;
            Load += TradePopupForm_Load;
            tableLayoutPanel1.ResumeLayout(false);
            tableLayoutPanel1.PerformLayout();
            ResumeLayout(false);
            PerformLayout();

        }

        #endregion
        private System.Windows.Forms.Label lblDesc;
        private System.Windows.Forms.Button btnDeny;
        private System.Windows.Forms.Button btnAccept;
        private System.Windows.Forms.Label lblStatus;
        private System.Windows.Forms.Label lblAccount;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel1;
    }
}