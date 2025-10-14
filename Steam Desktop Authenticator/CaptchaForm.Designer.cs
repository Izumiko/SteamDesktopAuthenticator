namespace Steam_Desktop_Authenticator
{
    partial class CaptchaForm
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(CaptchaForm));
            labelText = new System.Windows.Forms.Label();
            txtBox = new System.Windows.Forms.TextBox();
            btnAccept = new System.Windows.Forms.Button();
            btnCancel = new System.Windows.Forms.Button();
            pictureBoxCaptcha = new System.Windows.Forms.PictureBox();
            tableLayoutPanel1 = new System.Windows.Forms.TableLayoutPanel();
            ((System.ComponentModel.ISupportInitialize)pictureBoxCaptcha).BeginInit();
            tableLayoutPanel1.SuspendLayout();
            SuspendLayout();
            // 
            // labelText
            // 
            labelText.AutoSize = true;
            tableLayoutPanel1.SetColumnSpan(labelText, 2);
            labelText.Dock = System.Windows.Forms.DockStyle.Fill;
            labelText.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            labelText.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            labelText.ForeColor = System.Drawing.SystemColors.ControlText;
            labelText.Location = new System.Drawing.Point(3, 0);
            labelText.Name = "labelText";
            labelText.Size = new System.Drawing.Size(229, 50);
            labelText.TabIndex = 0;
            labelText.Text = "Please enter the following captcha code:";
            labelText.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // txtBox
            // 
            tableLayoutPanel1.SetColumnSpan(txtBox, 2);
            txtBox.Dock = System.Windows.Forms.DockStyle.Fill;
            txtBox.Font = new System.Drawing.Font("Segoe UI", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            txtBox.Location = new System.Drawing.Point(3, 124);
            txtBox.Name = "txtBox";
            txtBox.Size = new System.Drawing.Size(229, 45);
            txtBox.TabIndex = 1;
            // 
            // btnAccept
            // 
            btnAccept.Anchor = System.Windows.Forms.AnchorStyles.Left;
            btnAccept.AutoSize = true;
            btnAccept.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            btnAccept.Location = new System.Drawing.Point(3, 175);
            btnAccept.Name = "btnAccept";
            btnAccept.Size = new System.Drawing.Size(74, 33);
            btnAccept.TabIndex = 2;
            btnAccept.Text = "Submit";
            btnAccept.UseVisualStyleBackColor = true;
            btnAccept.Click += btnAccept_Click;
            // 
            // btnCancel
            // 
            btnCancel.Anchor = System.Windows.Forms.AnchorStyles.Right;
            btnCancel.AutoSize = true;
            btnCancel.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            btnCancel.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            btnCancel.Location = new System.Drawing.Point(161, 175);
            btnCancel.Name = "btnCancel";
            btnCancel.Size = new System.Drawing.Size(71, 33);
            btnCancel.TabIndex = 3;
            btnCancel.Text = "Cancel";
            btnCancel.UseVisualStyleBackColor = true;
            btnCancel.Click += btnCancel_Click;
            // 
            // pictureBoxCaptcha
            // 
            tableLayoutPanel1.SetColumnSpan(pictureBoxCaptcha, 2);
            pictureBoxCaptcha.Dock = System.Windows.Forms.DockStyle.Fill;
            pictureBoxCaptcha.Location = new System.Drawing.Point(3, 53);
            pictureBoxCaptcha.Name = "pictureBoxCaptcha";
            pictureBoxCaptcha.Size = new System.Drawing.Size(229, 65);
            pictureBoxCaptcha.SizeMode = System.Windows.Forms.PictureBoxSizeMode.StretchImage;
            pictureBoxCaptcha.TabIndex = 4;
            pictureBoxCaptcha.TabStop = false;
            // 
            // tableLayoutPanel1
            // 
            tableLayoutPanel1.AutoSize = true;
            tableLayoutPanel1.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            tableLayoutPanel1.ColumnCount = 2;
            tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 50F));
            tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 50F));
            tableLayoutPanel1.Controls.Add(labelText, 0, 0);
            tableLayoutPanel1.Controls.Add(btnCancel, 1, 3);
            tableLayoutPanel1.Controls.Add(pictureBoxCaptcha, 0, 1);
            tableLayoutPanel1.Controls.Add(btnAccept, 0, 3);
            tableLayoutPanel1.Controls.Add(txtBox, 0, 2);
            tableLayoutPanel1.Dock = System.Windows.Forms.DockStyle.Fill;
            tableLayoutPanel1.Location = new System.Drawing.Point(0, 0);
            tableLayoutPanel1.Name = "tableLayoutPanel1";
            tableLayoutPanel1.RowCount = 4;
            tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanel1.Size = new System.Drawing.Size(235, 211);
            tableLayoutPanel1.TabIndex = 5;
            // 
            // CaptchaForm
            // 
            AcceptButton = btnAccept;
            AutoScaleDimensions = new System.Drawing.SizeF(144F, 144F);
            AutoScaleMode = System.Windows.Forms.AutoScaleMode.Dpi;
            AutoSize = true;
            AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            CancelButton = btnCancel;
            ClientSize = new System.Drawing.Size(235, 211);
            Controls.Add(tableLayoutPanel1);
            Font = new System.Drawing.Font("Segoe UI", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            Icon = (System.Drawing.Icon)resources.GetObject("$this.Icon");
            Name = "CaptchaForm";
            StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            ((System.ComponentModel.ISupportInitialize)pictureBoxCaptcha).EndInit();
            tableLayoutPanel1.ResumeLayout(false);
            tableLayoutPanel1.PerformLayout();
            ResumeLayout(false);
            PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label labelText;
        public System.Windows.Forms.TextBox txtBox;
        private System.Windows.Forms.Button btnAccept;
        private System.Windows.Forms.Button btnCancel;
        private System.Windows.Forms.PictureBox pictureBoxCaptcha;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel1;
    }
}