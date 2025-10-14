namespace Steam_Desktop_Authenticator
{

    partial class MainForm
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
            components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(MainForm));
            timerSteamGuard = new System.Windows.Forms.Timer(components);
            trayIcon = new System.Windows.Forms.NotifyIcon(components);
            menuStripTray = new System.Windows.Forms.ContextMenuStrip(components);
            trayRestore = new System.Windows.Forms.ToolStripMenuItem();
            toolStripSeparator2 = new System.Windows.Forms.ToolStripSeparator();
            trayAccountList = new System.Windows.Forms.ToolStripComboBox();
            trayTradeConfirmations = new System.Windows.Forms.ToolStripMenuItem();
            trayCopySteamGuard = new System.Windows.Forms.ToolStripMenuItem();
            toolStripSeparator3 = new System.Windows.Forms.ToolStripSeparator();
            trayQuit = new System.Windows.Forms.ToolStripMenuItem();
            timerTradesPopup = new System.Windows.Forms.Timer(components);
            lblStatus = new System.Windows.Forms.Label();
            menuStrip = new System.Windows.Forms.MenuStrip();
            fileToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            menuImportAccount = new System.Windows.Forms.ToolStripMenuItem();
            toolStripSeparator1 = new System.Windows.Forms.ToolStripSeparator();
            menuSettings = new System.Windows.Forms.ToolStripMenuItem();
            menuQuit = new System.Windows.Forms.ToolStripMenuItem();
            accountToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            menuLoginAgain = new System.Windows.Forms.ToolStripMenuItem();
            toolStripSeparator4 = new System.Windows.Forms.ToolStripSeparator();
            menuRemoveAccountFromManifest = new System.Windows.Forms.ToolStripMenuItem();
            menuDeactivateAuthenticator = new System.Windows.Forms.ToolStripMenuItem();
            toolStripMenuItem1 = new System.Windows.Forms.ToolStripMenuItem();
            tableLayoutPanelMain = new System.Windows.Forms.TableLayoutPanel();
            tableLayoutPanelButtons = new System.Windows.Forms.TableLayoutPanel();
            btnManageEncryption = new System.Windows.Forms.Button();
            btnSteamLogin = new System.Windows.Forms.Button();
            groupBoxToken = new System.Windows.Forms.GroupBox();
            tableLayoutPanelToken = new System.Windows.Forms.TableLayoutPanel();
            pbTimeout = new System.Windows.Forms.ProgressBar();
            tableLayoutPanelTokenButton = new System.Windows.Forms.TableLayoutPanel();
            btnCopy = new System.Windows.Forms.Button();
            txtLoginToken = new System.Windows.Forms.TextBox();
            groupAccount = new System.Windows.Forms.GroupBox();
            btnTradeConfirmations = new System.Windows.Forms.Button();
            listAccounts = new System.Windows.Forms.ListBox();
            tableLayoutPanelFilter = new System.Windows.Forms.TableLayoutPanel();
            txtAccSearch = new System.Windows.Forms.TextBox();
            label1 = new System.Windows.Forms.Label();
            tableLayoutPanelStatus = new System.Windows.Forms.TableLayoutPanel();
            labelUpdate = new System.Windows.Forms.LinkLabel();
            labelVersion = new System.Windows.Forms.Label();
            menuStripTray.SuspendLayout();
            menuStrip.SuspendLayout();
            tableLayoutPanelMain.SuspendLayout();
            tableLayoutPanelButtons.SuspendLayout();
            groupBoxToken.SuspendLayout();
            tableLayoutPanelToken.SuspendLayout();
            tableLayoutPanelTokenButton.SuspendLayout();
            groupAccount.SuspendLayout();
            tableLayoutPanelFilter.SuspendLayout();
            tableLayoutPanelStatus.SuspendLayout();
            SuspendLayout();
            // 
            // timerSteamGuard
            // 
            timerSteamGuard.Enabled = true;
            timerSteamGuard.Interval = 1000;
            timerSteamGuard.Tick += timerSteamGuard_Tick;
            // 
            // trayIcon
            // 
            trayIcon.ContextMenuStrip = menuStripTray;
            trayIcon.Text = "Steam Desktop Authenticator";
            trayIcon.Visible = true;
            trayIcon.MouseDoubleClick += trayIcon_MouseDoubleClick;
            // 
            // menuStripTray
            // 
            menuStripTray.ImageScalingSize = new System.Drawing.Size(24, 24);
            menuStripTray.Items.AddRange(new System.Windows.Forms.ToolStripItem[] { trayRestore, toolStripSeparator2, trayAccountList, trayTradeConfirmations, trayCopySteamGuard, toolStripSeparator3, trayQuit });
            menuStripTray.Name = "contextMenuStripTray";
            menuStripTray.Size = new System.Drawing.Size(312, 174);
            // 
            // trayRestore
            // 
            trayRestore.Name = "trayRestore";
            trayRestore.Size = new System.Drawing.Size(311, 30);
            trayRestore.Text = "Restore";
            trayRestore.Click += trayRestore_Click;
            // 
            // toolStripSeparator2
            // 
            toolStripSeparator2.Name = "toolStripSeparator2";
            toolStripSeparator2.Size = new System.Drawing.Size(308, 6);
            // 
            // trayAccountList
            // 
            trayAccountList.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            trayAccountList.Items.AddRange(new object[] { "test1", "test2" });
            trayAccountList.Name = "trayAccountList";
            trayAccountList.Size = new System.Drawing.Size(121, 32);
            trayAccountList.SelectedIndexChanged += trayAccountList_SelectedIndexChanged;
            // 
            // trayTradeConfirmations
            // 
            trayTradeConfirmations.Name = "trayTradeConfirmations";
            trayTradeConfirmations.Size = new System.Drawing.Size(311, 30);
            trayTradeConfirmations.Text = "Trade Confirmations";
            trayTradeConfirmations.Click += trayTradeConfirmations_Click;
            // 
            // trayCopySteamGuard
            // 
            trayCopySteamGuard.Name = "trayCopySteamGuard";
            trayCopySteamGuard.Size = new System.Drawing.Size(311, 30);
            trayCopySteamGuard.Text = "Copy SG code to clipboard";
            trayCopySteamGuard.Click += trayCopySteamGuard_Click;
            // 
            // toolStripSeparator3
            // 
            toolStripSeparator3.Name = "toolStripSeparator3";
            toolStripSeparator3.Size = new System.Drawing.Size(308, 6);
            // 
            // trayQuit
            // 
            trayQuit.Name = "trayQuit";
            trayQuit.Size = new System.Drawing.Size(311, 30);
            trayQuit.Text = "Quit";
            trayQuit.Click += trayQuit_Click;
            // 
            // timerTradesPopup
            // 
            timerTradesPopup.Enabled = true;
            timerTradesPopup.Interval = 5000;
            timerTradesPopup.Tick += timerTradesPopup_Tick;
            // 
            // lblStatus
            // 
            lblStatus.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right;
            lblStatus.AutoSize = true;
            lblStatus.BackColor = System.Drawing.SystemColors.Control;
            lblStatus.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            lblStatus.Location = new System.Drawing.Point(194, 5);
            lblStatus.Name = "lblStatus";
            lblStatus.Size = new System.Drawing.Size(0, 25);
            lblStatus.TabIndex = 11;
            lblStatus.TextAlign = System.Drawing.ContentAlignment.TopRight;
            // 
            // menuStrip
            // 
            menuStrip.BackColor = System.Drawing.SystemColors.Control;
            menuStrip.ImageScalingSize = new System.Drawing.Size(24, 24);
            menuStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] { fileToolStripMenuItem, accountToolStripMenuItem, toolStripMenuItem1 });
            menuStrip.Location = new System.Drawing.Point(0, 0);
            menuStrip.Name = "menuStrip";
            menuStrip.Size = new System.Drawing.Size(362, 32);
            menuStrip.TabIndex = 15;
            menuStrip.Text = "menuStrip1";
            // 
            // fileToolStripMenuItem
            // 
            fileToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] { menuImportAccount, toolStripSeparator1, menuSettings, menuQuit });
            fileToolStripMenuItem.Name = "fileToolStripMenuItem";
            fileToolStripMenuItem.Size = new System.Drawing.Size(56, 28);
            fileToolStripMenuItem.Text = "File";
            // 
            // menuImportAccount
            // 
            menuImportAccount.Name = "menuImportAccount";
            menuImportAccount.Size = new System.Drawing.Size(270, 34);
            menuImportAccount.Text = "Import Account";
            menuImportAccount.Click += menuImportAccount_Click;
            // 
            // toolStripSeparator1
            // 
            toolStripSeparator1.Name = "toolStripSeparator1";
            toolStripSeparator1.Size = new System.Drawing.Size(267, 6);
            // 
            // menuSettings
            // 
            menuSettings.Name = "menuSettings";
            menuSettings.Size = new System.Drawing.Size(270, 34);
            menuSettings.Text = "Settings";
            menuSettings.Click += menuSettings_Click;
            // 
            // menuQuit
            // 
            menuQuit.Name = "menuQuit";
            menuQuit.Size = new System.Drawing.Size(270, 34);
            menuQuit.Text = "Quit";
            menuQuit.Click += menuQuit_Click;
            // 
            // accountToolStripMenuItem
            // 
            accountToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] { menuLoginAgain, toolStripSeparator4, menuRemoveAccountFromManifest, menuDeactivateAuthenticator });
            accountToolStripMenuItem.Name = "accountToolStripMenuItem";
            accountToolStripMenuItem.Size = new System.Drawing.Size(175, 28);
            accountToolStripMenuItem.Text = "Selected Account";
            // 
            // menuLoginAgain
            // 
            menuLoginAgain.Name = "menuLoginAgain";
            menuLoginAgain.Size = new System.Drawing.Size(325, 34);
            menuLoginAgain.Text = "Login again";
            menuLoginAgain.Click += menuLoginAgain_Click;
            // 
            // toolStripSeparator4
            // 
            toolStripSeparator4.Name = "toolStripSeparator4";
            toolStripSeparator4.Size = new System.Drawing.Size(322, 6);
            // 
            // menuRemoveAccountFromManifest
            // 
            menuRemoveAccountFromManifest.Name = "menuRemoveAccountFromManifest";
            menuRemoveAccountFromManifest.Size = new System.Drawing.Size(325, 34);
            menuRemoveAccountFromManifest.Text = "Remove from manifest";
            menuRemoveAccountFromManifest.Click += menuRemoveAccountFromManifest_Click;
            // 
            // menuDeactivateAuthenticator
            // 
            menuDeactivateAuthenticator.Name = "menuDeactivateAuthenticator";
            menuDeactivateAuthenticator.Size = new System.Drawing.Size(325, 34);
            menuDeactivateAuthenticator.Text = "Deactivate Authenticator";
            menuDeactivateAuthenticator.Click += menuDeactivateAuthenticator_Click;
            // 
            // toolStripMenuItem1
            // 
            toolStripMenuItem1.Name = "toolStripMenuItem1";
            toolStripMenuItem1.Size = new System.Drawing.Size(16, 28);
            // 
            // tableLayoutPanelMain
            // 
            tableLayoutPanelMain.AutoSize = true;
            tableLayoutPanelMain.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            tableLayoutPanelMain.ColumnCount = 1;
            tableLayoutPanelMain.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            tableLayoutPanelMain.Controls.Add(tableLayoutPanelButtons, 0, 0);
            tableLayoutPanelMain.Controls.Add(groupBoxToken, 0, 1);
            tableLayoutPanelMain.Controls.Add(groupAccount, 0, 2);
            tableLayoutPanelMain.Controls.Add(listAccounts, 0, 3);
            tableLayoutPanelMain.Controls.Add(tableLayoutPanelFilter, 0, 4);
            tableLayoutPanelMain.Controls.Add(tableLayoutPanelStatus, 0, 5);
            tableLayoutPanelMain.Dock = System.Windows.Forms.DockStyle.Fill;
            tableLayoutPanelMain.Location = new System.Drawing.Point(0, 32);
            tableLayoutPanelMain.Name = "tableLayoutPanelMain";
            tableLayoutPanelMain.RowCount = 6;
            tableLayoutPanelMain.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanelMain.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanelMain.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanelMain.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            tableLayoutPanelMain.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanelMain.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanelMain.Size = new System.Drawing.Size(362, 529);
            tableLayoutPanelMain.TabIndex = 16;
            // 
            // tableLayoutPanelButtons
            // 
            tableLayoutPanelButtons.AutoSize = true;
            tableLayoutPanelButtons.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            tableLayoutPanelButtons.ColumnCount = 2;
            tableLayoutPanelButtons.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 50F));
            tableLayoutPanelButtons.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 50F));
            tableLayoutPanelButtons.Controls.Add(btnManageEncryption, 1, 0);
            tableLayoutPanelButtons.Controls.Add(btnSteamLogin, 0, 0);
            tableLayoutPanelButtons.Dock = System.Windows.Forms.DockStyle.Fill;
            tableLayoutPanelButtons.Location = new System.Drawing.Point(3, 3);
            tableLayoutPanelButtons.Name = "tableLayoutPanelButtons";
            tableLayoutPanelButtons.RowCount = 1;
            tableLayoutPanelButtons.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            tableLayoutPanelButtons.Size = new System.Drawing.Size(356, 39);
            tableLayoutPanelButtons.TabIndex = 0;
            // 
            // btnManageEncryption
            // 
            btnManageEncryption.AutoSize = true;
            btnManageEncryption.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            btnManageEncryption.Dock = System.Windows.Forms.DockStyle.Fill;
            btnManageEncryption.Location = new System.Drawing.Point(181, 3);
            btnManageEncryption.Name = "btnManageEncryption";
            btnManageEncryption.Size = new System.Drawing.Size(172, 33);
            btnManageEncryption.TabIndex = 6;
            btnManageEncryption.Text = "Manage Encryption";
            btnManageEncryption.UseVisualStyleBackColor = true;
            btnManageEncryption.Click += btnManageEncryption_Click;
            // 
            // btnSteamLogin
            // 
            btnSteamLogin.AutoSize = true;
            btnSteamLogin.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            btnSteamLogin.Dock = System.Windows.Forms.DockStyle.Fill;
            btnSteamLogin.Location = new System.Drawing.Point(3, 3);
            btnSteamLogin.Name = "btnSteamLogin";
            btnSteamLogin.Size = new System.Drawing.Size(172, 33);
            btnSteamLogin.TabIndex = 1;
            btnSteamLogin.Text = "Setup New Account";
            btnSteamLogin.UseVisualStyleBackColor = true;
            btnSteamLogin.Click += btnSteamLogin_Click;
            // 
            // groupBoxToken
            // 
            groupBoxToken.AutoSize = true;
            groupBoxToken.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            groupBoxToken.Controls.Add(tableLayoutPanelToken);
            groupBoxToken.Dock = System.Windows.Forms.DockStyle.Fill;
            groupBoxToken.Location = new System.Drawing.Point(3, 48);
            groupBoxToken.Name = "groupBoxToken";
            groupBoxToken.Size = new System.Drawing.Size(356, 114);
            groupBoxToken.TabIndex = 2;
            groupBoxToken.TabStop = false;
            groupBoxToken.Text = "Login Token";
            // 
            // tableLayoutPanelToken
            // 
            tableLayoutPanelToken.AutoSize = true;
            tableLayoutPanelToken.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            tableLayoutPanelToken.ColumnCount = 1;
            tableLayoutPanelToken.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            tableLayoutPanelToken.Controls.Add(pbTimeout, 0, 1);
            tableLayoutPanelToken.Controls.Add(tableLayoutPanelTokenButton, 0, 0);
            tableLayoutPanelToken.Dock = System.Windows.Forms.DockStyle.Fill;
            tableLayoutPanelToken.Location = new System.Drawing.Point(3, 25);
            tableLayoutPanelToken.Name = "tableLayoutPanelToken";
            tableLayoutPanelToken.RowCount = 2;
            tableLayoutPanelToken.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanelToken.RowStyles.Add(new System.Windows.Forms.RowStyle());
            tableLayoutPanelToken.Size = new System.Drawing.Size(350, 86);
            tableLayoutPanelToken.TabIndex = 0;
            // 
            // pbTimeout
            // 
            pbTimeout.Dock = System.Windows.Forms.DockStyle.Fill;
            pbTimeout.Location = new System.Drawing.Point(3, 64);
            pbTimeout.Maximum = 30;
            pbTimeout.Name = "pbTimeout";
            pbTimeout.Size = new System.Drawing.Size(344, 19);
            pbTimeout.TabIndex = 1;
            pbTimeout.Value = 30;
            // 
            // tableLayoutPanelTokenButton
            // 
            tableLayoutPanelTokenButton.AutoSize = true;
            tableLayoutPanelTokenButton.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            tableLayoutPanelTokenButton.ColumnCount = 2;
            tableLayoutPanelTokenButton.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            tableLayoutPanelTokenButton.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            tableLayoutPanelTokenButton.Controls.Add(btnCopy, 1, 0);
            tableLayoutPanelTokenButton.Controls.Add(txtLoginToken, 0, 0);
            tableLayoutPanelTokenButton.Dock = System.Windows.Forms.DockStyle.Fill;
            tableLayoutPanelTokenButton.Location = new System.Drawing.Point(3, 3);
            tableLayoutPanelTokenButton.Name = "tableLayoutPanelTokenButton";
            tableLayoutPanelTokenButton.RowCount = 1;
            tableLayoutPanelTokenButton.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            tableLayoutPanelTokenButton.Size = new System.Drawing.Size(344, 55);
            tableLayoutPanelTokenButton.TabIndex = 2;
            // 
            // btnCopy
            // 
            btnCopy.AutoSize = true;
            btnCopy.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            btnCopy.Dock = System.Windows.Forms.DockStyle.Fill;
            btnCopy.Location = new System.Drawing.Point(282, 3);
            btnCopy.Name = "btnCopy";
            btnCopy.Size = new System.Drawing.Size(59, 49);
            btnCopy.TabIndex = 2;
            btnCopy.Text = "Copy";
            btnCopy.UseVisualStyleBackColor = true;
            btnCopy.Click += btnCopy_Click;
            // 
            // txtLoginToken
            // 
            txtLoginToken.BackColor = System.Drawing.SystemColors.Window;
            txtLoginToken.Dock = System.Windows.Forms.DockStyle.Fill;
            txtLoginToken.Font = new System.Drawing.Font("Segoe UI", 15.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            txtLoginToken.Location = new System.Drawing.Point(3, 3);
            txtLoginToken.Name = "txtLoginToken";
            txtLoginToken.ReadOnly = true;
            txtLoginToken.Size = new System.Drawing.Size(273, 49);
            txtLoginToken.TabIndex = 0;
            txtLoginToken.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // groupAccount
            // 
            groupAccount.AutoSize = true;
            groupAccount.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            groupAccount.Controls.Add(btnTradeConfirmations);
            groupAccount.Dock = System.Windows.Forms.DockStyle.Fill;
            groupAccount.Location = new System.Drawing.Point(3, 168);
            groupAccount.MaximumSize = new System.Drawing.Size(0, 64);
            groupAccount.MinimumSize = new System.Drawing.Size(0, 24);
            groupAccount.Name = "groupAccount";
            groupAccount.Size = new System.Drawing.Size(356, 61);
            groupAccount.TabIndex = 7;
            groupAccount.TabStop = false;
            groupAccount.Text = "Account";
            // 
            // btnTradeConfirmations
            // 
            btnTradeConfirmations.AutoSize = true;
            btnTradeConfirmations.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            btnTradeConfirmations.Dock = System.Windows.Forms.DockStyle.Fill;
            btnTradeConfirmations.Enabled = false;
            btnTradeConfirmations.Location = new System.Drawing.Point(3, 25);
            btnTradeConfirmations.Name = "btnTradeConfirmations";
            btnTradeConfirmations.Size = new System.Drawing.Size(350, 33);
            btnTradeConfirmations.TabIndex = 4;
            btnTradeConfirmations.Text = "View Confirmations";
            btnTradeConfirmations.UseVisualStyleBackColor = true;
            btnTradeConfirmations.Click += btnTradeConfirmations_Click;
            // 
            // listAccounts
            // 
            listAccounts.Dock = System.Windows.Forms.DockStyle.Fill;
            listAccounts.FormattingEnabled = true;
            listAccounts.Location = new System.Drawing.Point(3, 235);
            listAccounts.MinimumSize = new System.Drawing.Size(0, 64);
            listAccounts.Name = "listAccounts";
            listAccounts.Size = new System.Drawing.Size(356, 225);
            listAccounts.TabIndex = 3;
            listAccounts.SelectedValueChanged += listAccounts_SelectedValueChanged;
            listAccounts.KeyDown += listAccounts_KeyDown;
            // 
            // tableLayoutPanelFilter
            // 
            tableLayoutPanelFilter.AutoSize = true;
            tableLayoutPanelFilter.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            tableLayoutPanelFilter.ColumnCount = 2;
            tableLayoutPanelFilter.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            tableLayoutPanelFilter.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            tableLayoutPanelFilter.Controls.Add(txtAccSearch, 1, 0);
            tableLayoutPanelFilter.Controls.Add(label1, 0, 0);
            tableLayoutPanelFilter.Dock = System.Windows.Forms.DockStyle.Fill;
            tableLayoutPanelFilter.Location = new System.Drawing.Point(3, 466);
            tableLayoutPanelFilter.Name = "tableLayoutPanelFilter";
            tableLayoutPanelFilter.RowCount = 1;
            tableLayoutPanelFilter.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            tableLayoutPanelFilter.Size = new System.Drawing.Size(356, 35);
            tableLayoutPanelFilter.TabIndex = 8;
            // 
            // txtAccSearch
            // 
            txtAccSearch.Dock = System.Windows.Forms.DockStyle.Fill;
            txtAccSearch.Location = new System.Drawing.Point(60, 3);
            txtAccSearch.Name = "txtAccSearch";
            txtAccSearch.Size = new System.Drawing.Size(293, 29);
            txtAccSearch.TabIndex = 12;
            txtAccSearch.TextChanged += txtAccSearch_TextChanged;
            // 
            // label1
            // 
            label1.Anchor = System.Windows.Forms.AnchorStyles.Left;
            label1.AutoSize = true;
            label1.Location = new System.Drawing.Point(3, 6);
            label1.Name = "label1";
            label1.Size = new System.Drawing.Size(51, 23);
            label1.TabIndex = 13;
            label1.Text = "Filter:";
            // 
            // tableLayoutPanelStatus
            // 
            tableLayoutPanelStatus.AutoSize = true;
            tableLayoutPanelStatus.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            tableLayoutPanelStatus.ColumnCount = 2;
            tableLayoutPanelStatus.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            tableLayoutPanelStatus.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            tableLayoutPanelStatus.Controls.Add(labelUpdate, 0, 0);
            tableLayoutPanelStatus.Controls.Add(labelVersion, 1, 0);
            tableLayoutPanelStatus.Dock = System.Windows.Forms.DockStyle.Fill;
            tableLayoutPanelStatus.Location = new System.Drawing.Point(3, 507);
            tableLayoutPanelStatus.Name = "tableLayoutPanelStatus";
            tableLayoutPanelStatus.RowCount = 1;
            tableLayoutPanelStatus.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            tableLayoutPanelStatus.Size = new System.Drawing.Size(356, 19);
            tableLayoutPanelStatus.TabIndex = 9;
            // 
            // labelUpdate
            // 
            labelUpdate.Anchor = System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left;
            labelUpdate.AutoSize = true;
            labelUpdate.BackColor = System.Drawing.Color.Transparent;
            labelUpdate.Font = new System.Drawing.Font("Segoe UI", 6.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            labelUpdate.ForeColor = System.Drawing.SystemColors.ControlDarkDark;
            labelUpdate.ImageAlign = System.Drawing.ContentAlignment.BottomRight;
            labelUpdate.Location = new System.Drawing.Point(3, 0);
            labelUpdate.Name = "labelUpdate";
            labelUpdate.Size = new System.Drawing.Size(120, 19);
            labelUpdate.TabIndex = 9;
            labelUpdate.TabStop = true;
            labelUpdate.Text = "Check for updates";
            labelUpdate.TextAlign = System.Drawing.ContentAlignment.BottomLeft;
            labelUpdate.LinkClicked += labelUpdate_LinkClicked;
            // 
            // labelVersion
            // 
            labelVersion.Anchor = System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right;
            labelVersion.BackColor = System.Drawing.Color.Transparent;
            labelVersion.Font = new System.Drawing.Font("Segoe UI", 6.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            labelVersion.ForeColor = System.Drawing.SystemColors.ControlDarkDark;
            labelVersion.ImageAlign = System.Drawing.ContentAlignment.BottomRight;
            labelVersion.Location = new System.Drawing.Point(283, 4);
            labelVersion.Name = "labelVersion";
            labelVersion.Size = new System.Drawing.Size(70, 15);
            labelVersion.TabIndex = 8;
            labelVersion.Text = "v0.0.0";
            labelVersion.TextAlign = System.Drawing.ContentAlignment.BottomRight;
            // 
            // MainForm
            // 
            AutoScaleDimensions = new System.Drawing.SizeF(144F, 144F);
            AutoScaleMode = System.Windows.Forms.AutoScaleMode.Dpi;
            AutoSize = true;
            ClientSize = new System.Drawing.Size(362, 561);
            Controls.Add(lblStatus);
            Controls.Add(tableLayoutPanelMain);
            Controls.Add(menuStrip);
            Font = new System.Drawing.Font("Segoe UI", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, 0);
            Icon = (System.Drawing.Icon)resources.GetObject("$this.Icon");
            KeyPreview = true;
            MaximizeBox = false;
            MinimumSize = new System.Drawing.Size(350, 500);
            Name = "MainForm";
            StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            Text = "Steam Desktop Authenticator";
            FormClosing += MainForm_FormClosing;
            Load += MainForm_Load;
            Shown += MainForm_Shown;
            KeyDown += MainForm_KeyDown;
            Resize += MainForm_Resize;
            menuStripTray.ResumeLayout(false);
            menuStrip.ResumeLayout(false);
            menuStrip.PerformLayout();
            tableLayoutPanelMain.ResumeLayout(false);
            tableLayoutPanelMain.PerformLayout();
            tableLayoutPanelButtons.ResumeLayout(false);
            tableLayoutPanelButtons.PerformLayout();
            groupBoxToken.ResumeLayout(false);
            groupBoxToken.PerformLayout();
            tableLayoutPanelToken.ResumeLayout(false);
            tableLayoutPanelToken.PerformLayout();
            tableLayoutPanelTokenButton.ResumeLayout(false);
            tableLayoutPanelTokenButton.PerformLayout();
            groupAccount.ResumeLayout(false);
            groupAccount.PerformLayout();
            tableLayoutPanelFilter.ResumeLayout(false);
            tableLayoutPanelFilter.PerformLayout();
            tableLayoutPanelStatus.ResumeLayout(false);
            tableLayoutPanelStatus.PerformLayout();
            ResumeLayout(false);
            PerformLayout();

        }

        #endregion
        private System.Windows.Forms.Timer timerSteamGuard;
        private System.Windows.Forms.NotifyIcon trayIcon;
        private System.Windows.Forms.ContextMenuStrip menuStripTray;
        private System.Windows.Forms.ToolStripMenuItem trayRestore;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator2;
        private System.Windows.Forms.ToolStripMenuItem trayTradeConfirmations;
        private System.Windows.Forms.ToolStripMenuItem trayCopySteamGuard;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator3;
        private System.Windows.Forms.ToolStripMenuItem trayQuit;
        private System.Windows.Forms.Timer timerTradesPopup;
        private System.Windows.Forms.ToolStripComboBox trayAccountList;
        private System.Windows.Forms.Label lblStatus;
        private System.Windows.Forms.MenuStrip menuStrip;
        private System.Windows.Forms.ToolStripMenuItem fileToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem menuImportAccount;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator1;
        private System.Windows.Forms.ToolStripMenuItem menuSettings;
        private System.Windows.Forms.ToolStripMenuItem menuQuit;
        private System.Windows.Forms.ToolStripMenuItem accountToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem menuLoginAgain;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator4;
        private System.Windows.Forms.ToolStripMenuItem menuRemoveAccountFromManifest;
        private System.Windows.Forms.ToolStripMenuItem menuDeactivateAuthenticator;
        private System.Windows.Forms.ToolStripMenuItem toolStripMenuItem1;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanelMain;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanelButtons;
        private System.Windows.Forms.Button btnManageEncryption;
        private System.Windows.Forms.Button btnSteamLogin;
        private System.Windows.Forms.GroupBox groupBoxToken;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanelToken;
        private System.Windows.Forms.ProgressBar pbTimeout;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanelTokenButton;
        private System.Windows.Forms.Button btnCopy;
        private System.Windows.Forms.TextBox txtLoginToken;
        private System.Windows.Forms.GroupBox groupAccount;
        private System.Windows.Forms.Button btnTradeConfirmations;
        private System.Windows.Forms.ListBox listAccounts;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanelFilter;
        private System.Windows.Forms.TextBox txtAccSearch;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanelStatus;
        private System.Windows.Forms.LinkLabel labelUpdate;
        private System.Windows.Forms.Label labelVersion;
    }
}

