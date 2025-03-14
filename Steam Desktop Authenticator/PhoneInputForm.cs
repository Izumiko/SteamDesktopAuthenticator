﻿using SteamAuth;
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace Steam_Desktop_Authenticator
{
    public partial class PhoneInputForm : Form
    {
        private SteamGuardAccount Account;
        public string PhoneNumber;
        public string CountryCode;
        public bool Canceled;
        private static readonly HashSet<char> AllowedChars = ['+', ' '];

        public PhoneInputForm(SteamGuardAccount account)
        {
            this.Account = account;
            InitializeComponent();
        }

        private void btnSubmit_Click(object sender, EventArgs e)
        {
            this.PhoneNumber = txtPhoneNumber.Text;
            this.CountryCode = txtCountryCode.Text;

            if (this.PhoneNumber[0] != '+')
            {
                MessageBox.Show("Phone number must start with + and country code.", "Phone Number", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            this.Close();
        }

        private void txtPhoneNumber_KeyPress(object sender, KeyPressEventArgs e)
        {
            // Allow pasting
            if (Char.IsControl(e.KeyChar))
                return;

            // Only allow numbers, spaces, and +
            if (!char.IsDigit(e.KeyChar) && !AllowedChars.Contains(e.KeyChar))
            {
                e.Handled = true;
            }
        }

        private void txtCountryCode_KeyPress(object sender, KeyPressEventArgs e)
        {
            // Allow pasting
            if (Char.IsControl(e.KeyChar))
                return;

            // Only allow letters
            if (!char.IsLetter(e.KeyChar))
            {
                e.Handled = true;
            }
        }

        private void txtCountryCode_Leave(object sender, EventArgs e)
        {
            // Always uppercase
            txtCountryCode.Text = txtCountryCode.Text.ToUpper();
        }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            this.Canceled = true;
            this.Close();
        }
    }
}
