using SteamAuth;
using System.Windows.Forms;
using System.ComponentModel;

namespace Steam_Desktop_Authenticator
{
    public class ConfirmationButton : Button
    {
        [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
        public Confirmation Confirmation { get; set; }
    }

}
