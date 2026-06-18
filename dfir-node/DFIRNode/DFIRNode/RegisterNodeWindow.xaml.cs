using DFIRNode.Models;
using DFIRNode.Services;
using Microsoft.Win32;
using System.Windows;

namespace DFIRNode.Views
{
    public partial class RegisterNodeWindow : Window
    {
        public bool PacketExported { get; private set; } = false;
        public NodeIdentity? CreatedNode { get; private set; }

        public RegisterNodeWindow()
        {
            InitializeComponent();
            LoadDeviceInfo();
        }

        private void LoadDeviceInfo()
        {
            var fp = App.Registration.GetDeviceFingerprint();
            FingerprintText.Text = fp;
            HostnameText.Text = $"Hostname: {System.Environment.MachineName}  |  " +
                                $"OS: {System.Environment.OSVersion.VersionString}";
            NodeNameBox.Text = $"DFIR-{System.Environment.MachineName}";
        }

        private void Generate_Click(object sender, RoutedEventArgs e)
        {
            ErrorText.Visibility = Visibility.Collapsed;

            var nodeName = NodeNameBox.Text.Trim();
            var userName = UserNameBox.Text.Trim();
            var userEmail = UserEmailBox.Text.Trim();

            if (string.IsNullOrEmpty(nodeName))
            { ShowError("Node name is required."); return; }
            if (string.IsNullOrEmpty(userName))
            { ShowError("Your full name is required."); return; }
            if (string.IsNullOrEmpty(userEmail) || !userEmail.Contains('@'))
            { ShowError("A valid email address is required."); return; }

            // Check if node already initialized
            var existing = App.Registration.GetNodeIdentity();
            NodeIdentity node;
            if (existing == null)
                node = App.Registration.InitializeNode(nodeName);
            else
                node = existing;

            // Generate packet
            var packet = App.Registration.GenerateRegistrationPacket(
                node, userName, userEmail);

            // Save dialog
            var dialog = new SaveFileDialog
            {
                Title = "Export Registration Packet",
                FileName = $"registration_packet_{node.NodeId[..8]}.json",
                Filter = "JSON Files (*.json)|*.json",
                DefaultExt = "json"
            };

            if (dialog.ShowDialog() == true)
            {
                App.Registration.ExportPacketToFile(packet, dialog.FileName);
                CreatedNode = node;
                PacketExported = true;

                MessageBox.Show(
                    $"Registration packet exported successfully.\n\n" +
                    $"File: {dialog.FileName}\n\n" +
                    $"Submit this file to your Domain Registrar for approval.\n" +
                    $"Once approved, import the registration response to activate this node.",
                    "Packet Exported",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);

                DialogResult = true;
                Close();
            }
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private void ShowError(string message)
        {
            ErrorText.Text = message;
            ErrorText.Visibility = Visibility.Visible;
        }
    }
}