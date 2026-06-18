using Microsoft.Win32;
using System;
using System.IO;
using System.Text.Json;
using System.Windows;

namespace DFIRNode.Views
{
    public partial class ImportBundleWindow : Window
    {
        private string? _selectedFilePath;
        public bool ImportSucceeded { get; private set; } = false;

        public ImportBundleWindow()
        {
            InitializeComponent();
        }

        private void Browse_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Select Bundle File",
                Filter = "JSON Files (*.json)|*.json"
            };

            if (dialog.ShowDialog() != true) return;

            _selectedFilePath = dialog.FileName;

            FilePathText.Text = Path.GetFileName(dialog.FileName);
            FilePathText.Foreground = System.Windows.Media.Brushes.White;

            try
            {
                var json = File.ReadAllText(_selectedFilePath);
                PreviewText.Text = json.Length > 400
                    ? json.Substring(0, 400) + "\n..."
                    : json;
                PreviewText.Foreground = System.Windows.Media.Brushes.LightBlue;
                ErrorText.Visibility = Visibility.Collapsed;
                ImportBtn.IsEnabled = true;
            }
            catch (Exception ex)
            {
                PreviewText.Text = "Error reading file: " + ex.Message;
                ImportBtn.IsEnabled = false;
            }
        }

        private void Import_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var json = File.ReadAllText(_selectedFilePath!);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                var responseType = root.GetProperty("ResponseType").GetString() ?? "";
                if (responseType != "RegistrationResponse")
                {
                    MessageBox.Show("Wrong type: " + responseType, "Error");
                    return;
                }

                var nodeId = root.GetProperty("NodeId").GetString() ?? "";
                var domainId = root.GetProperty("DomainId").GetString() ?? "";
                var domainName = root.GetProperty("DomainName").GetString() ?? "";
                var expiry = root.GetProperty("ExpiryUtc").GetString() ?? "";

                var normalized = JsonSerializer.Serialize(new
                {
                    ResponseType = "RegistrationResponse",
                    NodeId = nodeId,
                    DomainId = domainId,
                    DomainName = domainName,
                    ExpiryUtc = expiry
                });

                var tempPath = Path.Combine(Path.GetTempPath(), "dfir_norm.json");
                File.WriteAllText(tempPath, normalized);

                var success = App.Registration.ImportRegistrationResponse(tempPath, "system");

                if (success)
                {
                    ImportSucceeded = true;
                    MessageBox.Show("Node activated successfully!", "Success");
                    DialogResult = true;
                    Close();
                }
                else
                {
                    MessageBox.Show("Import failed. NodeId may not match this node.", "Error");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "Error");
            }
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private void ShowError(string msg)
        {
            ErrorText.Text = msg;
            ErrorText.Visibility = Visibility.Visible;
        }

        private void ShowSuccess(string msg)
        {
            SuccessText.Text = msg;
            SuccessText.Visibility = Visibility.Visible;
        }
    }
}