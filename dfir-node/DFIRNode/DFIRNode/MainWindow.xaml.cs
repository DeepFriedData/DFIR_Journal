using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using System.Windows.Media;

namespace DFIRNode
{
    public partial class MainWindow : Window
    {
        private DispatcherTimer _clock;

        public MainWindow()
        {
            InitializeComponent();
            StartClock();
            ShowPlaceholder("DFIR Analyst View", "Technical findings, IOCs, timeline of events, and evidence chain.");
        }

        private void StartClock()
        {
            _clock = new DispatcherTimer();
            _clock.Interval = TimeSpan.FromSeconds(1);
            _clock.Tick += (s, e) => ClockText.Text = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss") + " UTC";
            _clock.Start();
            ClockText.Text = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss") + " UTC";
        }

        private void Nav_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button btn) return;

            foreach (var b in new[] { BtnAnalyst, BtnPrincipal, BtnEngLead, BtnAdmin, BtnCustodian })
                b.Style = (Style)FindResource("NavButton");
            btn.Style = (Style)FindResource("NavButtonActive");

            switch (btn.Tag?.ToString())
            {
                case "Analyst":
                    ShowPlaceholder("DFIR Analyst View", "Technical findings, IOCs, timeline of events, and evidence chain.");
                    break;
                case "Principal":
                    ShowPlaceholder("Principal Consultant View", "Hypothesis tracking, analytical confidence levels, and findings synthesis.");
                    break;
                case "EngagementLead":
                    ShowPlaceholder("Engagement Lead View", "Client communication, impact summary, status updates, and next steps.");
                    break;
                case "Admin":
                    ShowPlaceholder("Administrative View", "Node health, user activity, registration status, and audit log.");
                    break;
                case "Custodian":
                    ShowPlaceholder("Custodian of Evidence View", "Chain of custody, evidence integrity, WORM verification, and export.");
                    break;
            }
        }

        private void Cards_Click(object sender, RoutedEventArgs e) =>
            ShowPlaceholder("Engagement Cards", "Open, active, and archived engagement cards for this node.");

        private void Export_Click(object sender, RoutedEventArgs e) =>
            ShowPlaceholder("Export Bundle", "Export registration packets and telemetry bundles to Domain Registrar.");

        private void Import_Click(object sender, RoutedEventArgs e) =>
            ShowPlaceholder("Import Bundle", "Import registration responses and revocation bundles.");

        private void Register_Click(object sender, RoutedEventArgs e) =>
            ShowPlaceholder("Node Registration", "Generate a registration packet to submit to the Domain Registrar.");

        private void SignIn_Click(object sender, RoutedEventArgs e) =>
            ShowPlaceholder("Sign In", "Authenticate with your bound user identity.");

        private void ShowPlaceholder(string title, string description)
        {
            StatusBarText.Text = $"Viewing: {title}";

            var panel = new StackPanel
            {
                VerticalAlignment = VerticalAlignment.Center,
                HorizontalAlignment = HorizontalAlignment.Center
            };

            panel.Children.Add(new TextBlock
            {
                Text = title,
                Foreground = Brushes.White,
                FontSize = 22,
                FontWeight = FontWeights.SemiBold,
                FontFamily = new FontFamily("Segoe UI"),
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 0, 0, 10)
            });

            panel.Children.Add(new TextBlock
            {
                Text = description,
                Foreground = new SolidColorBrush(Color.FromRgb(139, 148, 158)),
                FontSize = 14,
                FontFamily = new FontFamily("Segoe UI"),
                HorizontalAlignment = HorizontalAlignment.Center,
                TextAlignment = TextAlignment.Center,
                MaxWidth = 500
            });

            MainFrame.Content = panel;
        }
    }
}