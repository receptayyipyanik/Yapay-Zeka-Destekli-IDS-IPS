using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace IdsWpfApp
{
    public class AlertItem
    {
        public string IpAddress { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
    }

    public partial class MainWindow : Window
    {
        private Process? pythonProcess;
        public ObservableCollection<AlertItem> Alerts { get; set; }

        public MainWindow()
        {
            InitializeComponent();
            Alerts = new ObservableCollection<AlertItem>();
            AlertList.ItemsSource = Alerts;
            StartPythonEngine();
        }

        private string FindPythonPath()
        {
            string[] possiblePaths = new[]
            {
                Environment.ExpandEnvironmentVariables(@"%LOCALAPPDATA%\Programs\Python\Python315\python.exe"),
                Environment.ExpandEnvironmentVariables(@"%LOCALAPPDATA%\Programs\Python\Python312\python.exe"),
                Environment.ExpandEnvironmentVariables(@"%LOCALAPPDATA%\Programs\Python\Python311\python.exe"),
                Environment.ExpandEnvironmentVariables(@"%LOCALAPPDATA%\Programs\Python\Python310\python.exe"),
                @"C:\Python312\python.exe",
                @"C:\Python311\python.exe",
                @"C:\Program Files\Python312\python.exe"
            };

            foreach (var path in possiblePaths)
            {
                if (System.IO.File.Exists(path)) return path;
            }

            string localPrograms = Environment.ExpandEnvironmentVariables(@"%LOCALAPPDATA%\Programs\Python");
            if (System.IO.Directory.Exists(localPrograms))
            {
                var files = System.IO.Directory.GetFiles(localPrograms, "python.exe", System.IO.SearchOption.AllDirectories);
                if (files.Length > 0) return files[0];
            }

            return "python";
        }

        private void StartPythonEngine()
        {
            try
            {
                pythonProcess = new Process();
                string exePath = AppDomain.CurrentDomain.BaseDirectory;
                string projectDir = System.IO.Path.GetFullPath(System.IO.Path.Combine(exePath, @"..\..\..\"));
                
                string pyScript = System.IO.Path.Combine(projectDir, "tespit_csharp.py");
                if (!System.IO.File.Exists(pyScript))
                {
                    pyScript = System.IO.Path.Combine(exePath, "tespit_csharp.py");
                    if (System.IO.File.Exists(pyScript)) projectDir = exePath;
                }

                string exeFile = System.IO.Path.Combine(projectDir, "tespit_motoru.exe");
                if (!System.IO.File.Exists(exeFile))
                {
                    exeFile = System.IO.Path.Combine(exePath, "tespit_motoru.exe");
                }

                string pyExe = FindPythonPath();

                if (System.IO.File.Exists(pyScript) && (System.IO.File.Exists(pyExe) || pyExe == "python"))
                {
                    pythonProcess.StartInfo.FileName = pyExe;
                    pythonProcess.StartInfo.Arguments = $"-u \"{pyScript}\"";
                }
                else if (System.IO.File.Exists(exeFile))
                {
                    pythonProcess.StartInfo.FileName = exeFile;
                    pythonProcess.StartInfo.Arguments = "";
                }
                else
                {
                    StatusText.Text = "Hata: Tespit motoru dosyasi bulunamadi.";
                    StatusText.Foreground = Brushes.Red;
                    return;
                }

                pythonProcess.StartInfo.WorkingDirectory = projectDir;
                pythonProcess.StartInfo.UseShellExecute = false;
                pythonProcess.StartInfo.RedirectStandardOutput = true;
                pythonProcess.StartInfo.RedirectStandardError = true;
                pythonProcess.StartInfo.CreateNoWindow = true;
                pythonProcess.OutputDataReceived += PythonProcess_OutputDataReceived;
                pythonProcess.ErrorDataReceived += (s, e) => {
                    if (!string.IsNullOrEmpty(e.Data) && !e.Data.Contains("Warning") && !e.Data.Contains("warning"))
                    {
                        Application.Current.Dispatcher.Invoke(() => {
                            StatusText.Text = "Python Hatasi: " + e.Data;
                            StatusText.Foreground = Brushes.Red;
                        });
                    }
                };
                
                pythonProcess.Start();
                pythonProcess.BeginOutputReadLine();
                pythonProcess.BeginErrorReadLine();
            }
            catch (Exception ex)
            {
                StatusText.Text = "Hata: Python baslatilamadi. " + ex.Message;
                StatusText.Foreground = Brushes.Red;
            }
        }

        private void PythonProcess_OutputDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (string.IsNullOrEmpty(e.Data)) return;

            try
            {
                using var doc = JsonDocument.Parse(e.Data);
                var root = doc.RootElement;
                if (!root.TryGetProperty("type", out var typeElement)) return;
                
                string type = typeElement.GetString() ?? "";

                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (type == "status")
                    {
                        StatusText.Text = " - " + root.GetProperty("message").GetString();
                        StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#34D399"));
                    }
                    else if (type == "stats")
                    {
                        TotalPacketsText.Text = root.GetProperty("total").GetInt32().ToString();
                        AnomalousPacketsText.Text = root.GetProperty("anomalous").GetInt32().ToString();
                    }
                    else if (type == "alarm")
                    {
                        string ip = root.GetProperty("ip").GetString() ?? "";
                        string count = root.GetProperty("count").GetInt32().ToString();
                        string loc = root.GetProperty("loc").GetString() ?? "";
                        string time = root.GetProperty("time").GetString() ?? "";

                        SystemStateText.Text = "SALDIRI TESPIT EDILDI!";
                        SystemStateText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F43F5E"));

                        Alerts.Insert(0, new AlertItem
                        {
                            IpAddress = ip,
                            Details = $"Ardisik Paket: {count}\nLokasyon: {loc}\nZaman: {time}"
                        });

                        if (Alerts.Count > 50) Alerts.RemoveAt(Alerts.Count - 1);
                    }
                });
            }
            catch
            {
            }
        }

        private void BlockIp_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.CommandParameter is string ip)
            {
                try
                {
                    // OWASP A03 Injection Korumasi: IP adresi formatini dogrula
                    if (!System.Net.IPAddress.TryParse(ip.Trim(), out var parsedIp))
                    {
                        MessageBox.Show("Gecersiz IP adresi formati! Komut calistirilamadi.", "Guvenlik Uyarisi", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }

                    // Self-DoS Onleme: Loopback ve broadcast adreslerini engelleme
                    if (System.Net.IPAddress.IsLoopback(parsedIp) || parsedIp.ToString() == "0.0.0.0" || parsedIp.ToString() == "255.255.255.255")
                    {
                        MessageBox.Show("Yerel veya gecersiz IP adresleri guvenlik nedeniyle engellenemez.", "Guvenlik Uyarisi", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }

                    string safeIp = parsedIp.ToString();
                    string ruleName = $"BLOCK_IP_{safeIp}";

                    ProcessStartInfo psi = new ProcessStartInfo("netsh", $"advfirewall firewall add rule name=\"{ruleName}\" dir=in action=block remoteip={safeIp}")
                    {
                        UseShellExecute = true,
                        Verb = "runas",
                        CreateNoWindow = true
                    };
                    Process.Start(psi);
                    btn.Content = "ENGELLENDI";
                    btn.IsEnabled = false;
                    btn.Background = Brushes.Gray;
                }
                catch
                {
                    MessageBox.Show("Guvenlik duvari kurali eklenirken yetki hatasi olustu. Uygulamayi yonetici olarak calistirin.", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (pythonProcess != null && !pythonProcess.HasExited)
            {
                pythonProcess.Kill();
            }
        }
    }
}