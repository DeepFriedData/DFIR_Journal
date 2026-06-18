using DFIRNode.Services;
using System.Windows;

namespace DFIRNode
{
    public partial class App : Application
    {
        public static DatabaseService Database { get; private set; } = null!;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            Database = new DatabaseService();
            Database.InitializeDatabase();
        }
    }
}