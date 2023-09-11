using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.IO;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Reflection;
using Microsoft.Win32;

using SnippetSvc;

namespace Snippet
{
    public enum ServiceState // from Windows
    {
        SERVICE_STOPPED = 0x00000001,
        SERVICE_START_PENDING = 0x00000002,
        SERVICE_STOP_PENDING = 0x00000003,
        SERVICE_RUNNING = 0x00000004,
        SERVICE_CONTINUE_PENDING = 0x00000005,
        SERVICE_PAUSE_PENDING = 0x00000006,
        SERVICE_PAUSED = 0x00000007,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ServiceStatus // from Windows
    {
        public long dwServiceType;
        public ServiceState dwCurrentState;
        public long dwControlsAccepted;
        public long dwWin32ExitCode;
        public long dwServiceSpecificExitCode;
        public long dwCheckPoint;
        public long dwWaitHint;
    };

    public partial class SnippetSvc : ServiceBase
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetServiceStatus(IntPtr handle, ref ServiceStatus serviceStatus); // from Windows

        public static ISnippetMobileSvc GetService(string strSvcName)
        {
            ISnippetMobileSvc svc = null;

            if (!SnippetMobileServices.TryGetValue(strSvcName, out svc))
            {
                Program.DbgReport("SnippetSvc.GetService() - unknown service " + strSvcName);

                return null;
            }

            return svc;
        }

        public static Dictionary<string, ISnippetMobileSvc> SnippetMobileServices
        {
            get { return dictSnippetMobileServices; }
        }

        private class ServerInit
        {
            public ServerInit(SnippetSvc s, int n)
            {
                svc = s;
                ID = n;
            }

            public SnippetSvc svc = null;
            public int ID = 0;
        }


        public static string ProcessRawClientRequest(string strRequest)
        {
            Snippet.SnippetMobileMessage msg = null;
            Snippet.SnippetMobileResult res = null;
            Snippet.SnippetMobileStatus status = Snippet.SnippetMobileStatus.UnknownError;

            string toSend = "";
            string cmd = Utils.Between(strRequest, "<!--BEGINMSG-->", "<!--ENDMSG-->");
            bool bNoComments = false;

            Program.DbgReport("Processing: " + cmd);

            if (!Snippet.SnippetXml.ObjectEntryDescribesFile(cmd))
            {
                Program.DbgReport("Starting deserialization...");
                try
                {
                    msg = (Snippet.SnippetMobileMessage)Snippet.SnippetXml.ReadObject(cmd, typeof(Snippet.SnippetMobileMessage));

                    Program.DbgReport("... deserialization done.");

                    if (string.IsNullOrEmpty(msg.Target))
                    {
                        throw (new Exception("No Target Specified"));
                    }

                    Program.DbgReport("Target: " + msg.Target);

                    ISnippetMobileSvc svc = Snippet.SnippetSvc.GetService(msg.Target);

                    if (svc != null)
                    {
                        Program.DbgReport("Got " + msg.Target);

                        res = svc.ProcessClientRequest(msg);

                        //toSend = SnippetXml.WriteObject(svc.CreateResponse(msg, res));

                        status = svc.FinalizeClientRequest(msg, res);

                        if (SnippetMobileStatus.OK == status)
                        {
                            toSend = SnippetXml.WriteObject(svc.CreateResponse(msg, res));
                        }
                        else
                        {
                            toSend = SnippetXml.WriteObject(CreateResponse(status));
                        }
                    }
                    else
                    {
                        toSend = SnippetXml.WriteObject(Snippet.SnippetSvc.CreateResponse(Snippet.SnippetMobileStatus.UnknowTarget));
                    }
                }
                catch (Exception x)
                {
                    Program.ProcessXcptInfo(x);

                    toSend = SnippetXml.WriteObject(Snippet.SnippetSvc.CreateResponse(Snippet.SnippetMobileStatus.InvalidFormat));
                }
            }
            else
            {
                switch (cmd)
                {
                    case "GetObject":
                        toSend = Snippet.Program.GetTestObjectAsXml();
                        bNoComments = true;
                        break;

                    default:
                        // no "echo back" any more!
                        //toSend = cmd;//"<!--BEGINRSP-->" + cmd + "<!--ENDRSP-->";
                        toSend = SnippetXml.WriteObject(Snippet.SnippetSvc.CreateResponse(Snippet.SnippetMobileStatus.InvalidFormat));
                        break;
                }
            }

            if (!bNoComments)
                toSend = "<!--BEGINRSP-->" + toSend + "<!--ENDRSP-->";
            //                toSend = "<!--BEGINRSP-->" + cmd + "<!--ENDRSP-->";

            toSend = toSend.Replace("utf-16", "utf-8"); // *grrrrr*

            Program.DbgReport("Response: " + toSend);

            return toSend;
        }

        public static SnippetMobileMessage CreateResponse(SnippetMobileStatus status, SnippetMobileMessage msg = null)
        {
            SnippetMobileMessage rsp = new SnippetMobileMessage();

            rsp.StatusCode = SnippetMobileResult.MessageFromStatus(status);

            if (msg != null)
            {
                rsp.DeviceID = msg.DeviceID;
                rsp.Target = msg.Target;
                rsp.Task = msg.Task;
                rsp.UserName = msg.UserName;
            }

            return rsp;
        }

        public static SnippetMobileMessage CreateResponse(SnippetMobileResult res)
        {
            SnippetMobileMessage rsp = new SnippetMobileMessage();

            rsp.StatusCode = SnippetMobileResult.MessageFromStatus(res.status);

            return rsp;
        }

#if SVCEMULATION
        public void Run()
        {
            OnStart(null);
        }
#endif

        private int ReadServices()
        {
            int i = 0;

            Program.DbgReport("... opening 'SOFTWARE\\Company\\SnippetSvc'");
            RegistryKey modules = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Company\\SnippetSvc");

            if (modules != null)
            {
                string[] asModules = modules.GetSubKeyNames();

                Program.DbgReport("... Modules: " + (asModules.Length - 1));

                foreach (string module in asModules)
                {
                    if (module == "Settings") continue; // skip 'Settings' subkey

                    Program.DbgReport("... \tfound service " + module);

                    RegistryKey mod = modules.OpenSubKey(module);

                    string strDllName = (string)mod.GetValue("DllName", "");

                    Program.DbgReport("... \t\tDllName: " + strDllName);

                    /* ---> Don't assume anything, the *full* path has to be given!
                                        if (!Path.IsPathRooted(strDllName))
                                        {
                                            strDllName = Path.GetFullPath(strDllName);
                                            Program.DbgReport("... \t\tassuming DllName to be: " + strDllName);
                                        }
                    */

                    try
                    {
                        Assembly asm = Assembly.LoadFrom(strDllName);
                        Type[] all = asm.GetTypes();

                        foreach (Type t in all)
                            Program.DbgReport(" - " + t.Name);

                        Type ty = asm.GetType("Snippet." + module);

                        ISnippetMobileSvc svc = (ISnippetMobileSvc)Activator.CreateInstance(ty);

                        dictSnippetMobileServices.Add(module, svc);
                        Program.DbgReport("... added " + module);
                        ++i;
                    }
                    catch (Exception x)
                    {
                        Program.ProcessXcptInfo(x);
                    }
                }
            }

            return i;
        }

        public SnippetSvc()
        {
            InitializeComponent();
            Program.DbgReport("SnippetSvc ctor");

            #region SnippetMobileServices

            ReadServices();
            #endregion
#if !SVCEMULATION
            eventLog = new System.Diagnostics.EventLog();
            if (!System.Diagnostics.EventLog.SourceExists("SnippetSvc"))
            {
                Program.DbgReport("... creating EventSource");
                System.Diagnostics.EventLog.CreateEventSource(
                    "SnippetSvc", "Application");
            }
            eventLog.Source = "SnippetSvc";
            eventLog.Log = "Application";

            // Update the service state to Start Pending.
            ReportServiceStatus(ServiceState.SERVICE_START_PENDING);
#endif
        }

        protected void ReportServiceStatus(ServiceState state, long dwWaitHint = 100000)
        {
#if !SVCEMULATION             
            ServiceStatus serviceStatus = new ServiceStatus();
            serviceStatus.dwCurrentState = state;
            serviceStatus.dwWaitHint = dwWaitHint;
            SetServiceStatus(this.ServiceHandle, ref serviceStatus);
#endif
        }

        protected override void OnStart(string[] args)
        {
            WriteEntry("SnippetSvc - OnStart()");

            // Update the service state to according to our init result.
            ReportServiceStatus(InitializeServerPool() ? ServiceState.SERVICE_RUNNING : ServiceState.SERVICE_STOPPED);
        }

        protected override void OnStop()
        {
            WriteEntry("SnippetSvc - OnStop()");

            TermEvent.Set();

            // Update the service state to Stopped.
            ReportServiceStatus(ServiceState.SERVICE_STOPPED);
        }

        protected bool InitializeServerPool()
        {
            //ServerInit si = new ServerInit(this, 0);
            int i = 0;

            servers = new WaitCallback[threads + 1 + 1]; // plus one SSL thread and one remoting thread

#if NONSSLSERVERS
            for (/*int i = 0*/; i < threads; ++i)
            {
                servers[i] = new WaitCallback(SnippetSvcThreadProc);
               
                if (!ThreadPool.QueueUserWorkItem(servers[i], new ServerInit(this, i))) return false;
            }
#endif
            ///* ---> no SSL for this test version
            for (/*int i = 0*/; i < threads; ++i)
            {
                Program.DbgReport("Starting SSL server...");
                servers[i] = new WaitCallback(SnippetSslThreadProc);
                if (!ThreadPool.QueueUserWorkItem(servers[i], new ServerInit(this, i)))
                {
                    Program.DbgReport("... error starting SSL server");
                    return false;
                }
                Program.DbgReport("... done");
            }
#if REMOTINGSUPPORT
            Program.DbgReport("Starting remoting server...");
            servers[i] = new WaitCallback(SnippetRemotingThreadProc);
            if (!ThreadPool.QueueUserWorkItem(servers[i], new ServerInit(this, i)))
            {
                Program.DbgReport("... error starting remoting server");
                return false;
            }
            Program.DbgReport("... done");
#endif
            //*/
            return true;
        }

        private void WriteEntry(string str)
        {
#if !SVCEMULATION
            eventLog.WriteEntry(str);
#endif
            Program.DbgReport(str);
        }

        static void SnippetSslThreadProc(Object obj)
        {
            ServerInit si = (ServerInit)obj;

            string strCert = Program.SslCertificateFile;

            Program.DbgReport("Starting SSL server instance " + si.ID);

            try
            {
                SslTcpServer.RunServer(strCert);
            }
            catch (Exception x)
            {
                Program.ProcessXcptInfo(x);
            }
        }

        static void SnippetRemotingThreadProc(Object obj)
        {
            ServerInit si = (ServerInit)obj;

            Program.DbgReport("Starting new remoting server instance " + si.ID);

            RemotingServer srv = new RemotingServer();

            SnippetSvc.TermEvent.WaitOne();

            Program.DbgReport("Terminating remoting server instance");
        }


        static void SnippetSvcThreadProc(Object obj)
        {
            ServerInit si = (ServerInit)obj;

            Program.DbgReport("Starting new server instance " + si.ID);

            Server srv = new Server();

            srv.Start();
        }

       private System.Diagnostics.EventLog eventLog;
        private WaitCallback[] servers = null;
        private static int threads = 1;
        private static EventWaitHandle TermEvent = new EventWaitHandle(false, EventResetMode.AutoReset);

        #region SnippetMobileServices
        // The dictionary to keep track of the services we manage
        private static Dictionary<string, ISnippetMobileSvc> dictSnippetMobileServices = new Dictionary<string, ISnippetMobileSvc>();
        #endregion
    }
    /*
* TODO: Keep in sync with SnippetMobileStringStatus!
*/
    public enum SnippetMobileStatus
    {
        OK = 0,
        UnknownError = 1,
        InvalidFormat = 2,
        UnknowTarget = 3,
        UnknownTask = 4,
        UnknownUser = 5,
        UnknownDevice = 6,
        InvalidConfiguration = 7,
        InvalidPassword = 8,
        NoData = 9,
        Busy = 10,
        UnauthorizedAccess = 11,
        IOError = 12
    };

    public class SnippetMobileResult
    {
        public SnippetMobileResult(SnippetMobileStatus s)
        {
            status = s;
        }
        public SnippetMobileResult(string s)
        {
            strPayload = s;
            status = SnippetMobileStatus.OK;
        }
        public SnippetMobileStatus status = SnippetMobileStatus.UnknownError;
        public string strPayload = null;

        public static string MessageFromStatus(SnippetMobileStatus status)
        {
            string result = "InternalError";

            try
            {
                result = SnippetMobileStringStatus[(int)status];
            }
            catch (IndexOutOfRangeException x)
            {
                Program.ProcessXcptInfo(x);
            }

            return result;
        }

        /*
        * TODO: Keep in sync with SnippetMobileStatus!
        */
        private static string[] SnippetMobileStringStatus = new string[]
        {
            "OK",                       // OK, no comment
            "UnknownError",             // An exception occured that could not be handled in a predefined manner
            "InvalidFormat",            // XML format was invalid (deserialization failed) or payload format is invalid
            "UnknownTarget",            // No handling facility was found (ATM only "WartManStock" is supported)
            "UnknownTask",              // neither "export" nor "import"
            "UnknownUser",              // User unknown
            "UnknownDevice",            // not relevant at the moment, device ID is unchecked
            "InvalidConfiguration",     // Service setup is faulty
            "InvalidPassword",          // Pwd does not match
            "NoData",                   // No export data available
            "Busy",                     // There's import data that hasn't been processed so far
            "UnauthorizedAccess",       // I/O target path not accessible (data files)
            "IOError",                  // read/Write error while accessing data
            "Ooops! Should not have happened...", // if that ever is *ever* displayed, we are in deep trouble....
            "Ooops! Should not have happened...",
            "Ooops! Should not have happened..."
        };
    }
}

