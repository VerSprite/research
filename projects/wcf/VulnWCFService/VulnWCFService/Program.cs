using System;
using System.ServiceModel;
using System.ServiceProcess;

namespace VulnWCFService
{
    [ServiceContract]
    public interface IVulnService
    {
        [OperationContract]
        void RunMe(string str);
    }

    public class VulnService : IVulnService
    {
        public void RunMe(string str)
        {
            Console.WriteLine(str);
            System.Diagnostics.Process.Start("CMD.exe", "/c " + str);
        }
    }

    public class VulnWCFService : ServiceBase
    {
        public ServiceHost serviceHost = null;

        public VulnWCFService()
        {
            ServiceName = "VulnWCFService";
        }

        public static void Main()
        {
            ServiceBase.Run(new VulnWCFService());
        }

        protected override void OnStart(string[] args)
        {

            if (serviceHost != null)
            {
                serviceHost.Close();
            }

            Uri baseAddress = new Uri("net.pipe://localhost/vulnservice/runme");
            serviceHost = new ServiceHost(typeof(VulnService), baseAddress);
            NetNamedPipeBinding binding = new NetNamedPipeBinding();

            try
            {
                serviceHost.AddServiceEndpoint(typeof(IVulnService), binding, baseAddress);
                serviceHost.Open();
            }
            catch (CommunicationException ce)
            {
                serviceHost.Abort();
            }

        }

        protected override void OnStop()
        {
            if (serviceHost != null)
            {
                serviceHost.Close();
                serviceHost = null;
            }
        }
    }
}