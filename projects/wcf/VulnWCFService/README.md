# VulnWCFService

**VulnWCFService** is a .NET Windows service written in C# that is designed to demonstrate an insecure WCF endpoint. Once installed, a client program may be used to remotely invoke the service's **RunMe** method resulting in the execution of a privileged application. This type of vulnerability has been found within several insecure Windows services by VerSrite research.

After a successful build, this service may be installed used the service control command-line utility, [**Sc.exe**](https://support.microsoft.com/en-us/help/251192/how-to-create-a-windows-service-by-using-sc-exe):

Click here to read VerSprite's article, ["Abusing Insecure WCF Endpoints"](https://versprite.com/blog/security-research/abusing-insecure-wcf-endpoints/).
