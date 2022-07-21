// See https://aka.ms/new-console-template for more information
using Microsoft.Dynamics.Commerce.Runtime.Services;

Console.WriteLine(CertificateHelper.GetCertificateByThumbprint("0D920D649950FC86786B7270655554810052DAD4", "My", "LocalMachine", true));