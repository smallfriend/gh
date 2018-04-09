using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.IO;
using System.Xml.Linq;

namespace MeasuredBootTool
{
    class Program
    {
        private static string AIK_NAME = "MbtAik";
        private static string PCPTOOL = "PcpTool.exe";

        static bool RunPcpTool(
            string clArgs,
            out string output,
            out int exitCode,
            out string errorMessage)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo(PCPTOOL);
            startInfo.Arguments = String.Format(clArgs);
            startInfo.CreateNoWindow = true;
            startInfo.RedirectStandardOutput = true;
            startInfo.UseShellExecute = false;

            Process pt = Process.Start(startInfo);
            output = pt.StandardOutput.ReadToEnd();
            pt.WaitForExit();
            exitCode = pt.ExitCode;

            if (0 != exitCode)
            {
                errorMessage = String.Format(
                    "Error: pcptool.exe {0} : {1}",
                    clArgs,
                    exitCode);
                return false;
            }
            else
            {
                errorMessage = null;
                return true;
            }
        }

        static void Main(string[] args)
        {
            string outStr = null;
            int exitCode = 0;
            string errorMessage = null;
            string aikNonce = null;
            string attestationNonce = null;
            string aikPubFileName = Path.GetTempFileName();
            
            //
            // Simulate getting an AIK creation nonce from the server
            //

            aikNonce = "1234";

            //
            // Create a temp file for the identity binding data
            //

            string idBindingFileName = Path.GetTempFileName();

            //
            // Create a new AIK
            //

            if (false == RunPcpTool(
                String.Format(
                    "CreateAIK {0} {1} {2}",
                    AIK_NAME,
                    idBindingFileName,
                    aikNonce),
                out outStr,
                out exitCode,
                out errorMessage))
            {
                Console.WriteLine(errorMessage);
                return;
            }

            //
            // Save the AIK public
            //

            if (false == RunPcpTool(
                String.Format(
                    "GetPubAIK {0} {1}",
                    idBindingFileName,
                    aikPubFileName),
                out outStr,
                out exitCode,
                out errorMessage))
            {
                Console.WriteLine(errorMessage);
                return;
            }

            //
            // Get the EK public
            //

            string ekPubFileName = Path.GetTempFileName();
            if (false == RunPcpTool(
                String.Format(
                    "GetEK {0}",
                    ekPubFileName),
                out outStr,
                out exitCode,
                out errorMessage))
            {
                Console.WriteLine(errorMessage);
                return;
            }

            //
            // Simulate the server challenging the AIK
            //

            string challengeBlobFileName = Path.GetTempFileName();
            string serverSecret = "ServerSecret";
            if (false == RunPcpTool(
                String.Format(
                    "ChallengeAIK {0} {1} {2} {3} {4}",
                    idBindingFileName,
                    ekPubFileName,
                    serverSecret,
                    challengeBlobFileName,
                    aikNonce),
                out outStr,
                out exitCode,
                out errorMessage))
            {
                Console.WriteLine(errorMessage);
                return;
            }

            //
            // Client responds to the challenge
            //

            if (false == RunPcpTool(
                String.Format(
                    "ActivateAIK {0} {1}",
                    AIK_NAME,
                    challengeBlobFileName),
                out outStr,
                out exitCode,
                out errorMessage))
            {
                Console.WriteLine(errorMessage);
                return;
            }

            if (false == outStr.Contains(serverSecret))
            {
                Console.WriteLine("Error: failed to decrypt server challenge");
                return;
            }

            //
            // Simulate getting an attestation nonce from the server
            //

            attestationNonce = "4321";

            //
            // Get attestation data
            //

            string attestationDataFileName = Path.GetTempFileName();
            if (false == RunPcpTool(
                String.Format(
                    "GetPlatformAttestation {0} {1} {2}",
                    AIK_NAME,
                    attestationDataFileName,
                    attestationNonce),
                out outStr,
                out exitCode,
                out errorMessage))
            {
                Console.WriteLine(errorMessage);
                return;
            }

            //
            // Verify the attestation log signature
            //

            if (false == RunPcpTool(
                String.Format(
                    "ValidatePlatformAttestation {0} {1} {2}",
                    attestationDataFileName,
                    aikPubFileName,
                    attestationNonce),
                out outStr,
                out exitCode,
                out errorMessage))
            {
                Console.WriteLine(errorMessage);
                return;
            }

            //
            // Turn the attestation log into XML
            //

            string attXml = null;
            if (false == RunPcpTool(
                String.Format(
                    "DisplayPlatformAttestationFile {0}",
                    attestationDataFileName),
                out attXml,
                out exitCode,
                out errorMessage))
            {
                Console.WriteLine(errorMessage);
                return;
            }

            //
            // Delete temp files
            //

            File.Delete(ekPubFileName);
            File.Delete(challengeBlobFileName);
            File.Delete(idBindingFileName);
            File.Delete(aikPubFileName);
            File.Delete(attestationDataFileName);

            //
            // Load the attestation XML output
            //

            string elamDriverPath = null;
            Dictionary<string, bool> bootBins = new Dictionary<string, bool>();
            XDocument xDoc = XDocument.Parse(attXml);
            foreach (XElement ele in xDoc.Descendants("LoadedModule_Aggregation"))
            {
                if (null == ele.Element("FilePath"))
                    continue;

                string loadedModuleFilePath = ele.Element("FilePath").Value;

                if (null != ele.Element("ImageValidated"))
                {
                    if (0 == String.Compare(
                        "true",
                        ele.Element("ImageValidated").Value,
                        true))
                    {
                        if (true == bootBins.ContainsKey(loadedModuleFilePath))
                            bootBins.Remove(loadedModuleFilePath);
                        bootBins.Add(loadedModuleFilePath, true);
                    }
                    else
                    {
                        if (false == bootBins.ContainsKey(loadedModuleFilePath))
                            bootBins.Add(loadedModuleFilePath, false);
                    }
                }
                else
                {
                    if (false == bootBins.ContainsKey(loadedModuleFilePath))
                        bootBins.Add(loadedModuleFilePath, false);
                }

                //
                // Check for an ELAM driver
                //

                XElement authorityHashEle = ele.Element(
                    "AuthoritySHA1Thumbprint");
                if (null == authorityHashEle)
                    continue;

                if (true == authorityHashEle.Value.Contains(
                    "c781d24b3d08cfab8a61b960e77c0cd6316e3d56"))
                {
                    elamDriverPath = loadedModuleFilePath;
                }
            }

            //
            // BitLocker check
            //

            bool bitLockerTpm = false;
            foreach (XElement ele in xDoc.Descendants("BitLocker_Unlock"))
            {
                XElement blKeyEle = ele.Element("BitLockerKeyFlag");
                if (null == blKeyEle)
                    continue;

                string blKey = blKeyEle.Value;
                if (true == blKey.Contains("TPM"))
                {
                    bitLockerTpm = true;
                    break;
                }
            }

            //
            // Integrity services check
            //

            bool integrityServices = false;
            foreach (XElement ele in xDoc.Descendants("IntegrityServices"))
            {
                if (0 == String.Compare(ele.Value, "enabled", true))
                    integrityServices = true;
            }

            //
            // Display results
            //

            Console.WriteLine("BitLocker (TPM) = {0}", bitLockerTpm);
            Console.WriteLine("Integrity services = {0}", integrityServices);

            Console.WriteLine("Early boot binaries:");
            foreach (string key in bootBins.Keys)
            {
                Console.WriteLine(
                    " {0}{1} -- {2}",
                    key,
                    0 == String.Compare(key, elamDriverPath) ? " (ELAM)" : "",
                    true == bootBins[key] ? "SIGNED" : "UNSIGNED!");
            }
        }
    }
}
