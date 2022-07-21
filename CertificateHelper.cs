namespace Microsoft.Dynamics.Commerce.Runtime.Services
{
    using System;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;

    /// <summary>
    /// Helper class for working with certificates.
    /// </summary>
    internal static class CertificateHelper
    {
        /// <summary>
        /// Retrieves the certificate using the specified thumbprint and optionally store name and store location.
        /// </summary>
        /// <param name="thumbprint">The certificate thumbprint to load.</param>
        /// <param name="storeName">The (optional) certificate store name. If null, My store name is used.</param>
        /// <param name="storeLocation">The (optional) certificate store location. If null, LocalMachine store location is used.</param>
        /// <param name="signature">Indicates (optional) if certificate is used for signature. If true certificate is used for signature. False if it is used for encryption.</param>
        /// <returns>
        /// The X509 certificate to encrypt, decrypt or sign the data blob.
        /// </returns>
        /// <remarks>
        /// Some validation is done to ensure that the loaded certificate can be used for RSA encryption/signature.
        /// </remarks>
        public static X509Certificate2 GetCertificateByThumbprint(string thumbprint, string storeName, string storeLocation, bool signature)
        {
            StoreName storeNameEnum;
            if (storeName == null || !Enum.TryParse<StoreName>(storeName, out storeNameEnum))
            {
                storeNameEnum = StoreName.My;
            }

            StoreLocation storeLocationEnum;
            if (storeLocation == null || !Enum.TryParse<StoreLocation>(storeLocation, out storeLocationEnum))
            {
                storeLocationEnum = StoreLocation.LocalMachine;
            }

            X509Store store = new X509Store(storeNameEnum, storeLocationEnum);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
            var certificate = certificates.Count > 0 ? certificates[0] : null;
            if (certificate == null)
            {
                string message = string.Format("The certificate '{0}' was not found in the {1}\\{2} certificate store.", thumbprint, storeNameEnum, storeLocationEnum);
                throw new NotSupportedException(message);
            }

            ValidateCertificate(certificate, signature);

            return certificate;
        }

        /// <summary>
        /// Validate entire certificate chain with custom validation policy and offline revocation list.
        /// </summary>
        /// <param name="certificate">The certificate to be validated.</param>
        /// <param name="verificationFlags">The verification flags to be used.</param>
        /// <param name="chainStatus">The array of invalid chain status.</param>
        /// <returns>Return True if certificate is valid False otherwise.</returns>
        public static bool ValidateCertificateChainOffline(X509Certificate2 certificate, X509VerificationFlags verificationFlags, out X509ChainStatus[] chainStatus)
        {
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.VerificationFlags = verificationFlags;
            chain.ChainPolicy.VerificationTime = DateTime.Now;
            chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 0);

            chainStatus = Array.Empty<X509ChainStatus>();
            bool isChainValid = chain.Build(certificate);
            if (!isChainValid)
            {
                chainStatus = chain.ChainStatus.ToArray();
            }

            return isChainValid;
        }

        private static void ValidateCertificate(X509Certificate2 certificate, bool signature)
        {
            if (certificate.HasPrivateKey == false)
            {
                string message = string.Format("The certificate '{0}' does not have a private key. A private key is required to encrypt data (otherwise it cannot be decrypted!).", certificate.ToString());
                throw new NotSupportedException(message);
            }

            if (string.IsNullOrWhiteSpace(signature ? certificate.PrivateKey.SignatureAlgorithm : certificate.PrivateKey.KeyExchangeAlgorithm))
            {
                string message = string.Format(
                    "The certificate '{0}' used for encryption must have SubjectKeySpec set to {1}.",
                    certificate.ToString(),
                    signature ? "signature" : "exchange");
                throw new NotSupportedException(message);
            }
        }
    }
}
