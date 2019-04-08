﻿using System;
using System.Collections.Generic;
using System.Linq;
using static System.FormattableString;

namespace OhadSoft.AzureLetsEncrypt.Renewal.Management
{
    public sealed class RenewalParameters : IEquatable<RenewalParameters>
    {
        public Guid SubscriptionId { get; }
        public string TenantId { get; }
        public string ResourceGroup { get; }
        public string WebApp { get; }
        public IReadOnlyList<string> Hosts { get; }
        public string Email { get; }
        public Guid ClientId { get; }
        public string ClientSecret { get; }
        public string ServicePlanResourceGroup { get; }
        public string SiteSlotName { get; }
        public string GroupName { get; }
        public bool UseIpBasedSsl { get; }
        public int RsaKeyLength { get; }
        public Uri AcmeBaseUri { get; }
        public string WebRootPath { get; }
        public int RenewXNumberOfDaysBeforeExpiration { get; }
        public Uri AuthenticationUri { get; }
        public Uri AzureTokenAudience { get; }
        public Uri AzureManagementEndpoint { get; }
        public string AzureDefaultWebsiteDomainName { get; }

        public RenewalParameters(
            Guid subscriptionId,
            string tenantId,
            string resourceGroup,
            string webApp,
            IReadOnlyList<string> hosts,
            string email,
            Guid clientId,
            string clientSecret,
            string servicePlanResourceGroup = null,
            string groupName = null,
            string siteSlotName = null,
            bool useIpBasedSsl = false,
            int rsaKeyLength = 2048,
            Uri acmeBaseUri = null,
            string webRootPath = null,
            int renewXNumberOfDaysBeforeExpiration = 22,
            Uri authenticationUri = null,
            Uri azureTokenAudience = null,
            Uri azureManagementEndpoint = null,
            string azureDefaultWebsiteDomainName = null)
        {
            SubscriptionId = VerifyGuid(subscriptionId, nameof(subscriptionId));
            TenantId = VerifyString(tenantId, nameof(tenantId));
            ResourceGroup = VerifyString(resourceGroup, nameof(resourceGroup));
            WebApp = VerifyString(webApp, nameof(webApp));
            Hosts = VerifyHosts(hosts, nameof(hosts));
            Email = VerifyEmail(email, nameof(email));
            ClientId = VerifyGuid(clientId, nameof(clientId));
            ClientSecret = VerifyString(clientSecret, nameof(clientSecret), allowWhitespace: true);
            ServicePlanResourceGroup = VerifyOptionalString(servicePlanResourceGroup, nameof(servicePlanResourceGroup));
            GroupName = VerifyOptionalString(groupName, nameof(groupName));
            SiteSlotName = VerifyOptionalString(siteSlotName, nameof(siteSlotName));
            UseIpBasedSsl = useIpBasedSsl;
            RsaKeyLength = VerifyPositiveInteger(rsaKeyLength, nameof(rsaKeyLength));
            AcmeBaseUri = VerifyOptionalUri(acmeBaseUri, nameof(acmeBaseUri));
            WebRootPath = VerifyOptionalString(webRootPath, nameof(webRootPath));
            RenewXNumberOfDaysBeforeExpiration = renewXNumberOfDaysBeforeExpiration;
            AuthenticationUri = VerifyOptionalUri(authenticationUri, nameof(authenticationUri));
            AzureTokenAudience = VerifyOptionalUri(azureTokenAudience, nameof(azureTokenAudience));
            AzureManagementEndpoint = VerifyOptionalUri(azureManagementEndpoint, nameof(azureManagementEndpoint));
            AzureDefaultWebsiteDomainName = VerifyOptionalHostName(azureDefaultWebsiteDomainName, nameof(azureDefaultWebsiteDomainName));
        }

        private static string VerifyOptionalHostName(string hostName, string name)
        {
            return hostName == null || Uri.CheckHostName(hostName) != UriHostNameType.Unknown
                ? hostName
                : throw new ArgumentException("Internet host name must be valid", name);
        }

        private static int VerifyPositiveInteger(int num, string name)
        {
            return num > 0
                ? num
                : throw new ArgumentException("Integer must be positive", name);
        }

        private static string VerifyOptionalString(string str, string name)
        {
            return str == null || !str.All(Char.IsWhiteSpace)
                ? str
                : throw new ArgumentException("String must be either null or non-whitespace", name);
        }

        private static IReadOnlyList<string> VerifyHosts(IReadOnlyList<string> hosts, string name)
        {
            return hosts != null && hosts.Count > 0 && hosts.All(h => Uri.CheckHostName(h) != UriHostNameType.Unknown)
                ? hosts
                : throw new ArgumentException("Host collection must be non-null, contain at least one element, and contain valid host names", name);
        }

        private static string VerifyEmail(string email, string name)
        {
            return !String.IsNullOrWhiteSpace(email) && email.Contains("@") && email.Length >= 3 && email.Length <= 254
                   && !email.StartsWith("@", StringComparison.OrdinalIgnoreCase) && !email.EndsWith("@", StringComparison.OrdinalIgnoreCase)
                ? email
                : throw new ArgumentException("E-mail address must not be null and must be valid", name);
        }

        private static string VerifyString(string str, string name, bool allowWhitespace = false)
        {
            var valid = allowWhitespace ? !String.IsNullOrEmpty(str) : !String.IsNullOrWhiteSpace(str);
            return valid
                ? str
                : throw new ArgumentException("String cannot be null or whitespace", name);
        }

        private static Guid VerifyGuid(Guid guid, string name)
        {
            return guid != default
                ? guid
                : throw new ArgumentException("GUID cannot be empty", name);
        }

        private static Uri VerifyOptionalUri(Uri uri, string name)
        {
            return uri == null || uri.IsAbsoluteUri
                ? uri
                : throw new ArgumentException("URI must be either null or absolute", name);
        }

        public override string ToString()
        {
            return Invariant($"{nameof(SubscriptionId)}: {SubscriptionId}, {nameof(TenantId)}: {TenantId}, {nameof(ResourceGroup)}: {ResourceGroup}, {nameof(WebApp)}: {WebApp}, {nameof(Hosts)}: {String.Join(", ", Hosts)}, {nameof(Email)}: {Email}, {nameof(ClientId)}: {ClientId}, {nameof(ClientSecret)}: <SCRUBBED>, {nameof(ServicePlanResourceGroup)}: {ServicePlanResourceGroup}, {nameof(GroupName)}: {GroupName}, {nameof(SiteSlotName)}: {SiteSlotName}, {nameof(UseIpBasedSsl)}: {UseIpBasedSsl}, {nameof(RsaKeyLength)}: {RsaKeyLength}, {nameof(AcmeBaseUri)}: {AcmeBaseUri}, {nameof(RenewXNumberOfDaysBeforeExpiration)}: {RenewXNumberOfDaysBeforeExpiration}, {nameof(WebRootPath)}: {WebRootPath}, {nameof(AuthenticationUri)}: {AuthenticationUri}, {nameof(AzureTokenAudience)}: {AzureTokenAudience}, {nameof(AzureManagementEndpoint)}: {AzureManagementEndpoint}, {nameof(AzureDefaultWebsiteDomainName)}: {AzureDefaultWebsiteDomainName}");
        }

        public bool Equals(RenewalParameters other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return SubscriptionId.Equals(other.SubscriptionId)
                   && string.Equals(TenantId, other.TenantId)
                   && string.Equals(ResourceGroup, other.ResourceGroup)
                   && string.Equals(WebApp, other.WebApp)
                   && Hosts.SequenceEqual(other.Hosts)
                   && string.Equals(Email, other.Email)
                   && ClientId.Equals(other.ClientId)
                   && string.Equals(ClientSecret, other.ClientSecret)
                   && string.Equals(ServicePlanResourceGroup, other.ServicePlanResourceGroup)
                   && string.Equals(SiteSlotName, other.SiteSlotName)
                   && string.Equals(GroupName, other.GroupName)
                   && UseIpBasedSsl == other.UseIpBasedSsl
                   && RsaKeyLength == other.RsaKeyLength
                   && Equals(AcmeBaseUri, other.AcmeBaseUri)
                   && string.Equals(WebRootPath, other.WebRootPath)
                   && RenewXNumberOfDaysBeforeExpiration == other.RenewXNumberOfDaysBeforeExpiration
                   && Equals(AuthenticationUri, other.AuthenticationUri)
                   && Equals(AzureTokenAudience, other.AzureTokenAudience)
                   && Equals(AzureManagementEndpoint, other.AzureManagementEndpoint)
                   && string.Equals(AzureDefaultWebsiteDomainName, other.AzureDefaultWebsiteDomainName);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            return obj is RenewalParameters other && Equals(other);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = SubscriptionId.GetHashCode();
                hashCode = (hashCode * 397) ^ (TenantId != null ? TenantId.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (ResourceGroup != null ? ResourceGroup.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (WebApp != null ? WebApp.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (Hosts != null ? Hosts.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (Email != null ? Email.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ ClientId.GetHashCode();
                hashCode = (hashCode * 397) ^ (ClientSecret != null ? ClientSecret.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (ServicePlanResourceGroup != null ? ServicePlanResourceGroup.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (SiteSlotName != null ? SiteSlotName.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (GroupName != null ? GroupName.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ UseIpBasedSsl.GetHashCode();
                hashCode = (hashCode * 397) ^ RsaKeyLength;
                hashCode = (hashCode * 397) ^ (AcmeBaseUri != null ? AcmeBaseUri.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (WebRootPath != null ? WebRootPath.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ RenewXNumberOfDaysBeforeExpiration;
                hashCode = (hashCode * 397) ^ (AuthenticationUri != null ? AuthenticationUri.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (AzureTokenAudience != null ? AzureTokenAudience.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (AzureManagementEndpoint != null ? AzureManagementEndpoint.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (AzureDefaultWebsiteDomainName != null ? AzureDefaultWebsiteDomainName.GetHashCode() : 0);
                return hashCode;
            }
        }
    }
}