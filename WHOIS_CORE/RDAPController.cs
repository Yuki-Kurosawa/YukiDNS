using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Microsoft.AspNetCore.Mvc;

namespace YukiDNS.WHOIS_CORE
{
    [Route("[controller]")]
    [ApiController]
    //[EnableCors("DefaultCorsPolicy")]
    public class RDAPController : ControllerBase
    {
        private static readonly string[] RdapConformance = new[]
        {
            "rdap_level_0",
            "icann_rdap_response_profile_1",
            "icann_rdap_technical_implementation_guide_1"
        };

        /// <summary>
        /// RDAP service discovery (RFC 7484 §4): advertise the top-level
        /// lookup URLs this server is able to serve.
        /// </summary>
        [HttpGet, Produces("application/rdap+json")]
        public object ServiceDiscovery()
        {
            string baseUrl = BuildBaseUrl();

            return new
            {
                rdapConformance = RdapConformance,
                services = new[]
                {
                    new object[] { new[] { "domain" }, new[] { baseUrl + "/RDAP/domain/" } },
                    new object[] { new[] { "nameserver" }, new[] { baseUrl + "/RDAP/nameserver/" } },
                    new object[] { new[] { "entity" }, new[] { baseUrl + "/RDAP/entity/" } }
                }
            };
        }

        [HttpGet, Produces("application/rdap+json"), Route("test")]
        public object Test()
        {
            return new { };
        }

        /// <summary>
        /// RDAP domain lookup (RFC 7482 §3.1 / RFC 7483 §5.3).
        /// </summary>
        [HttpGet, Produces("application/rdap+json"), Route("domain/{name}")]
        public object Resolve(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return Error(400, "Bad Request", "no domain name specified.");
            }

            WHOISDBObject domain = WHOISService.whoisdb
                .FirstOrDefault(x => string.Equals(x.DomainName, name, StringComparison.OrdinalIgnoreCase));

            if (domain == null)
            {
                return Error(404, "Not Found", $"no match for domain \"{name.ToUpperInvariant()}\".");
            }

            return BuildDomainResponse(domain);
        }

        /// <summary>
        /// RDAP nameserver lookup (RFC 7482 §3.2 / RFC 7483 §5.4).
        /// </summary>
        [HttpGet, Produces("application/rdap+json"), Route("nameserver/{name}")]
        public object ResolveNameServer(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return Error(400, "Bad Request", "no nameserver name specified.");
            }

            WHOISDBObject domain = WHOISService.whoisdb
                .FirstOrDefault(x => x.NameServer != null &&
                    x.NameServer.Any(ns => string.Equals(ns, name, StringComparison.OrdinalIgnoreCase)));

            if (domain == null)
            {
                return Error(404, "Not Found", $"no match for nameserver \"{name.ToUpperInvariant()}\".");
            }

            string ns = domain.NameServer.First(n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase));

            return new
            {
                rdapConformance = RdapConformance,
                objectClassName = "nameserver",
                ldhName = ns,
                links = new[]
                {
                    BuildLink("self", $"/RDAP/nameserver/{ns}"),
                    BuildLink("related", $"/RDAP/domain/{domain.DomainName}")
                }
            };
        }

        /// <summary>
        /// RDAP entity lookup (RFC 7482 §3.3 / RFC 7483 §5.7).
        /// Entities are derived from the contact records stored per domain.
        /// </summary>
        [HttpGet, Produces("application/rdap+json"), Route("entity/{handle}")]
        public object ResolveEntity(string handle)
        {
            if (string.IsNullOrWhiteSpace(handle))
            {
                return Error(400, "Bad Request", "no entity handle specified.");
            }

            foreach (WHOISDBObject domain in WHOISService.whoisdb)
            {
                foreach ((string role, RegistryInfoObject contact) in Contacts(domain))
                {
                    if (string.Equals(contact.ID, handle, StringComparison.OrdinalIgnoreCase))
                    {
                        return BuildEntityResponse(role, contact, domain);
                    }
                }
            }

            return Error(404, "Not Found", $"no match for entity \"{handle.ToUpperInvariant()}\".");
        }

        #region Response Builders

        private RDAPResponseProfile BuildDomainResponse(WHOISDBObject value)
        {
            return new RDAPResponseProfile
            {
                rdapConformance = RdapConformance,
                objectClassName = "domain",
                handle = value.RegistryDomainID,
                ldhName = value.DomainName,
                status = BuildDomainStatusArray(value.DomainStatus),
                port43 = value.RegistrarWHOISServer,
                events = BuildDomainEvents(value),
                entities = BuildEntities(value),
                nameservers = BuildNameServers(value),
                links = new List<RDAPLink>
                {
                    BuildLink("self", $"/RDAP/domain/{value.DomainName}")
                },
                notices = new List<RDAPNotice>
                {
                    new RDAPNotice
                    {
                        title = new[] { "Terms of Service" },
                        description = new[]
                        {
                            "This is the YukiDNS RDAP server. The data in this response is provided for information purposes only."
                        }
                    }
                }
            };
        }

        private RDAPEntity BuildEntityResponse(string role, RegistryInfoObject contact, WHOISDBObject domain)
        {
            return new RDAPEntity
            {
                objectClassName = "entity",
                handle = contact.ID,
                roles = new[] { role },
                vcardArray = BuildVCard(contact),
                links = new List<RDAPLink>
                {
                    BuildLink("self", $"/RDAP/entity/{contact.ID}"),
                    BuildLink("related", $"/RDAP/domain/{domain.DomainName}")
                }
            };
        }

        private List<RDAPEvent> BuildDomainEvents(WHOISDBObject value)
        {
            List<RDAPEvent> ret = new List<RDAPEvent>();
            AddEvent(ret, "registration", value.CreationDate);
            AddEvent(ret, "expiration", value.RegistryExpiryDate);
            AddEvent(ret, "last changed", value.UpdatedDate);
            AddEvent(ret, "last update of RDAP database", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));
            return ret;
        }

        private static void AddEvent(List<RDAPEvent> list, string action, string date)
        {
            if (!string.IsNullOrEmpty(date))
            {
                list.Add(new RDAPEvent { eventAction = action, eventDate = date });
            }
        }

        private List<RDAPEntity> BuildEntities(WHOISDBObject value)
        {
            List<RDAPEntity> ret = new List<RDAPEntity>();

            foreach ((string role, RegistryInfoObject contact) in Contacts(value))
            {
                ret.Add(BuildEntityResponse(role, contact, value));
            }

            return ret;
        }

        private List<RDAPNameServer> BuildNameServers(WHOISDBObject value)
        {
            List<RDAPNameServer> ret = new List<RDAPNameServer>();

            if (value.NameServer == null)
            {
                return ret;
            }

            foreach (string ns in value.NameServer)
            {
                ret.Add(new RDAPNameServer
                {
                    objectClassName = "nameserver",
                    ldhName = ns,
                    links = new List<RDAPLink>
                    {
                        BuildLink("self", $"/RDAP/nameserver/{ns}")
                    }
                });
            }

            return ret;
        }

        private static IEnumerable<(string Role, RegistryInfoObject Contact)> Contacts(WHOISDBObject value)
        {
            if (value.Registrant != null) yield return ("registrant", value.Registrant);
            if (value.Admin != null) yield return ("administrative", value.Admin);
            if (value.Tech != null) yield return ("technical", value.Tech);
            if (value.Billing != null) yield return ("billing", value.Billing);
        }

        /// <summary>
        /// Build a jCard (RFC 7095) vcardArray from a registry contact object.
        /// </summary>
        private static object[] BuildVCard(RegistryInfoObject contact)
        {
            List<object> fields = new List<object>();

            fields.Add(new object[] { "version", new { }, "text", "4.0" });
            fields.Add(new object[] { "kind", new { }, "text", string.IsNullOrEmpty(contact.Name) ? "org" : "individual" });

            if (!string.IsNullOrEmpty(contact.Name))
            {
                fields.Add(new object[] { "fn", new { }, "text", contact.Name });
            }

            if (!string.IsNullOrEmpty(contact.Organization))
            {
                fields.Add(new object[] { "org", new { }, "text", contact.Organization });
            }

            if (!string.IsNullOrEmpty(contact.Street) ||
                !string.IsNullOrEmpty(contact.City) ||
                !string.IsNullOrEmpty(contact.StateProvince) ||
                !string.IsNullOrEmpty(contact.PostalCode) ||
                !string.IsNullOrEmpty(contact.Country))
            {
                fields.Add(new object[]
                {
                    "adr",
                    new { type = "work" },
                    "text",
                    new[]
                    {
                        "", "",
                        contact.Street ?? "",
                        contact.City ?? "",
                        contact.StateProvince ?? "",
                        contact.PostalCode ?? "",
                        contact.Country ?? ""
                    }
                });
            }

            if (!string.IsNullOrEmpty(contact.Phone))
            {
                fields.Add(new object[] { "tel", new { type = "voice" }, "text", contact.Phone });
            }

            if (!string.IsNullOrEmpty(contact.Fax))
            {
                fields.Add(new object[] { "tel", new { type = "fax" }, "text", contact.Fax });
            }

            if (!string.IsNullOrEmpty(contact.Email))
            {
                fields.Add(new object[] { "email", new { }, "text", contact.Email });
            }

            return new object[] { "vcard", fields.ToArray() };
        }

        private static string[] BuildDomainStatusArray(DomainEPPStatus[] domainStatus)
        {
            List<string> ret = new List<string>();

            if (domainStatus == null)
            {
                return ret.ToArray();
            }

            foreach (DomainEPPStatus i in domainStatus)
            {
                MemberInfo propInfo = i.GetType().GetMember(i.ToString()).First();
                string propDesc = ((RdapStatusAttribute)propInfo.GetCustomAttributes(typeof(RdapStatusAttribute), false).FirstOrDefault())?.Description;
                if (!string.IsNullOrEmpty(propDesc))
                {
                    ret.Add(propDesc);
                }
            }

            return ret.ToArray();
        }

        #endregion

        #region Helpers

        private RDAPLink BuildLink(string rel, string path)
        {
            return new RDAPLink
            {
                value = BuildBaseUrl() + path,
                rel = rel,
                href = path,
                type = "application/rdap+json"
            };
        }

        private string BuildBaseUrl()
        {
            return $"{Request.Scheme}://{Request.Host}";
        }

        private ObjectResult Error(int code, string title, string description)
        {
            RDAPError err = new RDAPError
            {
                rdapConformance = RdapConformance,
                errorCode = code,
                title = title,
                description = new[] { description }
            };

            return StatusCode(code, err);
        }

        #endregion
    }
}
