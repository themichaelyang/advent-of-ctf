require "resolv"

# Overview: https://www.cloudflare.com/learning/dns/dns-records/
# SRV, CAA, HTTPS, SVCB missing in the Resolv docs! Submit a PR
# Resolv::DNS::Resource::IN.constants.map(&:to_s) - types
RESOURCE_TYPES = [
  "A",
  "AAAA",
  "ANY",
  # "AFSDB",
  # "APL",
  "CAA",
  # "CDNSKEY",
  # "CDS",
  # "CERT",
  "CNAME",
  # "CSYNC",
  # "DHCID",
  # "DLV",
  # "DNAME",
  # "DNSKEY",
  # "DS",
  # "EUI48",
  # "EUI64",
  "HINFO",
  # "HIP",
  "HTTPS",
  # "IPSECKEY",
  # "KEY",
  # "KX",
  "LOC",
  "MX",
  "MINFO",
  # "NAPTR",
  "NS",
  # "NSEC",
  # "NSEC3",
  # "NSEC3PARAM",
  # "OPENPGPKEY",
  "PTR",
  # "RP",
  # "RRSIG",
  # "SIG",
  # "SMIMEA",
  "SOA",
  "SRV",
  # "SSHFP",
  "SVCB",
  # "TLSA",
  "TXT",
  "WKS"
  # "URI",
  # "ZONEMD",
]

# NS, CNAME, SOA, PTR, HINFO, MINFO, MX, TXT, LOC, ANY, CAA
#
# RESOURCE_TYPES = %w[
#   A
#   AAAA
#   ANY
#   CNAME
#   HINFO
#   MINFO
#   MX
#   NS
#   PTR
#   SOA
#   TXT
#   WKS
# ]

def dns_records(domain)
  Resolv::DNS.open do |dns|
    RESOURCE_TYPES.map { |type|
      type_class = Resolv::DNS::Resource::IN.const_get(type)
      [type, dns.getresources(domain, type_class)]
    }
      .reject { |type, resources| resources.empty? }
      .to_h
  end
end

hash = [
  "krampus.csd.lol",
  # "www.krampus.csd.lol",
  "mail.krampus.csd.lol",
  "_spf.krampus.csd.lol",
  # https://en.wikipedia.org/wiki/DMARC
  "_dmarc.krampus.csd.lol",
  "ops.krampus.csd.lol",
  "_ldap._tcp.krampus.csd.lol",
  "_kerberos._tcp.krampus.csd.lol",
  "_metrics._tcp.krampus.csd.lol",
  "beacon.krampus.csd.lol",
  # "config=ZXhmaWwua3JhbXB1cy5jc2QubG9s=="
  "dc01.krampus.csd.lol",
  "exfil.krampus.csd.lol",
  # ["status=active; auth=dkim; selector=syndicate"],
  "syndicate._domainkey.krampus.csd.lol"
].to_h do |domain|
  [domain, dns_records(domain)]
end

# TXT: v=spf1 include:_spf.krampus.csd.lol -all
# MX: mail.krampus.csd.lol.

# https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/
# https://www.cloudflare.com/learning/dns/dns-records/dns-mx-record/
# https://www.cloudflare.com/learning/dns/dns-records/dns-a-record/
# https://mxtoolbox.com/dmarc/spf/what-is-an-spf-record/
# https://en.wikipedia.org/wiki/Sender_Policy_Framework
# https://www.cloudflare.com/learning/dns/dns-records/dns-dkim-record/

pp hash

require "base64"
p Base64.decode64("ZXhmaWwua3JhbXB1cy5jc2QubG9s==")
p Base64.decode64("Y3Nke2RuNV9tMTlIVF9CM19LMU5ENF9XME5LeX0=")
