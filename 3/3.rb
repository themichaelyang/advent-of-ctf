require "resolv"

# References:
# - https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/
# - https://www.cloudflare.com/learning/dns/dns-records/dns-mx-record/
# - https://www.cloudflare.com/learning/dns/dns-records/dns-a-record/
# - https://mxtoolbox.com/dmarc/spf/what-is-an-spf-record/
# - https://en.wikipedia.org/wiki/Sender_Policy_Framework
# - https://www.cloudflare.com/learning/dns/dns-records/dns-dkim-record/

# Overview: https://www.cloudflare.com/learning/dns/dns-records/

# SRV, CAA, HTTPS, SVCB missing in the Resolv docs! Submit a PR
# Resolv::DNS::Resource::IN.constants.map(&:to_s) - types
RESOURCE_TYPES = [
  "A",
  "AAAA",
  "ANY",
  "CAA",
  "CNAME",
  "HINFO",
  "HTTPS",
  "LOC",
  "MX",
  "MINFO",
  "NS",
  "PTR",
  "SOA",
  "SRV",
  "SVCB",
  "TXT",
  "WKS"
]

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

# {"krampus.csd.lol" =>
#   {"MX" =>
#     [#<Resolv::DNS::Resource::Type15_Class1:0x00000001044b6338
#       @exchange=#<Resolv::DNS::Name: mail.krampus.csd.lol.>,
#       @preference=10,
#       @ttl=300>],
#    "TXT" =>
#     [#<Resolv::DNS::Resource::Type16_Class1:0x0000000104648570
#       @strings=["v=spf1 include:_spf.krampus.csd.lol -all"],
#       @ttl=300>]},
#  "mail.krampus.csd.lol" =>
#   {"A" =>
#     [#<Resolv::DNS::Resource::IN::A:0x00000001046436d8
#       @address=#<Resolv::IPv4 127.0.0.1>,
#       @ttl=300>]},
#  "_spf.krampus.csd.lol" =>
#   {"TXT" =>
#     [#<Resolv::DNS::Resource::Type16_Class1:0x000000010444bee8
#       @strings=["v=spf1 ip4:203.0.113.0/24 ~all"],
#       @ttl=300>]},
#  "_dmarc.krampus.csd.lol" =>
#   {"TXT" =>
#     [#<Resolv::DNS::Resource::Type16_Class1:0x000000010464e5b0
#       @strings=
#        ["v=DMARC1; p=reject; rua=mailto:dmarc@krampus.csd.lol; ruf=mailto:forensics@ops.krampus.csd.lol; fo=1; adkim=s; aspf=s"],
#       @ttl=300>]},
#  "ops.krampus.csd.lol" =>
#   {"TXT" =>
#     [#<Resolv::DNS::Resource::Type16_Class1:0x00000001046e96c8
#       @strings=
#        ["internal-services: _ldap._tcp.krampus.csd.lol _kerberos._tcp.krampus.csd.lol _metrics._tcp.krampus.csd.lol"],
#       @ttl=300>]},
#  "_ldap._tcp.krampus.csd.lol" =>
#   {"SRV" =>
#     [#<Resolv::DNS::Resource::IN::SRV:0x00000001042da910
#       @port=389,
#       @priority=0,
#       @target=#<Resolv::DNS::Name: dc01.krampus.csd.lol.>,
#       @ttl=300,
#       @weight=0>]},
#  "_kerberos._tcp.krampus.csd.lol" =>
#   {"SRV" =>
#     [#<Resolv::DNS::Resource::IN::SRV:0x00000001046cb100
#       @port=88,
#       @priority=0,
#       @target=#<Resolv::DNS::Name: dc01.krampus.csd.lol.>,
#       @ttl=300,
#       @weight=0>]},
#  "_metrics._tcp.krampus.csd.lol" =>
#   {"SRV" =>
#     [#<Resolv::DNS::Resource::IN::SRV:0x0000000104380f18
#       @port=443,
#       @priority=0,
#       @target=#<Resolv::DNS::Name: beacon.krampus.csd.lol.>,
#       @ttl=300,
#       @weight=0>]},
#  "beacon.krampus.csd.lol" =>
#   {"A" =>
#     [#<Resolv::DNS::Resource::IN::A:0x000000010466fc10
#       @address=#<Resolv::IPv4 203.0.113.2>,
#       @ttl=300>],
#    "TXT" =>
#     [#<Resolv::DNS::Resource::Type16_Class1:0x00000001042ec958
#       @strings=["config=ZXhmaWwua3JhbXB1cy5jc2QubG9s=="],
#       @ttl=300>]},
#  "dc01.krampus.csd.lol" =>
#   {"A" =>
#     [#<Resolv::DNS::Resource::IN::A:0x000000010464b360
#       @address=#<Resolv::IPv4 203.0.113.1>,
#       @ttl=300>]},
#  "exfil.krampus.csd.lol" =>
#   {"TXT" =>
#     [#<Resolv::DNS::Resource::Type16_Class1:0x0000000104666340
#       @strings=["status=active; auth=dkim; selector=syndicate"],
#       @ttl=300>]},
#  "syndicate._domainkey.krampus.csd.lol" =>
#   {"TXT" =>
#     [#<Resolv::DNS::Resource::Type16_Class1:0x0000000104641ab8
#       @strings=["v=DKIM1; k=rsa; p=Y3Nke2RuNV9tMTlIVF9CM19LMU5ENF9XME5LeX0="],
#       @ttl=300>]}}
# "exfil.krampus.csd.lol"
# "csd{dn5_m19HT_B3_K1ND4_W0NKy}

pp hash

require "base64"
p Base64.decode64("ZXhmaWwua3JhbXB1cy5jc2QubG9s==")
p Base64.decode64("Y3Nke2RuNV9tMTlIVF9CM19LMU5ENF9XME5LeX0=")
