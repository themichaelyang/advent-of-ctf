require 'bundler/setup'

# Some questions I have:
# - What is a packet?
# - What is a MAC address?
# - How can Wireshark identify the source of the MAC address as VMWare?
# - What are: Ethernet II, IPv4, TCP?
# from the internet: "what a packet is, Ethernet vs. IP vs. TCP vs. UDP etc"
# What is a frame?

# See: https://datatracker.ietf.org/doc/id/draft-gharris-opsawg-pcap-00.html
require "pcaprub"

file = PCAPRUB::Pcap.open_offline("ftpchal.pcap")

class String
  def to_hex(joiner="")
    self.bytes.map { _1.to_s(16).rjust(2, "0") }.join(joiner)
  end
end


# What are:
# - Sequence number (how is this derived)
# - Acknowledgement number
# - Flags
# https://en.wikipedia.org/wiki/IPv4#Packet_structure
def ipv4_packet(packet)
  version = packet[0].ord >> 4
  header_length = (packet[0].ord & (0xf)) * 4
  header = packet[0, header_length] # usually 20, no options
  protocol = header[9].unpack1("C") # 6 => TCP

  # See: https://rickcarlino.com/notes/web-development/a-ruby-packet-analyzer.html
  source_ip = header[11, 4].unpack("CCCC").join(".")
  destination_ip = header[15, 4].unpack("CCCC").join(".")

  # network order = big endian
  total_length = header[2..3].unpack("n")
  data = packet[header_length..]

  {
    version:,
    header:,
    source_ip:,
    destination_ip:,
    protocol:,
    data:
  }
end

def tcp_segment(segment)
  source_port, destination_port, sequence_number, ack_number = segment.unpack("n n N N")
  data_offset = (segment[12].ord >> 4) * 4
  flags = segment[13].ord.to_s(2).rjust(8, "0").chars.map { |f| f == '1' }
  raise "not enough flags" if flags.length != 8

  data = segment[data_offset..]

  # cwr, ece, urg, ack, psh, rst, syn, fin = flags

  {
    source_port:,
    destination_port:,
    sequence_number:,
    ack_number:,
    flags:,
    data:
  }
end

# https://en.wikipedia.org/wiki/Ethernet_frame#Structure
def ethernet_ii(data)
  destination_mac, source_mac = data[..5].to_hex(":"), data[6..11].to_hex(":")
  type_or_length = data[12..13]
  data = data[14..]
  # I think the checksum is not present in this PCAP? FCS bits are set
  # in the PCAP header which I don't have access to.
  # checksum = [-4..]

  {
    destination_mac:,
    source_mac:,
    type_or_length:,
    data:,
    # checksum:
  }
end

file.each do |data|
  # PCAP packet contains (according to Wireshark):
  # └─Ethernet II frame (link)
  #   └─IPv4 packet (network)
  #     └─TCP segment (transport)
  #       └─FTP data (application)
  data = data.force_encoding("ASCII-8BIT")
  frame = ethernet_ii(data)
  packet = ipv4_packet(frame[:data])
  # p packet
  segment = tcp_segment(packet[:data])
  p segment
end
