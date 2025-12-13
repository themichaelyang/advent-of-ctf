require 'base64'
input = File.open('start.txt').read.split
hex = input.map { _1.to_i(2).chr }.join
b64 = hex.chars.each_slice(2).map { _1.join.to_i(16).chr }.join
p Base64.decode64(b64)
