import os
import sys
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

cui_modulus = 0xA9697F9D9343CADE68E04F9E356E6AB6BBC7DE36A4D81B98A83BC12BE3F6DF96ED7A64389456ACA933BEBFBA4FFEF05CF45F2F886F434FBBC3A01348533070C0B7D5E9C21EFE53E95A6019DB51C12C6BAFEB94E992287963448E59606384B99F3FF3E5EB6AA08BF32A4DBA7A312520CEC2B69BB20A6D0640B117170AA2DDA1FB590AEE7ADFC4E80DFCF27FA55DDEC92C07922FDD05AB1618DCB727AA6FF70027A9410BC845E50EAFD46C0FD92FF500672DE56489C669B0AA481FFD75E99E21A8DC2F9F9E87957B46BBF63FB7DDBE8B8CA861BA349A62458E855EE78C3DD6791F92E76422144E51295B1337E15C126DF6FA0C29321BC1D7C00E3C19EEF3A3E7A5L

cui_pub_exponent = 0x10001L

def aes_decrypt_cbc(key, iv, input):
    return AES.new(key, AES.MODE_CBC, iv).decrypt(input)

def s2i(s):
  result = 0L
  for c in s:
    result = 256 * result + ord(c)
  return result

def as_bytestring(x):
  return ''.join([chr((x >> (i * 8)) & 0xFF) for i in xrange(x.bit_length() / 8 - 1, -1, -1)])


def rsa_public_encrypt(modulus, public_exponent, data):
  key = RSA.construct((modulus, public_exponent))
  data = as_bytestring(key._encrypt(s2i(data)))
  return data

with open(sys.argv[1],"rb") as f:
	f.seek(-0x100, os.SEEK_END)
	cui_sig = f.read()
	cui_sig_out = rsa_public_encrypt(cui_modulus, cui_pub_exponent, cui_sig)[-0x34:]
	iv, key, sig = cui_sig_out[:0x10], cui_sig_out[0x10:0x20], cui_sig_out[0x20:]
	with open(sys.argv[1],"rb") as g:
		body = g.read()[0x120:]
		dec = aes_decrypt_cbc(key, iv, body)
		with open(sys.argv[2],"wb") as h:
			h.write(dec[:-0x100])
	