import os
import sys
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

cui_modulus = 0xA7CCAE0F501188527BF3DACCA3E231C8D8701E7B91927390701DE5E7A96327DAD87167A8F01368ADDFE490E325A290533697058FBA775766698010AFD8FD7A3FFD265E0A52FE04928BCE8B4302F4C70FFAC3C9397FD24B106271E57BDA20D2D702298F6F990ECF9B0FE04FF6CCEE170B555304232012D78E6019DAB29763829E6AF5ADA802204FA551631179CBFE6164732662E8576741949BB136456C11DE355F487211D230267DC05E699A2652AD5C6D74B0568326F4F2F5B86AD956E94404D3A65928F4EA2189567CE9989911B04808517F4C76A8B25DF1D6ABBE8595C469BFD7E870C4F00A89610C2C9B79F625A42CA2B4C6B8D37E62CE9EC61A856FD32FL

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
		body = g.read()[0x20:]
		dec = aes_decrypt_cbc(key, iv, body)
		with open(sys.argv[2],"wb") as h:
			h.write(dec[:-0x100])
	