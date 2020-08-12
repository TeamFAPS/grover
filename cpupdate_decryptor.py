#!/usr/bin/python
'''

PlayStation Vita Communication Processor Update Package Decryptor

by SocraticBliss (R)

Utilizing Python 2+3 Version of https://www.personal-view.com/faqs/sony-hack/axfs

'''

import os
import struct
import stat
import sys
import tarfile
import zlib

# Crypto Stuff ...

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

es2_modulus = 0xA7CCAE0F501188527BF3DACCA3E231C8D8701E7B91927390701DE5E7A96327DAD87167A8F01368ADDFE490E325A290533697058FBA775766698010AFD8FD7A3FFD265E0A52FE04928BCE8B4302F4C70FFAC3C9397FD24B106271E57BDA20D2D702298F6F990ECF9B0FE04FF6CCEE170B555304232012D78E6019DAB29763829E6AF5ADA802204FA551631179CBFE6164732662E8576741949BB136456C11DE355F487211D230267DC05E699A2652AD5C6D74B0568326F4F2F5B86AD956E94404D3A65928F4EA2189567CE9989911B04808517F4C76A8B25DF1D6ABBE8595C469BFD7E870C4F00A89610C2C9B79F625A42CA2B4C6B8D37E62CE9EC61A856FD32F

fs1_modulus = 0xA9697F9D9343CADE68E04F9E356E6AB6BBC7DE36A4D81B98A83BC12BE3F6DF96ED7A64389456ACA933BEBFBA4FFEF05CF45F2F886F434FBBC3A01348533070C0B7D5E9C21EFE53E95A6019DB51C12C6BAFEB94E992287963448E59606384B99F3FF3E5EB6AA08BF32A4DBA7A312520CEC2B69BB20A6D0640B117170AA2DDA1FB590AEE7ADFC4E80DFCF27FA55DDEC92C07922FDD05AB1618DCB727AA6FF70027A9410BC845E50EAFD46C0FD92FF500672DE56489C669B0AA481FFD75E99E21A8DC2F9F9E87957B46BBF63FB7DDBE8B8CA861BA349A62458E855EE78C3DD6791F92E76422144E51295B1337E15C126DF6FA0C29321BC1D7C00E3C19EEF3A3E7A5

cui_pub_exponent = 0x10001

def aes_decrypt_cbc(key, iv, input):
    return AES.new(key, AES.MODE_CBC, iv).decrypt(input)

def s2i(s):
  result = 0
  for c in s:
    try:
      result = 256 * result + c
    except:
      result = 256 * result + ord(c)
  return result
  
def as_bytestring(x):
  return ''.join([chr((x >> (i * 8)) & 0xFF) for i in range(x.bit_length() / 8 - 1, -1, -1)])

def rsa_public_encrypt(modulus, public_exponent, data):
  key = RSA.construct((modulus, public_exponent))
  data = as_bytestring(key._encrypt(s2i(data)))
  return data

class Header():
    def __init__(self, f):
        self.MAGIC          = f.read(4)
        self.VERSION        = struct.unpack('<I', f.read(4))[0]
        self.RESERVED       = struct.unpack('<Q', f.read(8))[0]
        self.UNKNOWN        = struct.unpack('<I', f.read(4))[0]
        self.SIZE           = struct.unpack('<I', f.read(4))[0]
        self.HEADER_SIZE    = struct.unpack('<I', f.read(4))[0]
        self.UNPACKED_SIZE  = struct.unpack('<I', f.read(4))[0]

def everybody_do_the_dinosaur(input, output, cui_modulus, start, outsize=0):
  with open(input, 'rb') as f:
    f.seek(-0x100, os.SEEK_END)
    cui_sig = f.read()
    f.close()
    cui_sig_out = rsa_public_encrypt(int(cui_modulus), int(cui_pub_exponent), cui_sig)[-0x34:]
    iv, key, sig = cui_sig_out[:0x10], cui_sig_out[0x10:0x20], cui_sig_out[0x20:]
    
    with open(input, 'rb') as g:
      body = g.read()[start:]
      g.close()
      dec = aes_decrypt_cbc(key, iv, body)
      
      with open(output, 'wb') as h:
        end_slide = 0x100
        if outsize != 0:
          end_slide += 0x10 - (outsize % 0x10)
        h.write(dec[:-end_slide])
        h.close()

# AXFS Stuff ....

header_keys = ('magic', 'signature', 'digest', 'cblock_size', 'files',
              'size', 'blocks', 'mmap_size', 'strings', 'xip',
              'byte_aligned', 'compressed', 'node_type', 'node_index',
              'cnode_offset', 'cnode_index', 'banode_offset',
              'cblock_offset', 'inode_file_size', 'inode_name_offset',
              'inode_num_entries', 'inode_mode_index',
              'inode_array_index', 'modes', 'uids', 'gids',
              'version_major', 'version_minor', 'version_sub',
              'compression_type') #, 'timestamp', 'page_shift')

region_keys = ('fsoffset', 'size', 'compressed_size', 'max_index',
              'table_byte_depth', 'incore')

node_types  = ['XIP', 'Compressed', 'Byte Aligned']

def inode(region, regions):
  data = []
  for i in range(regions[region]['max_index']):
    output = 0
    for j in range(regions[region]['table_byte_depth']):
      k = regions[region]['max_index'] * j + i
      bits = 8 * j
      byte = regions[region]['data'][k]
      try:
        output += byte << bits
      except:
        output += ord(byte) << bits
    data.append(output)
  return data
  
def inode2(region, regions):
  data = []
  for i in range(regions[region]['max_index']):
    output = 0
    for j in range(regions[region]['table_byte_depth']):
      k = regions[region]['max_index'] * j + i
      bits = 8 * j
      byte = regions[region]['data'][k]
      try:
        output += byte << bits
      except:
        output += ord(byte) << bits
    data.append(output)
  return data

def extract(root, path):
  inode = inodes[root]
  curpath = os.path.join(path, inode['name'].decode('ASCII'))
  
  if stat.S_ISDIR(inode['mode']):
    if os.path.isdir(curpath) == False:
      os.mkdir(curpath, inode['mode'] & 0o777)
    else:
      os.chmod(curpath, inode['mode'] & 0o777)
    
    for i in range(inode['num_entries']):
      extract(i + inode['array_index'], curpath)
  
  elif stat.S_ISREG(inode['mode']):
    try:
      os.mknod(curpath, inode['mode'])
    except:
      pass
    
    with open(curpath, 'wb') as f:
      for i in range(inode['num_entries']):
        node = nodes[i + inode['array_index']]
        if node['node_type'] == 0:
          offset = node['node_index'] << 12
          f.write(regions['xip']['data'][offset:offset + 4096])
        if node['node_type'] == 1:
          offset = cnode_index[node['node_index']]
          f.write(zlib.decompress(regions['compressed']['data'][cblock_offset[offset]:]))
        if node['node_type'] == 2:
          offset = banode_offset[node['node_index']]
          length = inode['file_size']
          f.write(regions['byte_aligned']['data'][offset:offset + length])
    
    if os.lstat(curpath).st_size > inode['file_size']:
      with open(curpath, 'rb') as f:
        data = f.read(inode['file_size'])
      with open(curpath, 'wb') as f:
        f.write(data)
  
  elif stat.S_ISCHR(inode['mode']) or stat.S_ISBLK(inode['mode']) or stat.S_ISFIFO(inode['mode']):
    pass
    try:
      os.mknod(os.path.join(path, inode['name'].decode('ASCII')), inode['mode'], inode['file_size'])
    except:
      pass
  
  elif stat.S_ISLNK(inode['mode']):
    inode['type'] = 'Symlink'
    node = nodes[inode['array_index']]
    
    if node['node_type'] == 2:
      offset = banode_offset[node['node_index']]
      length = inode['file_size']
      inode['dest'] = regions['byte_aligned']['data'][offset:offset + length]
    else:
      print('Shit')
    
    if inode['num_entries'] > 1:
      print('Fuck')
    
    try:
      os.symlink(inode['dest'], os.path.join(path, inode['name'].decode('ASCII')))
    except:
      pass
  
  try:
    os.lchown(curpath, inode['uid'], inode['gid'])
  except:
    pass
    

# PROGRAM START

# STAGE 0) Sanity check
if len(sys.argv) != 2:
  raise SystemExit('\nUsage: %s [Input]\n' % sys.argv[0])

with open(sys.argv[1], 'rb') as fd:
  # Parse Header
  header = Header(fd)
  if header.MAGIC != "pUpC":
    print "Bad CpUp magic !"
  fd.close()

# STAGE 1) Decrypt cpupdate.bin
input_path = sys.argv[1].replace('.bin', '')
everybody_do_the_dinosaur(sys.argv[1], input_path + '.tar.gz', es2_modulus, header.HEADER_SIZE, header.UNPACKED_SIZE)

# STAGE 2) Extract .tar.gz decrypted cpupdate.bin
tar = tarfile.open(input_path + '.tar.gz')
tar.extractall(input_path)
tar.close()

# STAGE 3) Decrypt fsimage1.trf
everybody_do_the_dinosaur(input_path + '/fsimage1.trf', input_path + '/fsimage1.trf.dec', fs1_modulus, 0x120)

# STAGE 4) Extract fsimage1.trf.dec
outp = os.path.join(os.getcwd() + '/' + input_path, 'fsimage1_output')

try:
  with open(input_path + '/fsimage1.trf.dec', 'rb') as file:
    
    try:
      os.mkdir(outp)
    except:
      pass
    
    # Header
    header = file.read(244)
    if header[:4] != b'\x48\xA0\xE4\xCD':
      raise SystemExit('\nError: Wrong AXFS Header Magic!')
    
    header_values = struct.unpack('>I16s40sI22Q4B', header)
    axfs_super_onmedia = dict(zip(header_keys, header_values))
    
    # Regions
    regions = {}
    for i in header_keys[8:-4]:
      file.seek(axfs_super_onmedia[i])
      region_desc = dict(zip(region_keys, struct.unpack('>4Q2B', file.read(34))))
      #print(i + repr(region_desc))
      file.seek(region_desc['fsoffset'])
      region_data = file.read(region_desc['size'])
      region_desc['data'] = region_data
      regions[i] = region_desc
    
    at = regions['xip']['data'].decode('ASCII').find('ELF')
    #print(at)
    
    while at != -1:
      at = regions['xip']['data'].decode('ASCII').find('ELF', at + 1)
      #print(at)
    
    # Inode Names
    for i in range(regions['inode_name_offset']['max_index']):
      output = 0
      for j in range(regions['inode_name_offset']['table_byte_depth']):
        k = regions['inode_name_offset']['max_index'] * j + i
        bits = 8 * j #(regions['inode_name_offset']['table_byte_depth'] - j - 1)
        byte = regions['inode_name_offset']['data'][k]
        try:
          output += byte << bits
        except:
          output += ord(byte) << bits
    
    # Nodes
    nodes = []
    node_type  = inode('node_type', regions)
    node_index = inode('node_index', regions)
    
    for i in range(axfs_super_onmedia['blocks']):
      node = {
        'id'         : i,
        'node_type'  : node_type[i],
        'node_index' : node_index[i],
      }
      nodes.append(node)
    
    # BAnodes
    banode_offset = inode('banode_offset', regions)
    
    # Inodes
    inodes = []
    file_size     = inode('inode_file_size', regions)
    name_offset   = inode('inode_name_offset', regions)
    num_entries   = inode('inode_num_entries', regions)
    mode_index    = inode('inode_mode_index', regions)
    array_index   = inode('inode_array_index', regions)
    modes         = inode('modes', regions)
    uids          = inode('uids', regions)
    gids          = inode('gids', regions)
    cnode_index   = inode('cnode_index', regions)
    cnode_offset  = inode('cnode_offset', regions)
    cblock_offset = inode('cblock_offset', regions)
    
    for i in range(axfs_super_onmedia['files']):
      inode = {
        'id'          : i,
        'file_size'   : file_size[i],
        'name'        : regions['strings']['data'][name_offset[i]:regions['strings']['data'].decode('ASCII').index('\x00', name_offset[i])],
        'num_entries' : num_entries[i],
        'mode'        : modes[mode_index[i]],
        'uid'         : uids[mode_index[i]],
        'gid'         : gids[mode_index[i]],
        'array_index' : array_index[i],
      }
      inodes.append(inode)
    
    # Root Directory
    extract(0, outp)
except:
  raise SystemExit('\nError: Not a AXFS Input file!\n')

# STAGE 5) Extract fsimage0.trf
outp2 = os.path.join(os.getcwd() + '/' + input_path, 'fsimage0_output')

with open(input_path + '/fsimage0.trf', 'rb') as file:
    file.seek(0x120)
    body = file.read()
    file.close()
    with open(input_path + '/fsimage0.trf.dec', 'wb') as file:
        file.write(body)
        file.close()
        
outp2 = os.path.join(os.getcwd() + '/' + input_path, 'fsimage0_output')

try:
  with open(input_path + '/fsimage0.trf.dec', 'rb') as file2:
    
    try:
      os.mkdir(outp2)
    except:
      pass
    
    # Header
    header = file2.read(244)
    if header[:4] != b'\x48\xA0\xE4\xCD':
      raise SystemExit('\nError: Wrong AXFS Header Magic!')
    
    header_values = struct.unpack('>I16s40sI22Q4B', header)
    axfs_super_onmedia = dict(zip(header_keys, header_values))
    
    # Regions
    regions = {}
    for i in header_keys[8:-4]:
      file2.seek(axfs_super_onmedia[i])
      region_desc = dict(zip(region_keys, struct.unpack('>4Q2B', file2.read(34))))
      #print(i + repr(region_desc))
      file2.seek(region_desc['fsoffset'])
      region_data = file2.read(region_desc['size'])
      region_desc['data'] = region_data
      regions[i] = region_desc
    
    at = regions['xip']['data'].decode('ASCII').find('ELF')
    #print(at)
    
    while at != -1:
      at = regions['xip']['data'].decode('ASCII').find('ELF', at + 1)
      #print(at)
    
    # Inode Names
    for i in range(regions['inode_name_offset']['max_index']):
      output = 0
      for j in range(regions['inode_name_offset']['table_byte_depth']):
        k = regions['inode_name_offset']['max_index'] * j + i
        bits = 8 * j #(regions['inode_name_offset']['table_byte_depth'] - j - 1)
        byte = regions['inode_name_offset']['data'][k]
        try:
          output += byte << bits
        except:
          output += ord(byte) << bits
    
    
    
    # Nodes
    nodes = []
    node_type  = inode2('node_type', regions)
    node_index = inode2('node_index', regions)
    
    
    
    for i in range(axfs_super_onmedia['blocks']):
      node = {
        'id'         : i,
        'node_type'  : node_type[i],
        'node_index' : node_index[i],
      }
      nodes.append(node)
    
    
    
    # BAnodes
    banode_offset = inode2('banode_offset', regions)
    
    # Inodes
    inodes = []
    file_size     = inode2('inode_file_size', regions)
    name_offset   = inode2('inode_name_offset', regions)
    num_entries   = inode2('inode_num_entries', regions)
    mode_index    = inode2('inode_mode_index', regions)
    array_index   = inode2('inode_array_index', regions)
    modes         = inode2('modes', regions)
    uids          = inode2('uids', regions)
    gids          = inode2('gids', regions)
    cnode_index   = inode2('cnode_index', regions)
    cnode_offset  = inode2('cnode_offset', regions)
    cblock_offset = inode2('cblock_offset', regions)
    
    for i in range(axfs_super_onmedia['files']):
      
      inode = {
        'id'          : i,
        'file_size'   : file_size[i],
        'name'        : regions['strings']['data'][name_offset[i]:regions['strings']['data'].decode('ASCII').index('\x00', name_offset[i])],
        'num_entries' : num_entries[i],
        'mode'        : modes[mode_index[i]],
        'uid'         : uids[mode_index[i]],
        'gid'         : gids[mode_index[i]],
        'array_index' : array_index[i],
      }
      inodes.append(inode)
    
    # Root Directory
    extract(0, outp2)
except:
  raise SystemExit('\nError: Not a AXFS Input file!\n')

# PROGRAM END