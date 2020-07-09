#!/usr/bin/python

import struct
import cStringIO
import zlib
import string

import stat

import os
import sys

outpath = os.path.join(os.getcwd(),sys.argv[2] + '_output')

os.mkdir(outpath)

def inode(region, regions):
  data = []
  for i in range(regions[region]['max_index']):
    output = 0
    for j in range(regions[region]['table_byte_depth']):
      k = regions[region]['max_index'] * j + i
      bits = 8 * j
      byte = regions[region]['data'][k]
      output += ord(byte) << bits
    data.append(output)
  return data

def extract(root=0, path=outpath):
  inode = inodes[root]
  curpath = os.path.join(path,inode['name'])
  if stat.S_ISDIR(inode['mode']):
    if os.path.isdir(curpath) == False:
      os.mkdir(curpath,inode['mode'] & 0777)
    else:
      os.chmod(curpath, inode['mode'] & 0777)
    for i in range(inode['num_entries']):
      extract(i+inode['array_index'], curpath)
  elif stat.S_ISREG(inode['mode']):
    os.mknod(curpath,inode['mode'])
    with open(curpath, 'wb') as f:
      for i in range(inode['num_entries']):
        node = nodes[i+inode['array_index']]
        if node['node_type'] == 0:
          offset = node['node_index'] << 12
          f.write(regions['xip']['data'][offset:offset+4096])
        if node['node_type'] == 1:
          offset = cnode_index[node['node_index']]
          f.write(zlib.decompress(regions['compressed']['data'][cblock_offset[offset]:]))
        if node['node_type'] == 2:
          offset = banode_offset[node['node_index']]
          length = inode['file_size']
          f.write(regions['byte_aligned']['data'][offset:offset+length])
    if os.lstat(curpath).st_size > inode['file_size']:
      with open(curpath, 'rb') as f:
        data = f.read(inode['file_size'])
      with open(curpath, 'wb') as f:
        f.write(data)
        
  elif stat.S_ISCHR(inode['mode']) or stat.S_ISBLK(inode['mode']) or stat.S_ISFIFO(inode['mode']):
    pass
    os.mknod(os.path.join(path,inode['name']),inode['mode'],inode['file_size'])
  elif stat.S_ISLNK(inode['mode']):
    inode['type'] = 'Symlink'
    node = nodes[inode['array_index']]
    if node['node_type'] == 2:
      offset = banode_offset[node['node_index']]
      length = inode['file_size']
      inode['dest'] = regions['byte_aligned']['data'][offset:offset+length]
    else:
      print 'Shit'
    if inode['num_entries'] > 1:
      print 'Fuck'
    os.symlink(inode['dest'],os.path.join(path,inode['name']))
  os.lchown(curpath,inode['uid'],inode['gid'])
  
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

node_types = ['XIP','Compressed','Byte Aligned']

with open(sys.argv[1], 'rb') as file:
  # Header
  header = file.read(244)
  header_values = struct.unpack('>I16s40sI22Q4B',header)
  axfs_super_onmedia = dict(zip(header_keys, header_values))

  # Regions  
  regions = {}
  for i in header_keys[8:-4]:
    file.seek(axfs_super_onmedia[i])
    region_desc = dict(zip(region_keys, struct.unpack('>4Q2B', file.read(34))))
    #print i + repr(region_desc)
    file.seek(region_desc['fsoffset'])
    region_data = file.read(region_desc['size'])
    region_desc['data'] = region_data
    regions[i] = region_desc
    
  at = regions['xip']['data'].find('ELF')
  #print at
  while at != -1:
    at = regions['xip']['data'].find('ELF', at+1)
    #print at
    #Inode Names
  for i in range(regions['inode_name_offset']['max_index']):
    output = 0
    for j in range(regions['inode_name_offset']['table_byte_depth']):
      k = regions['inode_name_offset']['max_index'] * j + i
      bits = 8 * j #(regions['inode_name_offset']['table_byte_depth'] - j - 1)
      byte = regions['inode_name_offset']['data'][k]
      output += ord(byte) << bits
  
  #Nodes
  nodes = []
  node_type = inode('node_type', regions)
  node_index = inode('node_index', regions)

  for i in range(axfs_super_onmedia['blocks']):
    node = {
      'id'         : i,
      'node_type'  : node_type[i],
      'node_index' : node_index[i]
           }
    nodes.append(node)
  
  #BANodes
  banode_offset = inode('banode_offset', regions)

  #Inodes
  inodes = []
  file_size = inode('inode_file_size', regions)
  name_offset = inode('inode_name_offset', regions)
  num_entries = inode('inode_num_entries', regions)
  mode_index = inode('inode_mode_index', regions)
  array_index = inode('inode_array_index', regions)
  modes = inode('modes', regions)
  uids = inode('uids', regions)
  gids = inode('gids', regions)
  cnode_index = inode('cnode_index', regions)
  cnode_offset = inode('cnode_offset', regions)
  cblock_offset = inode('cblock_offset', regions)
 
  for i in range(axfs_super_onmedia['files']):
    inode = {
      'id'          : i,
      'file_size'   : file_size[i],
      'name'        : regions['strings']['data'][name_offset[i]:regions['strings']['data'].index('\x00', name_offset[i])],
      'num_entries' : num_entries[i],
      'mode'        : modes[mode_index[i]],
      'uid'         : uids[mode_index[i]],
      'gid'         : gids[mode_index[i]],
      'array_index' : array_index[i]
            }
    inodes.append(inode)

  # Root Directory
  extract()
