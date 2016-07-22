#pack and unpack forlder

import os
import sys
import os.path
import zipfile

class ZFile(object):
	def __init__(self, filename, mode='r', basedir=''):
		self.filename = filename
		self.mode = mode
		if self.mode in ('w', 'a'):
			self.zfile = zipfile.ZipFile(filename, self.mode, compression=zipfile.ZIP_DEFLATED)
		else:
			self.zfile = zipfile.ZipFile(filename, self.mode)
		self.basedir = basedir
		if not self.basedir:
			self.basedir = os.path.dirname(filename)

	def addfile(self, path, arcname=None):
		path = path.replace('//','/')
		if not arcname:
			if path.startswith(self.basedir):
				arcname = path[len(self.basedir):]
			else:
				arcname = ''
		self.zfile.write(path, arcname)

	def addfiles(self, paths):
		for path in paths:
			if isinstance(path, tuple):
				self.addfile(*path)
			else:
				self.addfile(path)

	def close(self):
		self.zfile.close()

	def extract_to(self, path):
		for p in self.zfile.namelist():
			self.extract(p, path)

	def extract(self, filename, path):
		if not filename.endswith('/'):
			f = os.path.join(path, filename)
			dir = os.path.dirname(f)
			if not os.path.exists(dir):
				os.makedirs(dir)
			file(f, 'wb').write(self.zfile.read(filename))


def zip_dir(dir_name,zip_file_name):
		filelist=[]
		if os.path.isfile(dir_name):
			filelist.append(dir_name)
		else:
			for root,dirs,files in os.walk(dir_name):
				for name in files:
					filelist.append(os.path.join(root, name))
		zf = zipfile.ZipFile(zip_file_name, 'w', zipfile.zlib.DEFLATED)
		for tar in filelist:
			arcname = tar[len(dir_name):]
			zf.write(tar,arcname)
		zf.close()


def create(zfile, files):
	zip_dir(files, zfile)

def extract(zfile, path):
	z = ZFile(zfile)
	z.extract_to(path)
	z.close