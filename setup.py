# Mau Ngapain Bro?
import sys
import os
import re
import shutil

py_vers = sys.version_info[:2]
pystr = "python" + ".".join([str(i) for i in py_vers])
binfile = os.path.join(sys.prefix, "bin", "disasm")
src_path = os.path.join(sys.prefix, "lib", pystr)

class Main():
	def __init__(self):
		self.proc = "disasm"
		self.succes = "\nDisasm has been installed\ntype \"disasm\" for run program ^_^\n"
		self.rmstr = "Succes Uninstalled"
		self.path = "./disasm/__init__.py"
	def install(self):
		source = open(self.path, "r").read()
		execute = "\n".join(("#!/usr/bin/python3",
			"from disasm import main_tes as main",
			"if __name__ == \"__main__\":",
			"\tmain()"))
		open(binfile, "w").write(execute)
		os.system("cp -R %s %s"%(self.proc, src_path))
		os.system(f"chmod 775 {binfile}")
		exit(self.succes)
	def uninstall(self):
		if os.path.exists(binfile):
			os.remove(binfile)
		path = os.path.join(src_path, self.proc)
		if os.path.isdir(path):
			shutil.rmtree(path)
		exit(self.rmstr)

if len(sys.argv) < 2:
	exit("Usage: python3 setup.py (install, uninstall)")
argc = sys.argv[1]
self = Main()
if argc == "install":
	self.install()
elif argc == "uninstall":
	self.uninstall()
else:
	exit("what's \"%s\" bro?"%(argc))


