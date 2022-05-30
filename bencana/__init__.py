# Terimakasih untuk beberapa pihak yg Udah ngebantu
# Alat ini di khususkan untuk python versi 3.10
# Original Repo : https://github.com/shp46/python-disasm

# Free And Open Source
# Jangan Di recode Ya Bro
# Tinggal Pake aja

# And Note:
#	 Alat ini Belom 100% bekerja sih menurut gw
# 	Ada Beberapa Bagian Yg Gk gw benerin
# 	Jadi kalo kurang pas Edit aja, sesuaikan sendiri

# Bagian Yg Perlu Di Benerin utamanya di bagian asm.
# Dari Bagian type Code <code object (.+) at (.+), file "asw.py" line 0>
#	co_firslineno
#	co_lnotab
# Gak Gw benerin gara² pening pala mikir nya :v

# Bagian (co_varnames, co_names, co_consts)
# variable itu gak di ubah pake asm, jadi tetep bawaan original

# Untuk selebih nya tinggal benerin atau tambahin sendiri aja

# Kalo Ada saran perbaikan ataupun bugs di sc ini silahkan Dm ke wa gw aja bro
# Dan jangan spam ya ajg:c

import sys
import json
import re
import dis
import marshal
import time
import io
import os
from opcode import *
import struct
from importlib.util import MAGIC_NUMBER

if sys.version_info[:2] != (3, 10):
	exit("Only For Python3.10 ")

cmp_op = ('<', '<=', '==', '!=', '>', '>=', 'in', 'not in', 'is', 'is not', 'exception match', 'BAD')
opmap38 = {'POP_TOP': 1, 'ROT_TWO': 2, 'ROT_THREE': 3, 'DUP_TOP': 4, 'DUP_TOP_TWO': 5, 'ROT_FOUR': 6, 'NOP': 9, 'UNARY_POSITIVE': 10, 'UNARY_NEGATIVE': 11, 'UNARY_NOT': 12, 'UNARY_INVERT': 15, 'BINARY_MATRIX_MULTIPLY': 16, 'INPLACE_MATRIX_MULTIPLY': 17, 'BINARY_POWER': 19, 'BINARY_MULTIPLY': 20, 'BINARY_MODULO': 22, 'BINARY_ADD': 23, 'BINARY_SUBTRACT': 24, 'BINARY_SUBSCR': 25, 'BINARY_FLOOR_DIVIDE': 26, 'BINARY_TRUE_DIVIDE': 27, 'INPLACE_FLOOR_DIVIDE': 28, 'INPLACE_TRUE_DIVIDE': 29, 'GET_AITER': 50, 'GET_ANEXT': 51, 'BEFORE_ASYNC_WITH': 52, 'BEGIN_FINALLY': 53, 'END_ASYNC_FOR': 54, 'INPLACE_ADD': 55, 'INPLACE_SUBTRACT': 56, 'INPLACE_MULTIPLY': 57, 'INPLACE_MODULO': 59, 'STORE_SUBSCR': 60, 'DELETE_SUBSCR': 61, 'BINARY_LSHIFT': 62, 'BINARY_RSHIFT': 63, 'BINARY_AND': 64, 'BINARY_XOR': 65, 'BINARY_OR': 66, 'INPLACE_POWER': 67, 'GET_ITER': 68, 'GET_YIELD_FROM_ITER': 69, 'PRINT_EXPR': 70, 'LOAD_BUILD_CLASS': 71, 'YIELD_FROM': 72, 'GET_AWAITABLE': 73, 'INPLACE_LSHIFT': 75, 'INPLACE_RSHIFT': 76, 'INPLACE_AND': 77, 'INPLACE_XOR': 78, 'INPLACE_OR': 79, 'WITH_CLEANUP_START': 81, 'WITH_CLEANUP_FINISH': 82, 'RETURN_VALUE': 83, 'IMPORT_STAR': 84, 'SETUP_ANNOTATIONS': 85, 'YIELD_VALUE': 86, 'POP_BLOCK': 87, 'END_FINALLY': 88, 'POP_EXCEPT': 89, 'STORE_NAME': 90, 'DELETE_NAME': 91, 'UNPACK_SEQUENCE': 92, 'FOR_ITER': 93, 'UNPACK_EX': 94, 'STORE_ATTR': 95, 'DELETE_ATTR': 96, 'STORE_GLOBAL': 97, 'DELETE_GLOBAL': 98, 'LOAD_CONST': 100, 'LOAD_NAME': 101, 'BUILD_TUPLE': 102, 'BUILD_LIST': 103, 'BUILD_SET': 104, 'BUILD_MAP': 105, 'LOAD_ATTR': 106, 'COMPARE_OP': 107, 'IMPORT_NAME': 108, 'IMPORT_FROM': 109, 'JUMP_FORWARD': 110, 'JUMP_IF_FALSE_OR_POP': 111, 'JUMP_IF_TRUE_OR_POP': 112, 'JUMP_ABSOLUTE': 113, 'POP_JUMP_IF_FALSE': 114, 'POP_JUMP_IF_TRUE': 115, 'LOAD_GLOBAL': 116, 'SETUP_FINALLY': 122, 'LOAD_FAST': 124, 'STORE_FAST': 125, 'DELETE_FAST': 126, 'RAISE_VARARGS': 130, 'CALL_FUNCTION': 131, 'MAKE_FUNCTION': 132, 'BUILD_SLICE': 133, 'LOAD_CLOSURE': 135, 'LOAD_DEREF': 136, 'STORE_DEREF': 137, 'DELETE_DEREF': 138, 'CALL_FUNCTION_KW': 141, 'CALL_FUNCTION_EX': 142, 'SETUP_WITH': 143, 'LIST_APPEND': 145, 'SET_ADD': 146, 'MAP_ADD': 147, 'LOAD_CLASSDEREF': 148, 'EXTENDED_ARG': 144, 'BUILD_LIST_UNPACK': 149, 'BUILD_MAP_UNPACK': 150, 'BUILD_MAP_UNPACK_WITH_CALL': 151, 'BUILD_TUPLE_UNPACK': 152, 'BUILD_SET_UNPACK': 153, 'SETUP_ASYNC_WITH': 154, 'FORMAT_VALUE': 155, 'BUILD_CONST_KEY_MAP': 156, 'BUILD_STRING': 157, 'BUILD_TUPLE_UNPACK_WITH_CALL': 158, 'LOAD_METHOD': 160, 'CALL_METHOD': 161, 'CALL_FINALLY': 162, 'POP_FINALLY': 163}

globals().update(opmap)

_OPNAME_WIDTH = 20
_OPARG_WIDTH = 5

def c_to_pyc(co, files, msg=False):
	xa=(lambda val: struct.pack("<I", val))
	data = bytearray(MAGIC_NUMBER)
	data.extend(xa(0))
	data.extend(xa(int(time.time())))
	data.extend(xa(0))
	data.extend(marshal.dumps(co))
	with open(files, "wb") as self:
		self.write(data)
	if msg:
		print(f"Write {files}")

def iscode(co):
	return hasattr(co, "co_code")

try:
	import ajg
except (Exception) as e:
	e = None

class Code():
	def __init__(self, co):
		self.co = co
		for loop in dir(co):
			if loop.startswith("co_"):
				setattr(self, loop, getattr(co, loop))
		self.co_consts = list(self.co_consts)
	def asm(self):
		sp = ("argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize, flags, code, consts, names, varnames, filename, name, firstlineno, lnotab, freevars, cellvars")
		self.co_consts = tuple(self.co_consts)
		opcodes = sp.split(", ")
		for rangee, loop in enumerate(opcodes):
			code = getattr(self, "co_%s" % loop)
			opcodes[rangee] = code
		return type(self.co)(*opcodes)
	def __repr__(self):
		return f"<Code object {self.co_name}>"
class Diss():
	def __init__(self, l):
		self.strr, self.is_jump, self.offset, self.opname, self.arg, self.kind = l
	def dis(self, lineno_width=3, mark_as_current=False, offset_width=4):
		fields = []
		if self.strr:
			ajg = "\nL%d." % self.strr
			fields.append(ajg.ljust(lineno_width))
		else:
			fields.append(' ' * lineno_width)
		if mark_as_current:
			fields.append('-->')
		else:
			fields.append('   ')
		if self.is_jump:
			fields.append('>>')
		else:
			fields.append('  ')
		if type(self.offset) is str:
			fields.append(str(self.offset).rjust(offset_width))
		fields.append(self.opname.ljust(_OPNAME_WIDTH))
		if self.arg is not None:
			fields.append(str(self.arg).rjust(_OPARG_WIDTH))
			if self.kind:
				fields.append('(' + self.kind + ')')
		return ' '.join(fields).rstrip()

class Reduce():
	def __init__(self, co):
		self.co = co
		self.findlabels()
	def inst_bytecode(self):
		code = self.co.co_code
		i = 0
		n = len(code)
		while i < n:
			op = code[i]
			arg = code[i + 1]
			yield (i, op, arg)
			i += 2
	def findlabels(self):
		labels = {}
		j = 1
		for offset, op, arg in self.inst_bytecode():
			if op in hasjabs:
				label = arg*2
			elif op in hasjrel:
				label = offset + 2 + arg*2
			else:
				continue
			if label not in labels:
				labels[label] = "jump"+str(j)
				j += 1
		self.labels = labels
	def get_inst(self):
		inst = []
		label = self.labels
		linest = dict(dis.findlinestarts(self.co))
		for offset, op, arg in self.inst_bytecode():
			is_jump = offset in label.keys()
			opc = opname[op]
			start = linest.get(offset)
			argval = None
			if op in hasjrel:
				j = offset + 2 + arg*2
				arg = label[j]
			elif op in hasjabs:
				j = arg*2
				arg = label[j]
			elif op in hasconst:
				argval = repr(self.co.co_consts[arg])
			elif op in hasname:
				argval = self.co.co_names[arg]
			elif op in haslocal:
				argval = self.co.co_varnames[arg]
			if is_jump:
				offset = label[offset]
			if opc.startswith("JUMP_IF_NOT_"):
				kn = 10
				w = Diss([start, is_jump, offset, "COMPARE_OP", kn, cmp_op[kn]])
				inst.append(w)
				opc = "POP_JUMP_IF_FALSE"
			elif op in (CONTAINS_OP, IS_OP):
				opc = "COMPARE_OP"
				if op == CONTAINS_OP:
					arg = 6 if arg == 0 else 7
				else:
					arg = 8 if arg == 0 else 9
				argval = cmp_op[arg]
			p = Diss([start, is_jump, offset, opc, arg, argval])
			inst.append(p)
		self.inst = inst
	def flush(self, file=None):
		self.get_inst()
		for i in self.inst:
			print(i.dis(), file=file)

class Nn():
	def __init__(self,q,a,b,c):
		self.is_jump = ''
		self.of2 = str(a)
		try:
			self.op = opmap[b]
		except:
			self.op = opmap38[b]
		self.opname = b
		self.arg = str(c)
		self.argval = None
		self.lines = q
def dis_in(sc):
	b=[i for i in sc.splitlines() if i != '']
	c=[]
	lab={}
	of2=0
	for l in b:
		x = (l).split()
		for (i, op3) in enumerate(x):
			if op3 in opmap38 or op3 in opmap:
				op = op3
				try:
					arg = x[i+1]
				except:
					arg = str(0)
				break
		lineno = None
		if x[0] == ">>":
			if x[1].startswith("jump"):
				lab[x[1]]=of2
		elif x[0].startswith("L"):
			match = re.findall("L(\d+).",x[0])
			if match:
				lineno = int(match[0])
			if x[1] == ">>":
				if x[2].startswith("jump"):
					lab[x[2]]=of2
		c.append(Nn(lineno,of2,op,arg))
		of2+=2
	return (lab,c)
def secret_jmp(sc):
	jabs38 = (111, 112, 113, 114, 115)
	jrel38 = (93, 110, 122, 143, 154, 162)
	lab, inst = dis_in(sc)
	p=[]
	for i in inst:
		if i.arg in lab.keys():
			if i.op in hasjabs or i.op in jabs38:
				w = lab[i.arg]
				j = int(w/2)
				i.arg = str(j)
				i.argval = "to " + str(w)
			elif i.op in hasjrel or i.op in jrel38:
				m = int(i.of2)+2
				w = lab[i.arg]
				q = w - m
				j = int(q/2)
				i.arg = str(j)
				i.argval = "to " + str(w)
		p.append(i)
	return p
def load_code(sc):
	l = secret_jmp(sc)
	bit = bytearray()
	for lop, i in enumerate(l):
		for x in (i.op, i.arg):
			try:
				bit.append(int(x))
			except:
				raise Exception("Error \"%s %s\" in range %s"%(str(i.opname), str(i.arg), str(lop)))
	lnotab = ''
	return lnotab, bytes(bit)
def get_code_obj(stream):
	s = stream.split("Disassembly")[0]
	xa = re.search("module\((.*?)\)",s).group(1)
	i = bytearray([int(i) for i in xa.split(",")])
	return marshal.loads(i)

def diss(co, indent='', file=None):
	print("Disassembly of", indent, co, file=file)
	Reduce(co).flush(file=file)
	for l, i in enumerate(co.co_consts):
		if iscode(i):
			diss(i, indent=indent+"."+str(l), file=file)
def codereduce(co):
	c = Code(co)
	for l, i in enumerate(c.co_consts):
		if iscode(i):
			c.co_consts[l] = codereduce(i)
	return c.asm()
def tes_dis(co, file=None):
	co = codereduce(co)
	aray = list(marshal.dumps(co))
	wm = ("#DisAsm for python 3.10\n#module({})").format(",".join([str(i) for i in aray]))
	print(wm, file=file)
	diss(co, indent="0", file=file)
def find_names(p):
	match =re.findall("Disassembly of (.+) <code object (.*?) at (.*?), file \"(.*?)\", line (\d+)>",p)
	vals = (match[0][0]).split(".")[1:]
	return (".").join(vals)
def dis_to(a):
	sc = a.splitlines()
	for l, i in enumerate(sc):
		if i.startswith("Disassembly"):
			break
	sc = sc[l:]
	co = get_code_obj(a)
	da = {}
	i = 0
	n = len(sc)
	while i < n:
		p = sc[i]
		if p.startswith("Disassembly"):
			names = find_names(p)
			if names == '':
				names = "module"
			da[names] = []
		if p != '':
			da[names].append(p)
		i+=1
	for k,v in da.items():
		da[k] = "\n".join(v[1:])
	return (co, da)
def rewatch(self):
	(co, da) = dis_to(self)
	for k,v in da.items():
		da[k] = load_code(v)
	return (co, da)
def reduceall(co):
	c = Code(co)
	for l, i in enumerate(c.co_consts):
		if iscode(i):
			c.co_consts[l] = reduceall(i)
	return c
def get_addr(addr):
	x = [int(i) for i in addr.split(".")]
	w = ".".join(["co_consts[%d]" % i for i in x])
	return w
def asm2(stream):
	co, data = rewatch(stream)
	cc = reduceall(co)
	keys = list(data.keys())[::-1]
	for k in keys:
		lnotab, codestr = data[k]
		if k == "module":
			cc.co_code = codestr
			continue
		addr = get_addr(k)
		exec(f"cc.{addr}.co_code = {codestr}")
		exec(f"cc.{addr} = cc.{addr}.asm()")
	x = cc.asm()
	return x
def asm_(self):
	a = open(self, "r").read()
	code = asm2(a)
	out = os.path.splitext(self)[0]+".pyc"
	c_to_pyc(code, out, msg=True)
def compiler(self):
	str = open(self, "r").read()
	co = compile(str, self, "exec")
	return co
def pycomp(self):
	str = open(self, "rb")
	magic = str.read(16)
	bytes = (str).read()
	co = marshal.loads(bytes)
	return co
def dumpfile(self):
	try:
		return compiler(self)
	except:
		try:
			return pycomp(self)
		except:
			exit("error in the %s file to unpack"%(self))
description = """
This tool to disassemble and reassemble python code bytecode version 3.10
Usage: disasm (options)

	-f|--file	set filename
	-a|--asm	reassemble the code
	-d|--dis	Unload pyc or source files
	-h|--help	show this message
	-n|--note	note from developer 
"""
notes = """
Ngapain Cok Ngeliat Notes Dari Gw.
Kurang Kerjaan aja Lu:v
"""
class dict_attr():
	def __init__(self):
		self.asm = False
		self.dis = False
		self.file = None
	def setcomp(self, i):
		dict = {"asm":"dis","dis":"asm"}
		vals = dict.get(i)
		if vals:
			setattr(self, i, True)
			setattr(self, vals, False)
	def setfile(self, list, start, end=1):
		start += end
		try:
			self.file = list[start]
		except Exception:
			exit("Missing argument file givens")
	def beol(self):
		if self.asm:
			return self.asm
		if self.dis:
			return self.dis
	def cebok(self, kntl, wait):
		dict = {"asm":("-a","--asm"),
			"dis":("-d","--dis"), "note":("-n","--note"),
		"help":("-h","--help"), "file":("-f","--file")}
		return wait in dict.get(kntl)
	def printindent(self, item):
		if not self.beol():
			exit(item)
	def chek(self):
		if self.asm is False and self.dis is False:
			if self.file:
				exit("Nothing argument (--dis, --asm) given")
			else:
				exit(description)
		if not self.file:
			exit("Missing argument file givens")
	def __repr__(self):
		return (f"Argparse(asm={str(self.asm)}, dis={str(self.dis)}, file={repr(self.file)})")
def main_tes():
	argv = dict_attr()
	for i, kntl in enumerate(sys.argv):
		if argv.cebok("file", kntl):
			argv.setfile(sys.argv, i)
		elif argv.cebok("asm", kntl):
			argv.setcomp("asm")
		elif argv.cebok("dis", kntl):
			argv.setcomp("dis")
		elif argv.cebok("help", kntl):
			argv.printindent(description)
		elif argv.cebok("note", kntl):
			argv.printindent(notes)
	argv.chek()
	if argv.asm:
		asm_(argv.file)
	elif argv.dis:
		xa = dumpfile(argv.file)
		tes_dis(xa)
	else:
		exit(description)

if __name__ == "__main__":
	main_tes()

# Nyari Apa sampe Bawah Sini?
# Are You Fucking Motherfucker?
