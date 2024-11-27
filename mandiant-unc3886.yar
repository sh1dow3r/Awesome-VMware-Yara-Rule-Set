rule M_Sniffer_LOOKOVER_1 {
meta:
  author = "Mandiant"
strings:
  $str1 = "TKEY" 
  $str2 = "FILTER" 
  $str3 = "DEVICE" 
  $str4 = "SNFILENAME" 
  $str5 = "/var/lib/libsyslog.so" 
  $code = {8B 55 F8 48 8B 45 E8 48 01 C2 8B 45 FC 48 8D 0C 85 00 00 00 00 
48 8B 45 E0 48 01 C8 8B 00 88 02 8B 45 F8 83 C0 01 89 C2 48 8B 45 E8 48 01 
C2 8B 45 FC 48 8D 0C 85 00 00 00 00 48 8B 45 E0 48 01 C8 8B 00 C1 E8 08 88 
02 8B 45 F8 83 C0 02 89 C2 48 8B 45 E8 48 01 C2 8B 45 FC 48 8D 0C 85 00 00 
00 00 48 8B 45 E0 48 01 C8 8B 00 C1 E8 10 88 02 8B 45 F8 83 C0 03 89 C2 48 
8B 45 E8 48 01 C2 8B 45 FC 48 8D 0C 85 00 00 00 00 48 8B 45 E0 48 01 C8 8B 
00 C1 E8 18 88 02 83 45 FC 01 83 45 F8 04} 
condition:
  uint32(0) == 0x464c457f and filesize < 5MB and all of them
}
rule M_Utility_GHOSTTOWN_1 {
meta:
  author = "Mandiant"
strings:
  $code1 = { 2F 76 61 72 2F 6C 6F 67 } 
  $code2 = { 2F 76 61 72 2F 72 75 6E } 
  $debug1 = "=== results ===" ascii
  $debug2 = "=== %s ===" ascii
  $debug3 = "searching record in file %s" ascii
  $debug4 = "record not matched, not modifing %s" ascii
  $debug5 = "delete %d records in %s" ascii
  $debug6 = "NEVER_LOGIN" ascii
  $debug7 = "you need to specify a username to clear" ascii
  $pattern1 = "%-10s%-10s%-10s%-20s%-10s" ascii
  $pattern2 = "%-15s%-10s%-15s%-10s" ascii
condition:
  uint32(0) == 0x464C457F and all of them
}
rule M_Utility_VIRTUALPEER_1 {
    meta:
        author = "Mandiant"
    strings:
        $vmci_socket_family = {B? 00 00 00 00 B? 02 00 00 00 B? 28 00 
00 00 e8 [4-128] B? 00 00 00 00 48 8d [5] b? 00 00 00 00 e8 [4-64] B? 
00 00 00 00 48 8d [5] b? 00 00 00 00 e8 [4-64] B? B8 07 00 00 [0-8] b? 
00 00 00 00 e8}
        $vmci_socket_marker1 = "/dev/vsock" ascii wide
        $vmci_socket_marker2 = "/vmfs/devices/char/vsock/vsock" 
ascii wide
        $vmci_socket_init_bind_listen = {e8 [4] 89 45 [4-64] 8B 45 ?? b? 
00 00 00 00 b? 01 00 00 00 [0-4] e8 [4-128] B? 10 00 00 00  [1-16] e8 
[4-128] BE 01 00 00 00 [1-16] e8 [4] 83 F8 FF}
        $socket_read_write = {BA 01 00 00 00 48 89 CE 89 C7 E8 [4] 48 
85 C0 [1-64] BA 01 00 00 00 48 89 CE 89 C7 E8 [4] 48 85 C0 7e ?? eb}
        $marker1 = "nc <port>"
    condition:
        uint32(0) == 0x464c457f and all of them
          
}
rule M_Hunting_VIRTUALPITA_1
{
    meta:
        author = "Mandiant"
    strings:
        $forpid = { 70 69 64 20 [0-10] 69 6E 20 60 [0-10] 70 73 20 2D [0-10] 
63 20 7C 20 [0-10] 67 72 65 70 [0-10] 20 76 6D 73 [0-10] 79 73 6C 6F [0-10] 
67 64 20 7C [0-10] 20 61 77 6B [0-10] 20 27 7B 20 [0-10] 70 72 69 6E [0-10] 
74 20 24 31 [0-10] 20 7D 27 60 [0-10] 3B 20 64 6F [0-10] 20 6B 69 6C [0-10] 
6C 20 2D 39 [0-10] 20 24 70 69 [0-10] 64 3B 20 64 [0-10] 6F 6E 65 00 }
        $vmsyslogd = { 2F 75 73 72 [0-10] 2F 6C 69 62 [0-10] 2F 76 6D 77 
[0-10] 61 72 65 2F [0-10] 76 6D 73 79 [0-10] 73 6C 6F 67 [0-10] 2F 62 69 6E 
[0-10] 2F 76 6D 73 [0-10] 79 73 6C 6F [0-10] 67 64 00 00 }
    condition:
        uint32(0) == 0x464c457f and any of them
}
rule M_APT_Launcher_REPTILE_1 {
meta:
  author = "Mandiant"
strings:
  $str1 = {B8 00 00 00 00 E8 A1 FE FF FF 48 8B 85 40 FF FF FF 48 
83 C0 08 48 8B 00 BE 00 00 00 00 48 89 C7 B8 00 00 00 00 E8 ?? 
FD FF FF 89 45 ?8 48 8D 95 50 FF FF FF 8B 45 ?8 48 89 D6 89 C7 
E8 ?? 0? 00 00 48 8B 45 80 48 89 45 F0 48 8B 45 F0 48 89 C7 E8 
?? F? FF FF 48 89 45 ?8 48 8B 55 F0 48 8B 4D ?8 8B 45 ?8 48 89 
CE 89 C7 E8 ?? FC FF FF 48 8B 55 F0 48 8B 45 ?8 B9 4? 0C 40 00 
48 89 C6 BF AF 00 00 00 B8 00 00 00 00 E8 ?? FC FF FF E8 ?? FC 
FF FF 8B 00 83 F8 25 75 07 C7 45 ?C 00 00 00 00 } 
  $str2 = {81 7D F? FF 03 00 00 7E E9 BE 02 00 00 00 BF ?? 0C 40 
00 B8 00 00 00 00 E8 ?? F? FF FF 89 45 F? 8B 45 F? BE 01 00 00 
00 89 C7 E8 ?? FD FF FF 8B 45 F? BE 02 00 00 00 89 C7 E8 ?? F? 
FF FF C9 C3} 
condition:
  uint32(0) == 0x464C457F and all of them
}
rule M_APT_Backdoor_VIRTUALSHINE_1 {
    meta:
        author = "Mandiant"
	strings:
		$str1 = "/dev/vsock"
		$str2 = "/vmfs/devices/char/vsock/vsock"
		$str3 = "nds4961l <cid> <vport>"
		$str4 = "[!] VMCISock_GetAFValue()."
		$str5 = "[+] Connected to server.[ %s:%s ]"
		$str6 = "TERM=xterm"
		$str7 = "PWD=/tmp/"
	condition:
		uint32(0) == 0x464C457F and all of them
          
}
rule M_APT_BACKDOOR_MOPSLED_1
{
	meta:
		author = "Mandiant"
	strings:
		$x = { e8 ?? ?? ?? ?? 85 c0 0f 85 ?? ?? ?? ?? 4? 8d ?? ?4 ?8 
be ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 0f 84 ?? ?? ?? ?? 4? 8b 94 ?? ?? ?? ?? 
?? 4? 8b 44 ?? ?? 4? 89 e1 [0-6]  be ?? ?? ?? ?? b? ?? ?? ?? ?? 4? 89 10 8b 
94 ?? ?? ?? ?? ?? [0-6] 89 50 08 4? 8b 54 ?? ?? c7 42 0c ?? ?? ?? ?? e8 
?? ?? ?? ?? }
    condition:
          uint32(0) == 0x464c457f and uint8(4) == 2 and filesize < 5MB and $x
}
rule M_APT_BACKDOOR_MOPSLED_1
{
	meta:
		author = "Mandiant"
	strings:
		$x = { e8 ?? ?? ?? ?? 85 c0 0f 85 ?? ?? ?? ?? 4? 8d ?? ?4 
?8 be ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 0f 84 ?? ?? ?? ?? 4? 8b 94 
?? ?? ?? ?? ?? 4? 8b 44 ?? ?? 4? 89 e1 [0-6]  be ?? ?? ?? ?? b? ?? ?? 
?? ?? 4? 89 10 8b 94 ?? ?? ?? ?? ?? [0-6] 89 50 08 4? 8b 54 ?? ?? 
c7 42 0c ?? ?? ?? ?? e8 ?? ?? ?? ?? }
    condition:
          uint32(0) == 0x464c457f and uint8(4) == 2 and filesize < 5MB and $x
}
