rule Detect_Manual_SEH_Manipulation
{
    meta:
        description = "Detect x86 manual SEH manipulation via fs:[0] head. Typical in SEH waterfall style attacks."
        author = "Carson Hrusovsky"
        creation_date = "2025-11-30"
        reference_sample = "0b31d34bdbfb53f53d1c217452ec6a1afee140f5b10af52df194269a072721da"
        os = "windows"
        arch_context = "x86"
        scan_context = "file"
    
        strings:
        // New entry to SEH head at fs:[0] | mov dword ptr fs:[0], [(eax, ebx, ecx, etc...)]
            $new_chain_fs = /\x64\x89[\x05\x0D\x15\x1D\x25\x2D\x35\x3D]\x00{4}/
            $new_chain_fs_A3 = /\x64\xA3\x00{4}/
            // Save old SEH chain fs:[0] | mov [(eax, ebc, ecx, etc...)], dword ptr fs:[0]
            $save_chain_fs = /\x64\x8B[\x05\x0D\x15\x1D\x25\x2D\x35\x3D]\x00{4}/
            $save_chain_fs_A1 = /\x64\xA1\x00{4}/ 

    condition:
            uint16(0) == 0x5a4d and 
            uint32(uint32(0x3C)) == 0x00004550 and
            ($new_chain_fs or $new_chain_fs_A3) and ($save_chain_fs or $save_chain_fs_A1) // Matches on both - saving fs:[0] and modifying fs:[0].
}
