**Project Description**
Measured Boot Tool demonstrates TPM secure boot and remote attestation on Windows 8.

The tool performs the following tasks:

* Create a new TPM (Trusted Platform Module) AIK (Attestation Identity Key), simulating EK (Endorsement Key) challenge/response with a remote server
* Generate a measured boot log using the new AIK
* Parse the boot log
	* Flag unsigned early-boot drivers
	* Report whether BitLocker is enabled with a TPM-based key protector
	* Report whether boot loader integrity services are enabled
	* Flag the ELAM driver, if any

Sample output:

>MeasuredBootTool.exe
BitLocker (TPM) = True
Integrity services = True
Early boot binaries:
 \Windows\system32\winload.exe -- SIGNED
 \Boot\en-US\bootmgr.EXE.MUI -- SIGNED
 \Windows\System32\Drivers\ksecpkg.sys -- SIGNED
 \Windows\system32\drivers\Wdf01000.sys -- SIGNED
 \Windows\boot\resources\en-US\bootres.dll.mui -- SIGNED
 \Windows\System32\drivers\msrpc.sys -- SIGNED
 \Windows\System32\drivers\vdrvroot.sys -- SIGNED
 \Windows\System32\drivers\storahci.sys -- SIGNED
 \Windows\System32\drivers\WMILIB.SYS -- SIGNED
 \Windows\system32\drivers\tpm.sys -- SIGNED
 \Windows\System32\drivers\pci.sys -- SIGNED
 \Windows\System32\Drivers\cng.sys -- SIGNED
 \Windows\system32\drivers\WdBoot.sys (ELAM) -- SIGNED
 \Windows\System32\drivers\pcw.sys -- SIGNED
 \Windows\System32\drivers\EhStorClass.sys -- SIGNED
 \Windows\System32\drivers\rdyboost.sys -- SIGNED
 \Windows\System32\drivers\disk.sys -- SIGNED
 \Windows\System32\drivers\volsnap.sys -- SIGNED
 \Windows\system32\drivers\fltmgr.sys -- SIGNED
 \Windows\system32\drivers\WdFilter.sys -- SIGNED
 \Windows\System32\drivers\msisadrv.sys -- SIGNED
 \Windows\system32\CI.dll -- SIGNED
 \Windows\System32\Drivers\Fs_Rec.sys -- SIGNED
 \Windows\System32\drivers\tm.sys -- SIGNED
 \Windows\System32\DRIVERS\fvevol.sys -- SIGNED
 \Windows\system32\drivers\ndis.sys -- SIGNED
 \Windows\System32\drivers\partmgr.sys -- SIGNED
 \Windows\system32\drivers\WDFLDR.SYS -- SIGNED
 \Windows\system32\BOOTVID.dll -- SIGNED
 \Windows\system32\mcupdate_GenuineIntel.dll -- SIGNED
 \Windows\System32\drivers\spaceport.sys -- SIGNED
 \Windows\System32\Drivers\mup.sys -- SIGNED
 \Windows\System32\Drivers\Ntfs.sys -- SIGNED
 \Windows\System32\drivers\storport.sys -- SIGNED
 \Windows\System32\drivers\ACPI.sys -- SIGNED
 \Windows\system32\DRIVERS\hpdskflt.sys -- SIGNED
 \Windows\boot\resources\bootres.dll -- SIGNED
 \Windows\System32\Drivers\ksecdd.sys -- SIGNED
 \Windows\System32\drivers\CLFS.SYS -- SIGNED
 \Windows\system32\en-US\winload.exe.MUI -- SIGNED
 \Windows\system32\ApiSetSchema.dll -- SIGNED
 \Windows\system32\drivers\pdc.sys -- SIGNED
 \Windows\System32\drivers\mountmgr.sys -- SIGNED
 \Windows\system32\drivers\NETIO.SYS -- SIGNED
 \Windows\System32\drivers\tcpip.sys -- SIGNED
 \Windows\System32\Drivers\WppRecorder.sys -- SIGNED
 \Windows\System32\drivers\hwpolicy.sys -- SIGNED
 \Windows\System32\Drivers\acpiex.sys -- SIGNED
 \Windows\system32\DRIVERS\wfplwfs.sys -- SIGNED
 \Windows\system32\ntoskrnl.exe -- SIGNED
 \Windows\system32\hal.dll -- SIGNED
 \Windows\system32\PSHED.dll -- SIGNED
 \Windows\System32\drivers\fwpkclnt.sys -- SIGNED
 \Windows\System32\drivers\volmgr.sys -- SIGNED
 \Windows\system32\kd.dll -- SIGNED
 \Windows\System32\drivers\volmgrx.sys -- SIGNED
 \Windows\System32\drivers\fileinfo.sys -- SIGNED
 \Windows\System32\drivers\CLASSPNP.SYS -- SIGNED
