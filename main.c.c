/*############################################################################*/
/* Keygen - To solve the Kringlecon 2019 'elfscrow' challenge                 */
/*                                                                            */
/* Useage: keygen name_of_encrypted.pdf.enc save_as.pdf                       */
/*                                                                            */
/* by bl4krat                                                                 */
/*############################################################################*/


#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <Windows.h> // required by wincrypt
#include <wincrypt.h>


/*** Global Declarations ***/
typedef unsigned int	uint;
typedef unsigned char	uchar;
typedef unsigned long	ulong;

typedef struct _DESKEYBLOB {
	PUBLICKEYSTRUC hdr;
	DWORD dwKeySize;
	uchar rgbKeyData[8];
} DESKEYBLOB;

int GlobalSeed;


void fatal_error(char *msg) {
	DWORD DVar1;
	HMODULE lpSource;
	DWORD dwMessageId;
	DWORD dwLanguageId;
	char **lpBuffer;
	DWORD nSize;
	va_list *Arguments;
	char *local_10;
	char *buffer;

	buffer = (char *)0x0;
	DVar1 = GetLastError();
	Arguments = (va_list *)0x0;
	nSize = 0;
	lpBuffer = &buffer;
	dwLanguageId = 0x400;
	dwMessageId = DVar1;
	lpSource = GetModuleHandleA("wininet.dll");
	FormatMessageA(0x1b00, lpSource, dwMessageId, dwLanguageId, (LPSTR)lpBuffer, nSize, Arguments);
	printf("Uh oh, something went very wrong. That\'s not supposed to happen.\n");
	printf("Please don\'t tell Santa :(\n\n");
	if (buffer == (char *)0x0) {
		local_10 = "(unknown error)";
	}
	else {
		local_10 = buffer;
	}
	printf("%s: %s (%d)\n", msg, local_10, DVar1);
	/* WARNING: Subroutine does not return */
	exit(1);
}


/*###########################################################################*/
/* prints hex values with an introduction                                    */
void print_hex(char* title, uchar* str, uint length) {
	uint current;
	uint i;

	printf("%s: ", title);

	i = 0;
	while (i < length) {
		current = (uint)str[i];
		printf("%02x", current);
		i++;
	}

	printf(" (length: %d)\n", length);
	return;
}


void write_file(char *filename, uchar *data, uint length) {
	void *f;
	ulong bytes_written;

	if (filename == (char *)0x0) {
		f = GetStdHandle(0xfffffff5);
	}
	else {
		f = CreateFileA(filename, 0x40000000, 0, (LPSECURITY_ATTRIBUTES)0x0, 1, 0x80, (HANDLE)0x0);
	}
	if (f == (void *)0xffffffff) {
		fatal_error("Could not open the file for writing (elfscrow won\'t overwritefiles)");
	}
	WriteFile(f, data, length, &bytes_written, (LPOVERLAPPED)0x0);
	return;
}


void* read_file(char *filename, ulong *bytesRead) {
	DWORD _Size;
	void *lpBuffer;
	BOOL BVar1;
	void *f;

	if (filename == (char *)0x0) {
		f = GetStdHandle(STD_INPUT_HANDLE);
	}
	else {
		f = CreateFileA(filename,GENERIC_READ, 0, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (f == INVALID_HANDLE_VALUE) { 
			fatal_error("Could not open the file for reading");
		}
	}

	_Size = GetFileSize(f, NULL);
	lpBuffer = malloc(_Size);
	BVar1 = ReadFile(f, lpBuffer, _Size, bytesRead, NULL);
	if (BVar1 == 0) {
		fatal_error("Could not read the file");
	}
	CloseHandle(f); //tidy up
	return lpBuffer;
}


/*###########################################################################*/
BOOL do_decrypt(int insecure, char* data, ulong* dataLen, uchar key[8]) {
	BOOL successful;
	DESKEYBLOB keyBlob;
	ulong hProv;
	ulong hKey;
	
	//data = (uchar*) read_file(in_file, &data_len);  //originally, this func read data from a file

	successful = CryptAcquireContextA(&hProv, NULL, "Microsoft Enhanced Cryptographic Provider v1.0", PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	if (!successful) {
		fatal_error("CryptAcquireContext failed");
	}
	//else printf("CryptAcquireContext OK");

	//retrieve_key(insecure, key, id); // this would poll the 'elfscrow' with the id to retrieve the key

	keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
	keyBlob.hdr.bVersion = '\x02';
	keyBlob.hdr.reserved = 0;
	keyBlob.hdr.aiKeyAlg = CALG_DES;
	keyBlob.dwKeySize = 8;
	memcpy(&keyBlob.rgbKeyData, key, keyBlob.dwKeySize);
	
	successful = CryptImportKey(hProv, (BYTE *)&keyBlob, 0x14, 0, 1, &hKey);
	if (!successful) {
		//fatal_error("CryptImportKey failed for DES-CBC key");
		printf("CryptImportKey failed for DES-CBC key\n");
	}
	//else printf(": CryptImportKey sucseeded for DES-CBC key");

	successful = CryptDecrypt(hKey, 0, 1, 0, data, dataLen);
	if (!successful) {
		//fatal_error("CryptDecrypt failed");
		//printf(": CryptDecrypt failed with code: %d\n", GetLastError());
		//exit(1);
	}
	else {
		//printf("File successfully decrypted! Key: \n\n\n\n\n\n\n\n\n\n\n");
		print_hex("Sucsessfully decrypted with key: ", key, 8);
		//print_hex("DEcrypted data: ", data, dataLen);
		// stop execution if we decoded the message
		//exit(1);
	}

	if (CryptReleaseContext(hProv, 0)){	//release the context
		//printf("The handle has been released.\n");
	}
	else {
		printf("The handle could not be released.\n");
	}

	return successful;
}


/*###########################################################################*/
/* Super Secure rng - produces a 'random' int in a non-non-crappy way        */
int super_secure_random(void) {
	GlobalSeed = GlobalSeed * 0x343fd + 0x269ec3;
	return GlobalSeed >> 0x10 & 0x7fff;
}


/*###########################################################################*/
/*Seeds the RNG in a super secure way - by setting GlobalSeed to seed  !     */
void super_secure_srand(int seed) {
	//printf("Seed = %d", seed);
	GlobalSeed = seed;
}


/*###########################################################################*/
/* Generates a super secure key -                                            */
/* so long as you dont do it twice per second. Or at all.                    */
void generateKey(uchar* newKey) {
	int randomNumber;
	time_t currentTime;
	int i;

	printf("Our miniature elves are putting together random bits for your secret key!\n\n");
	time(&currentTime);
	super_secure_srand((int)currentTime);
	i = 0;
	while (i < 8) {
		randomNumber = super_secure_random();
		newKey[i] = (uchar)randomNumber;
		i = i + 1;
	}
	return;
}


/*###########################################################################*/
/* Generates a super secure key for any given time                           */
void generateKeyForTime(uchar* newKey, int currentTime) {
	int randomNumber;
	int i;

	super_secure_srand((int)currentTime);
	i = 0;
	while (i < 8) {
		randomNumber = super_secure_random();
		newKey[i] = (uchar)randomNumber;
		i = i + 1;
	}
	return;
}


/*###########################################################################*/
int main(int argc, char **argv) {

	uchar key[8];
	int	  insecure = 0;
	char* in_file  = argv[1]; // command line parameter 1 = file to decrypt
	char* out_file = argv[2]; // command line parameter 2 = output file name
	char* ctDataMaster; //master copy of the cyphertext data
	ulong ctDataMaster_len; //length of ctDataMaster
	char* ctData; //working copy of ctData - gets overwritten each time we decrypt
	ulong ctData_len; //length of ctData - gets overwritten each time we decrypt
	BOOL successful;
	char PDFSIGNATURE[] = { 0x25, 0x50, 0x44, 0x46, 0x2d };	// file signature for PDF files
	char firstFive[sizeof(PDFSIGNATURE)];
	
	ctDataMaster = (uchar*)read_file(in_file, &ctDataMaster_len); // read in the master data
	//print_hex("Content of input file: ", pbData, data_len);
	//printf("\n");


	// various ranges for t...
	// clue: "we know the fle was encrypted between 7pm and 9pm on 6/12/2019"
	int tMin = 1575658800;		// 7pm 6/12/2019
	int tMax = 1575666000;		// 9pm 6/12/2019

	//int tMax = 1575658800 +1 ;	// 19:00:01 06012129 - 2 second range for testing
	//int tMax = 1575658800 + 500;	// alt max value - run 500 times to estimate duration of entire run
	//int t = 1579064400;			// t = 5am 15/1/2020	- time the test.enc file was encrypted

	// seed for the real pdf - so we can 'just' decrypt it
	// t = 1575663650
	//int tMin = 1575663650;
	//int tMax = 1575663650;


	//calculate the seeds for the known time/date range
	for (int t = tMin; t <= tMax; t++) {	// generate and try all keys
		generateKeyForTime(key, t);
		//print_hex("Key", key, 8);
		
		ctData = malloc(ctDataMaster_len);	// allocate memory on the heap for the data working copy
		memcpy(ctData, ctDataMaster, ctDataMaster_len); // create the working copy of the data
		ctData_len = ctDataMaster_len;					// and the working copy data length

		successful = do_decrypt(insecure, ctData, &ctData_len, key); //try to decrypt with the current key
		if (successful) {												// if decrypt was successful
			printf("main() is dealing with that: Seed value %d", t);
			print_hex("data starts: ", ctData, 32);						//print the first few (32) decrypted bytes
			strncpy(firstFive, ctData, sizeof(firstFive));				//grab the first 5 bytes of the decrypted data
			if (strncmp(firstFive, PDFSIGNATURE, sizeof(PDFSIGNATURE)) == 0) {	// is the signature a .pdf signature?
				printf("\n .pdf file signature detected!!\n\n");
				write_file(out_file, ctData, ctData_len);					// write the data to a file (fails if file exists)
				return 0;											// end here - file has been decrypted.
			}
			else printf("Not a .pdf signature :-(\n\n");
		}
			
		free(ctData);		//release the space on the heap - otherwise there is a memory leak.

	}
	printf("Generated %d keys.\n", tMax - tMin + 1);

	return 0;
}