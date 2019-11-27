#include <windows.h> 
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>
#include <thread>
#include <iostream>
#include <fstream>
#include <string.h>
#include <Shlwapi.h>
#include <aclapi.h>
#include <vector>
#include <conio.h>
// Shlwapi.lib is included because of the "PathFileExists()" function call
#pragma comment(lib, "Shlwapi.lib")

struct clientParsingStruct {
	uint8_t typeFieldParsingResponse = 0x00;
	uint8_t challengeFieldParsingResponseLogic = 0x00;
	uint8_t challengeFieldParsingResponseMemory = 0x00;
	uint8_t parseResponseChallenge = 0x00;
};
struct ClientPktStruct {

	char clientPktName[255] = { 0 };
	int clientPktNameLen = NULL;
	int clientPktNameResp = NULL;

	char clientPktData[500] = { 0 };
	int clientPktDataLen = NULL;
	int clientPktDataResp = NULL;

	BOOL clientPktRegistryChallenge = FALSE;

	char clientPktRegistryHiveName[255] = { 0 };
	char clientpktRegistryKeyEntryName[255] = { 0 };
	char clientpktRegistryKeyEntryValue[255] = { 0 };
	int clientPktHiveType = NULL;
	int clientPktKeyEntryType = NULL;
	int clientPktHiveNameLen = NULL;
	int clientPktHiveTypeLen = NULL;
	int clientPktRegistryKeyEntryNameLen = NULL;
	int clientPktRegistryKeyEntryValueLen = NULL;

	int clientPktChallengeResp = NULL;
};


struct ClientPktStruct getName(const std::vector<uint8_t> &gnclientPktVect, BOOL gnRegChallenge) {
	/*
		Arguments -

			1 - uint8_t array	- gnclientPktVect[] - This is the raw packet from the client
			2 - bool		    - gnRegChallenge	- This is used as a check to determine if the incoming request is for either a Registry based challenge or a File based challenge.

		Local Variables -

			gnGetNameResp			- Custom structure created that holds the return value of this function within the "clientPktNameResp" member
			gnMAX_SIZE_NAME			- Acts as a bounds limit for the max number of bytes to read during a "strnlen_s()" function call
			gnMIN_SIZE_NAME			- Acts as a bounds limit for the min number of bytes allowed - if less then 5 bytes this function exits with an error code
			gnNameElementIdx_Start	- The stating index of the "Name" element within gnclientPktVect
			gnNameLen				- This is used as a bounds for a memcpy() call later on

		Function Description -

			This function returns the name field of the client packet of either two types:
				1 - Registry Name
				2 - File name

			Bounds checking is implemented to also ensure that we're not operating on invalid data when accessing elements within our arrays.

		Potential Return Values stored in "gnGetNameResp.clientPktNameResp"

				Registry Name:
					0x01 Error -> The registry name field within the client packet is NULL
					0x02 Error -> The registry name field within the client packet is less than 5 Bytes long
					0x00 Success -> The registry name field within the client packet was successfully retrieved
					0x04 Error -> The total length of the client packet is less than 3 bytes long
				File Name:
					0x05 Error -> The file name field within the client packet is NULL
					0x06 Error -> The file name field within the client packet is less than 5 Bytes long
					0x00 Success -> The file name field within the client packet was successfully retrieved
					0x08 Error -> The total length of the client packet is less than 3 bytes long
	*/

	ClientPktStruct gnGetNameResp = {};
	size_t gnNameLen = NULL;
	size_t gnRegKeyNameLen = NULL;
	const int gnNameElementIdx_Start = 3;
	const int gnMAX_SIZE_NAME = 254;
	const int gnMIN_SIZE_NAME = 5;

	// This function may get hit multiple times during debug mode so I just want to make sure that each time we null out the values of these members within the gnGetNameResp structure
	memset(gnGetNameResp.clientPktName, 0, sizeof(gnGetNameResp.clientPktName));
	memset(&gnGetNameResp.clientPktNameLen, 0, sizeof(gnGetNameResp.clientPktNameLen));
	memset(gnGetNameResp.clientPktRegistryHiveName, 0, sizeof(gnGetNameResp.clientPktRegistryHiveName));
	memset(&gnGetNameResp.clientPktHiveNameLen, 0, sizeof(gnGetNameResp.clientPktHiveNameLen));
	memset(&gnGetNameResp.clientPktNameResp, 0, sizeof(gnGetNameResp.clientPktNameResp));


	// Determine if challenge is for File objects or Registry Key Objects
	if (gnRegChallenge == TRUE) {
		// The only item we recover from the client packet here is the "Hive name"
		// We're implementing bounds checking in all places where we're accessing unknown user data that resides in an array
		// Here we are checking to make sure that the total size of our clients array (returned from "gnClientPktvect.size()" ) is larger than 3 a.k.a "gnNameElementIdx_Start"	
		if (gnNameElementIdx_Start < gnclientPktVect.size()) {
			gnRegKeyNameLen = strnlen_s((char*)& gnclientPktVect[gnNameElementIdx_Start], gnMAX_SIZE_NAME);
			if (gnRegKeyNameLen == NULL) {
				std::cout << "\t\t\t[+] Server: Error Detected -> The total length of the Hive Name was determined to be NULL" << std::endl;
				std::cout << "\t\t\t[+] Server: Exiting with error code -> 0x01" << std::endl;
				gnGetNameResp.clientPktHiveNameLen = gnRegKeyNameLen;
				gnGetNameResp.clientPktNameResp = 0x01;
				return gnGetNameResp;
			}
			else if (gnRegKeyNameLen < gnMIN_SIZE_NAME) {
				std::cout << "\t\t\t[+] Server: Error Detected -> The total length of the Hive Name was determined to be less than 5 bytes long" << std::endl;
				std::cout << "\t\t\t\t[!] Server: Length of Hive Name -> " << gnRegKeyNameLen << std::endl;
				std::cout << "\t\t\t[+] Server: Exiting with error code -> 0x02" << std::endl;
				gnGetNameResp.clientPktHiveNameLen = gnRegKeyNameLen;
				gnGetNameResp.clientPktNameResp = 0x02;
				return gnGetNameResp;
			}
			else {
				memcpy(gnGetNameResp.clientPktRegistryHiveName, &gnclientPktVect[gnNameElementIdx_Start], gnRegKeyNameLen);
				gnGetNameResp.clientPktHiveNameLen = gnRegKeyNameLen;
				gnGetNameResp.clientPktNameResp = 0x00;
				return gnGetNameResp;
			}
		}
		else {
			std::cout << "\t\t[+] Server: Error Detected -> Total number of elements within the client packet is not greater than three (gnNameElementIdx_Start)" << std::endl;
			std::cout << "\t\t\t[!] Server: Total number of elements within client packet -> " << gnclientPktVect.size() << std::endl;
			std::cout << "\t\t[+] Server: Exiting with error code 0x04" << std::endl;
			gnGetNameResp.clientPktNameResp = 0x04;
			return gnGetNameResp;
		}
	}
	else {
		// The only item we recover from the client packet here is the "Filename"
		// We're implementing bounds checking in all places where we're accessing unknown user data that resides in an array
		// Here we are checking to make sure that the total size of our clients array (returned from "gnClientPktvect.size()" ) is larger than 3 a.k.a "gnNameElementIdx_Start"
		if (gnNameElementIdx_Start < gnclientPktVect.size()) {
			gnNameLen = strnlen_s((char*)& gnclientPktVect[gnNameElementIdx_Start], gnMAX_SIZE_NAME);
			if (gnNameLen == NULL) {
				std::cout << "\t\t\t[+] Server: Error Detected -> The total length of the Filename was determined to be NULL" << std::endl;
				std::cout << "\t\t\t[+] Server: Exiting with error code -> 0x05" << std::endl;
				gnGetNameResp.clientPktNameLen = gnNameLen;
				gnGetNameResp.clientPktNameResp = 0x05;
				return gnGetNameResp;
			}
			else if (gnNameLen < gnMIN_SIZE_NAME) {
				std::cout << "\t\t\t[+] Server: Error Detected -> The total length of the Filename was determined to be less than 5 bytes long" << std::endl;
				std::cout << "\t\t\t\t[!] Server: Length of Filename -> " << gnNameLen << std::endl;
				std::cout << "\t\t\t[+] Server: Exiting with error code -> 0x06" << std::endl;
				gnGetNameResp.clientPktNameLen = gnNameLen;
				gnGetNameResp.clientPktNameResp = 0x06;
				return gnGetNameResp;
			}
			else {
				memcpy(gnGetNameResp.clientPktName, &gnclientPktVect[gnNameElementIdx_Start], gnNameLen);
				gnGetNameResp.clientPktNameLen = gnNameLen;
				gnGetNameResp.clientPktNameResp = 0x00;
				return gnGetNameResp;
			}
		}
		else {
			std::cout << "\t\t[+] Server: Error Detected -> Total number of elements within the client packet is not greater than three (gnNameElementIdx_Start)" << std::endl;
			std::cout << "\t\t\t[!] Server: Total number of elements within client packet -> " << gnclientPktVect.size() << std::endl;
			std::cout << "\t\t[+] Server: Exiting with error code 0x08" << std::endl;
			gnGetNameResp.clientPktNameResp = 0x08;
			return gnGetNameResp;
		}
	}
}
struct ClientPktStruct getValue(const std::vector<uint8_t>& gvclientPktVect, ClientPktStruct& gvClientDataStruct) {
	/*
		Arguments -

			1 - uint8_t array     gvclientPktVect[]  -  Raw client packet data within vector array
			2 - ClientPktStruct   gvClientDataStruct -  This is the same struct that was populated inside of the "getName()" function


		Local Variables -

				// Length Variables
				size_t - gvDataLen		- Acts as a boundary for a memcpy() call later on when dealing with "File" objects
				size_t - gvHiveTypeLen	- Acts as a boundary  for a memcpy() call later on when dealing with "Registry" objects

				// Index Variables
				const int - gvHiveTypeLenIdx_Start  - Starting index of the "Hive Type" element within the Client Packet Array
				const int - gvDataElementIdx_Start  - Starting index of the "Data" element within in the Client Packet Array

				// Maximum and minimum size variables
				const int - gvRegistryMinMax_SIZE	- This value is both the "maximum" and "minimum" size value because the "Hive Type" field in the client packet is only one byte (one element) long
				const int - gvMAX_DATA_SIZE 		- Acts as a boundary during a "strnlen_s()" function call when operating on "File" objects
				const int - gvMIN_DATA_SIZE			- This value is used as a check against the return value from the "strnlen_s()" function call when operating on "File" objects

				// Bounds checking variable
				UINT gvBoundsCheck - Variable used during verification of length of client data field within client packet array before potentially dangerous operations are executed

		Function Description -

			This function returns the DATA field of the client packet of either two types:
				1 - Registry -> Hive Type
				2 - File -> File Data

			Bounds checking is also implemented to ensure that we're not operating on invalid data when accessing elements within our arrays.

		Potential Return Values stored in "gvClientDataStruct.clientPktDataResp"

				Registry Hive Type:
					0x01 Error -> The registry Hive Type field within the client packet is NULL
					0x02 Error -> The registry Hive Type field within the client packet is less than 1 Bytes long
					0x00 Success -> The registry Hive Type field within the client packet was successfully retrieved
					0x04 Error -> The total length of the client packet is less than (gvClientDataStruct.clientPktHiveNameLen + gvHiveTypeLenIdx_Start) bytes long
				File Data:
					0x05 Error -> The file DATA field within the client packet is NULL
					0x06 Error -> The file DATA field within the client packet is less than 5 Bytes long
					0x00 Success -> The file DATA field within the client packet was successfully retrieved
					0x08 Error -> The total length of the client packet is less than (gvClientDataStruct.clientPktNameLen + gvDataElementIdx_Start) bytes long
	*/

	// Length Variables
	size_t gvDataLen = 0;
	size_t gvHiveTypeLen = 0;

	// Index Variables
	const int gvHiveTypeLenIdx_Start = 4;
	const int gvDataElementIdx_Start = 4;

	// Maximum and minimum size variables
	const int gvRegistryMinMax_SIZE = 1;
	const int gvMAX_DATA_SIZE = 499;
	const int gvMIN_DATA_SIZE = 5;

	// Variable used during verification of length of client data before potentially dangerous operations are executed
	UINT gvBoundsCheck = 0;

	memset(gvClientDataStruct.clientPktData, 0, sizeof(gvClientDataStruct.clientPktData));
	memset(&gvClientDataStruct.clientPktDataLen, 0, sizeof(gvClientDataStruct.clientPktDataLen));
	memset(&gvClientDataStruct.clientPktHiveType, 0, sizeof(gvClientDataStruct.clientPktHiveType));
	memset(&gvClientDataStruct.clientPktHiveTypeLen, 0, sizeof(gvClientDataStruct.clientPktHiveTypeLen));
	memset(&gvClientDataStruct.clientPktDataResp, 0, sizeof(gvClientDataStruct.clientPktDataResp));

	// Determine if challenge is for File objects or Registry Key Objects
	if (gvClientDataStruct.clientPktRegistryChallenge == TRUE) {
		// The only item we recover from the client packet here is the "Hive Type"
		// We're implementing bounds checking in all places where we're accessing unknown user data that resides in an array
		// Here we are checking to make sure that the total size of our clients array (returned from "gvclientPktVect.size()" ) is larger than "gvClientDataStruct.clientPktHiveNameLen + gvHiveTypeLenIdx_Start"
		// The reason were making this check is because the "Hive Type" field within our Client Packet array is at a element farther into the array then the "Hive Name" element recorded within the "getName()" function.
		// So, by making sure that "gvBoundsCheck" is smaller then the total elements within the client packet we will be sure to only operate on data within our client packet array safely!
		gvBoundsCheck = (gvClientDataStruct.clientPktHiveNameLen + gvHiveTypeLenIdx_Start);
		if (gvBoundsCheck < gvclientPktVect.size()) {
			gvHiveTypeLen = strnlen_s((char*)& gvclientPktVect[gvClientDataStruct.clientPktHiveNameLen + gvHiveTypeLenIdx_Start], gvRegistryMinMax_SIZE);
			if (gvHiveTypeLen == NULL) {
				std::cout << "\t\t\t[+] Server: Error Detected -> The total length of the Hive Type was determined to be NULL" << std::endl;
				std::cout << "\t\t\t[+] Server: Exiting with error code -> 0x01" << std::endl;
				gvClientDataStruct.clientPktHiveTypeLen = gvHiveTypeLen;
				gvClientDataStruct.clientPktDataResp = 0x01;
				return gvClientDataStruct;
			}
			else if (gvHiveTypeLen < gvRegistryMinMax_SIZE) {
				std::cout << "\t\t\t[+] Server: Error Detected -> The total length of the Hive Type was determined to be less than 1 bytes long" << std::endl;
				std::cout << "\t\t\t\t[!] Server: Length of Hive Name -> " << gvHiveTypeLen << std::endl;
				std::cout << "\t\t\t[+] Server: Exiting with error code -> 0x02" << std::endl;
				gvClientDataStruct.clientPktHiveTypeLen = gvHiveTypeLen;
				gvClientDataStruct.clientPktDataResp = 0x02;
				return gvClientDataStruct;
			}
			else {
				memcpy(&gvClientDataStruct.clientPktHiveType, &gvclientPktVect[gvClientDataStruct.clientPktHiveNameLen + gvHiveTypeLenIdx_Start], gvHiveTypeLen);
				gvClientDataStruct.clientPktHiveTypeLen = gvHiveTypeLen;
				gvClientDataStruct.clientPktDataResp = 0x00;
				return gvClientDataStruct;
			}
		}
		else {
			std::cout << "\t\t[+] Server: Error Detected -> Total number of elements within the client packet is not greater than result of (gvClientDataStruct.clientPktHiveNameLen + gvHiveTypeLenIdx_Start)" << std::endl;
			std::cout << "\t\t\t[!] Server: Total number of elements within client packet -> " << gvclientPktVect.size() << std::endl;
			std::cout << "\t\t[+] Server: Exiting with error code 0x04" << std::endl;
			gvClientDataStruct.clientPktHiveTypeLen = gvHiveTypeLen;
			gvClientDataStruct.clientPktDataResp = 0x04;
			return gvClientDataStruct;
		}
	}
	else {
		// The only item we recover from the client packet here is the File "Data"
		// We're implementing bounds checking in all places where we're accessing unknown user data that resides in an array
		// Here we are checking to make sure that the total size of our clients array (returned from "gvclientPktVect.size()" ) is larger than "gvClientDataStruct.clientPktNameLen + gvDataElementIdx_Start"
		// The reason were making this check is because the "Data" field within our Client Packet array is at a element farther into the array then the "File name" element recorded within the "getName()" function.
		// So, by making sure that "gvBoundsCheck" is smaller then the total elements within the client packet we will be sure to only operate on data within our client packet array safely!
		gvBoundsCheck = (gvClientDataStruct.clientPktNameLen + gvDataElementIdx_Start);
		if (gvBoundsCheck < gvclientPktVect.size()) {
			gvDataLen = strnlen_s((char*)& gvclientPktVect[gvClientDataStruct.clientPktNameLen + gvDataElementIdx_Start], gvMAX_DATA_SIZE);
			if (gvDataLen == NULL) {
				std::cout << "\t\t\t[+] Server: Error Detected -> The total length of the DATA was determined to be NULL" << std::endl;
				std::cout << "\t\t\t[+] Server: Exiting with error code -> 0x05" << std::endl;
				gvClientDataStruct.clientPktDataLen = gvDataLen;
				gvClientDataStruct.clientPktDataResp = 0x05;
				return gvClientDataStruct;
			}
			else if (gvDataLen < gvMIN_DATA_SIZE) {
				std::cout << "\t\t\t[+] Server: Error Detected -> The total length of the DATA was determined to be less than 5 bytes long" << std::endl;
				std::cout << "\t\t\t\t[!] Server: Length of DATA -> " << gvDataLen << std::endl;
				std::cout << "\t\t\t[+] Server: Exiting with error code -> 0x06" << std::endl;
				gvClientDataStruct.clientPktDataLen = gvDataLen;
				gvClientDataStruct.clientPktDataResp = 0x06;
				return gvClientDataStruct;
			}
			else {
				memcpy(gvClientDataStruct.clientPktData, &gvclientPktVect[gvClientDataStruct.clientPktNameLen + gvDataElementIdx_Start], gvDataLen);
				gvClientDataStruct.clientPktDataLen = gvDataLen;
				gvClientDataStruct.clientPktDataResp = 0x00;
				return gvClientDataStruct;
			}
		}
		else {
			std::cout << "\t\t[+] Server: Error Detected -> Total number of elements within the client packet is not greater than result of (gvClientDataStruct.clientPktNameLen + gvDataElementIdx_Start)" << std::endl;
			std::cout << "\t\t\t[!] Server: Total number of elements within client packet -> " << gvclientPktVect.size() << std::endl;
			std::cout << "\t\t[+] Server: Exiting with error code 0x08" << std::endl;
			gvClientDataStruct.clientPktDataLen = gvDataLen;
			gvClientDataStruct.clientPktDataResp = 0x08;
			return gvClientDataStruct;
		}
	}
}

// Logic challenges
void write_file(ClientPktStruct & wfClientPktStruct) {
	/*
		Arguments -

			1 - ClientPktStruct - wfClientPktStruct - This structure holds all the information required to create a new file and write data to it.

		Local Variables -


			wfHandleFile		HANDLE	-	This variable is a "HANDLE" to the File that the client packet wishes to operate on
			wfuint8_tsWritten	DWORD	-	This variable holds the amount of bytes successfully written during the "WriteFile()" function call
			wfResponse			int		-	This is the return value from "WriteFile()" function call

		Function Description -

			This function is responsible for taking the client data provided within the members of the "wfClientPktStruct" and attempting to perform these steps:
				1 - Obtain a handle to this "FILE"
				2 - Attempt to Write the Data from the client to the "FILE"

		Return Values -

			This function returns VOID however - the return values are actually recorded within the "clientPktChallengeResp" member of the ClientPktStruct structure.
			The Caller of this function (A.K.A -> parseClientPkt() ) is responsible for parsing the return values from the structure after returning from this function.

			0x01 - Error -> "CreateFileA()" function call failed and we were unable to obtain a valid HANDLE to the "FILE"
			0x02 - Error -> The amount of bytes recorded within wfuint8_tsWritten during the "WriteFile()" function call do not match with the amount of bytes the client requested to be written
			0x00 - Success -> The amount of bytes recorded within wfuint8_tsWritten during the "WriteFile()" function call do match with the amount of bytes the client requested to be written
			0x04 - Error -> "WriteFile()" function call failed to execute properly so we exit this function returning to "parseClientPkt()"

	*/

	HANDLE wfHandleFile = INVALID_HANDLE_VALUE;
	DWORD wfuint8_tsWritten = 0;
	int wfResponse = 0;

	// Attempt to obtain a HANDLE to a FILE object
	wfHandleFile = CreateFileA(
		wfClientPktStruct.clientPktName,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	// This is a check to make sure that the "HANDLE" obtained CreateFileA() function is a VALID handle
	if (wfHandleFile != INVALID_HANDLE_VALUE) {
		std::cout << "\n\t[+] Server: Creating file with client data now!" << std::endl;
		// Attempt to write data to "x" File
		wfResponse = WriteFile(
			wfHandleFile,
			wfClientPktStruct.clientPktData,
			wfClientPktStruct.clientPktDataLen + 1,
			&wfuint8_tsWritten,
			NULL);
		// Check making sure that the "File" and "Data" was successfully written.
		if (wfResponse != FALSE) {
			std::cout << "\t\t[!] Server: WriteFile() Succeeded." << std::endl;
			std::cout << "\t[+] Server: Checking to ensure that the amount of bytes written during the \"WriteFile()\" function call match with what the client wanted" << std::endl;
			// After attempting to Write data to our file the first thing we check is to make sure that the amount of "DATA" written recorded inside of the "wfuint8_tsWritten" variable matches with the amount of bytes the client wanted to write.
			if ((int)wfuint8_tsWritten < wfClientPktStruct.clientPktDataLen) {
				std::cout << "\t\t[!] Server: The amounts of bytes written do NOT match the amount the client specified" << std::endl;
				std::cout << "\t\t[!] Server: Error -> Invalid amount of bytes were written" << std::endl;
				std::cout << "\t\t[!] Server: Exiting with error code 0x02" << std::endl;
				wfClientPktStruct.clientPktChallengeResp = 0x02;
				return;
			}
			else {
				std::cout << "\t\t[!] Server: The amounts of bytes written do match the amount the client specified" << std::endl;
				std::cout << "\t\t[!] Server: \"WriteFile()\" function call successfully executed" << std::endl;
				wfClientPktStruct.clientPktChallengeResp = 0x00;
				CloseHandle(wfHandleFile);
				return;
			}
		}
		// If "File" and "Data" was not successfully written then ERROR out.
		else {
			std::cout << "\t\t[!] Server: \"WriteFile()\" function call failed to execute properly" << std::endl;
			std::cout << "\t\t[!] Server: Exiting with error code 0x04" << std::endl;
			wfClientPktStruct.clientPktChallengeResp = 0x04;
			CloseHandle(wfHandleFile);
			return;
		}
	}
	// If "HANDLE" was not valid then ERROR out.
	else {
		std::cout << "\t\t[!] Server: Unable to create file." << std::endl;
		std::cout << "\t\t[!] Server: Error -> \"INALID_HANDLE_VALUE\"." << std::endl;
		std::cout << "\t\t[!] Server: Exiting with error code 0x01" << std::endl;
		wfClientPktStruct.clientPktChallengeResp = 0x01;
		return;
	}
}
void delete_file(ClientPktStruct & dfClientPktStruct) {
	/*
		Arguments -

			1 - ClientPktStruct - dfClientPktStruct - This structure holds all information required to delete an arbitrary file from the system.

		Local Variables -

			dfPathExistsResp	BOOL        -	This holds the return value from the "PathFileExistsA()" function call and it is used as a check to make sure the function executed successfully
			dfDeleteFileResp	BOOL        -	This holds the return value from the "DeleteFileA()" function call and it is used as a check to make sure the function executed successfully

		Function Description -

			This function is responsible for taking the client name provided within the member "clientPktName" of the "dfClientPktStruct" structure and perform these steps:
				1 - Check and make sure the file exists by passing it to "PathFileExistsA()" function
				2 - If the file does exist then call "DeleteFileA()" on that file

		Potential Return Values -

			This function returns VOID however - the return values are actually recorded within the "clientPktChallengeResp" member of the ClientPktStruct structure.
			The Caller of this function (A.K.A -> parseClientPkt() ) is responsible for parsing the return values from the structure after returning from this function.

			0x01 - Error -> Client Filename NOT deleted!
			0x00 - Error -> Client Filename deleted!
			0x03 - Error -> Client Filename Does NOT Exists!
			0x04 - Error -> Unknown Response from PathFileExistsA() Function!
	*/

	BOOL dfPathExistsResp = NULL;
	BOOL dfDeleteFileResp = NULL;

	// Check if the file path provided inside of the 
	// ".clientPktName" member is a valid file on the system.
	std::cout << "\n\t[+] Server: Detecting if file provided already exists or not." << std::endl;
	dfPathExistsResp = PathFileExistsA(dfClientPktStruct.clientPktName);

	// Switch case on the return value from "PathFileExistsA()" function call.
	switch (dfPathExistsResp) {

	case TRUE:
		std::cout << "\t\t[!] Server: Filename \"" << dfClientPktStruct.clientPktName << "\" does exist." << std::endl;
		std::cout << "\t\t[!] Server: Continuing to deletion of file" << std::endl;
		dfDeleteFileResp = DeleteFileA(dfClientPktStruct.clientPktName);
		// Switch case on the return value from "DeleteFileA()" function call.
		switch (dfDeleteFileResp) {

		case FALSE:
			std::cout << "\t\t[!] Server: Filename \"" << dfClientPktStruct.clientPktName << "\" NOT deleted." << std::endl;
			std::cout << "\t\t[!] Server: Exiting with error code 0x01" << std::endl;
			dfClientPktStruct.clientPktChallengeResp = 0x01;
			return;

		default:
			std::cout << "\t\t[!] Server: Filename \"" << dfClientPktStruct.clientPktName << "\" deleted." << std::endl;
			dfClientPktStruct.clientPktChallengeResp = 0x00;
			return;
		}

	case FALSE:
		std::cout << "\t\t[!] Server: Filename \"" << dfClientPktStruct.clientPktName << "\" does NOT exist." << std::endl;
		std::cout << "\t\t[!] Server: Exiting with error code 0x03" << std::endl;
		dfClientPktStruct.clientPktChallengeResp = 0x03;
		return;

	default:
		std::cout << "\t\t[!] Server: Unknown response from 'PathFileExistsA()' function!" << std::endl;
		std::cout << "\t\t[!] Server: Exiting with error code 0x04" << std::endl;
		dfClientPktStruct.clientPktChallengeResp = 0x04;
		return;
	}
}
void create_reg_key(ClientPktStruct & crkClientPktStruct) {
	/*
		Arguments -

			1 - ClientPktStruct     crkClientPktStruct - This structure holds all the information required to create a registry key in an arbitrary hive!

		Local Variables -

			crkOpenKeyResp			int			- Holds the response value from the "RegOpenKeyExA()" function.
			crkCreateKeyResp		int			- Holds the response value from the "RegCreateKeyExA()" function.
			crkRegistryKeyName		char		- Local character array which holds the Key Name that the client wishes to create.
			crkHiveType				int			- This variable holds the ID for the type of "HIVE" that the client wishes to operate within.
			crkHiveID				HKEY		- This variable holds the HKEY hive ID.
			crkHiveKeyRaw			HKEY		- This variable holds the Hive Key raw id.

		Function Description -

			This function is responsible for the creation of an registry key in an registry hive on the system.

			First things first - we must determine the type of "HIVE" that we wish to create a registry key within.
			The valid "HIVE" types can be seen in the list below:

				1 - 0x1 = HKEY_CLASSES_ROOT
				2 - 0x2 = HKEY_CURRENT_CONFIG
				3 - 0x3 = HKEY_CURRENT_USER
				4 - 0x4 = HKEY_LOCAL_MACHINE
				5 - 0x5 = HKEY_USERS

			After we figure out the type of "HIVE" that the client wishes to operate on - the next step is checking to see if that Registry Key currently exists or not.
			This is performed by checking the return value from the API function call "RegOpenKeyExA()" for a value of "ERROR_FILE_NOT_FOUND". If this is detected then it can be assumed
			that the desired Registry Key currently does not exists within the given "HIVE".

			After verification that the Registry Key does not exist the next step is creation of that key. This is performed by a function call to "RegCreateKeyExA()".


		Potential Return Values -

				This function returns VOID however - the return values are actually recorded within the "clientPktChallengeResp" member of the ClientPktStruct structure.
				The Caller of this function (A.K.A -> parseClientPkt() ) is responsible for parsing the return values from the structure after returning from this function.

					0x01 - Error -> Unknown hive type!
					0x02 - Error -> RegCreateKey() failure
					0x00 - Success -> Registry key successfully created
					0x04 - Error -> RegOpenKeyA() failure
					0x05 - Error -> Key already exists
	*/

	// responses
	int crkOpenKeyResp = NULL;
	int crkCreateKeyResp = NULL;

	// HKEY's
	HKEY crkHiveID = NULL;
	HKEY crkHiveKeyRaw = NULL;

	std::cout << "\n\t[+] Server: Detecting the hive type." << std::endl;
	// Extract hive type information from clientStruct
	switch (crkClientPktStruct.clientPktHiveType) {
	case 1:
		std::cout << "\t\t[!] Server: assigning hive type \"HKEY_CLASSES_ROOT\"" << std::endl;
		crkHiveID = HKEY_CLASSES_ROOT;
		break;
	case 2:
		std::cout << "\t\t[!] Server: assigning hive type \"HKEY_CURRENT_CONFIG\"" << std::endl;
		crkHiveID = HKEY_CURRENT_CONFIG;
		break;
	case 3:
		std::cout << "\t\t[!] Server: assigning hive type \"HKEY_CURRENT_USER\"" << std::endl;
		crkHiveID = HKEY_CURRENT_USER;
		break;
	case 4:
		std::cout << "\t\t[!] Server: assigning hive type \"HKEY_LOCAL_MACHINE\"" << std::endl;
		crkHiveID = HKEY_LOCAL_MACHINE;
		break;
	case 5:
		std::cout << "\t\t[!] Server: assigning hive type \"HKEY_USERS\"" << std::endl;
		crkHiveID = HKEY_USERS;
		break;
	default:
		std::cout << "\t\t[!] Server: Unknown hive type detected!" << std::endl;
		std::cout << "\t\t[!] Server: Exiting!" << std::endl;
		crkClientPktStruct.clientPktChallengeResp = 0x01;
		return;
	}

	std::cout << "\t[+] Server: Detecting if Registry Key already exists or not!" << std::endl;
	// Now we can check if the key already exists or not.
	// This is done by checking return value of 'RegOpenKeyEx' against 'ERROR_FILE_NOT_FOUND' and 'ERROR SUCCESS'"
	crkOpenKeyResp = RegOpenKeyExA(crkHiveID, crkClientPktStruct.clientPktRegistryHiveName, 0, KEY_READ, &crkHiveKeyRaw);
	if (crkOpenKeyResp == ERROR_FILE_NOT_FOUND) {
		std::cout << "\t\t[!] Server: Registry key not found!" << std::endl;
		std::cout << "\t[+] Server: Continuing to create new registry key: " << crkClientPktStruct.clientPktRegistryHiveName << std::endl;

		// Attempting to create key.
		crkCreateKeyResp = RegCreateKeyExA(crkHiveID, crkClientPktStruct.clientPktRegistryHiveName, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &crkHiveKeyRaw, NULL);

		if (crkCreateKeyResp != ERROR_SUCCESS) {
			std::cout << "\t\t[!] Server: Unknown Error!" << std::endl;
			std::cout << "\t\t[!] Server: Exiting. error code -> " << crkCreateKeyResp << std::endl;
			RegCloseKey(crkHiveKeyRaw);
			crkClientPktStruct.clientPktChallengeResp = 0x02;
			return;
		}
		else {
			std::cout << "\t\t[!] Server: Registry key created!" << std::endl;
			RegCloseKey(crkHiveKeyRaw);
			crkClientPktStruct.clientPktChallengeResp = 0x00;
			return;
		}
	}
	else if (crkOpenKeyResp != ERROR_SUCCESS) {
		std::cout << "\t\t[!] Server: Unknown Error!" << std::endl;
		std::cout << "\t\t[+] Server: Exiting. error code -> " << crkOpenKeyResp << std::endl;
		RegCloseKey(crkHiveKeyRaw);
		crkClientPktStruct.clientPktChallengeResp = 0x04;
		return;
	}
	else {
		std::cout << "\t\t[!] Server: Registry key already exists!" << std::endl;
		std::cout << "\t\t[!] Server: Exiting." << std::endl;
		RegCloseKey(crkHiveKeyRaw);
		crkClientPktStruct.clientPktChallengeResp = 0x05;
		return;
	}
}
void create_reg_entry(const std::vector<uint8_t> & creclientPktVect, ClientPktStruct & creClientPktStruct) {
	/*
		Arguments -

			1 - uint8_t array	  creclientPktVect	    - This is the raw packet from the client
			2 - ClientPktStruct   creClientPktStruct	- This structure holds all the required information in order to properly create a registry key entry in an arbitrary hive!

		Local Variables -

			int creOpenKeyResp - Holds the response value from the "RegOpenKeyExA()" function.
			int creSetValResp - Holds the response value from the "RegSetValueExA()" function.
			int creKeyEntryTypeID = - Holds the ID for the specific type of HIVE Entry type that the client has requested
			HKEY creHiveID - Holds the HKEY hive ID.
			HKEY creHiveKeyRaw - Holds the Hive Key raw id.
			UINT creRegistryValueType_IDX		- Index into the client packet array where the Entry Value Type is located
			UINT creRegistryKeyEntryName_IDX	- Index into the client packet array where the Entry Name Type is located
			UINT creRegistryKeyEntryValue_IDX	- Index into the client packet array where the Entry Value is located


		Function Description -

			This function is responsible for the creation of an registry key entry within a registry key that the client packet requests.

		Potential Return Values -'

			This function returns VOID however - the return values are actually recorded within the "clientPktChallengeResp" member of the ClientPktStruct structure.
			The Caller of this function (A.K.A -> parseClientPkt() ) is responsible for parsing the return values from the structure after returning from this function.

				0x01 - Error -> Unknown Hive Type!
				0x02 - Error -> Potential OOB read while trying to determine the key entry type
				0x03 - Error -> Key Entry Type value within client packet is NULL (0)
				0x04 - Error -> Unknown key entry type detected!
				0x05 - Error -> Potential OOB read while trying to determine the key entry name length
				0x06 - Error -> The length of the client provided Key Entry Name is "Null" (0)
				0x07 - Error -> The length of the client provided Key Entry Name is shorter than 2 bytes
				0x08 - Error -> Potential OOB read while trying to determine the length of the key entry value
				0x09 - Error -> The length of the client provided Key Entry Value is "Null" (0)
				0x10 - Error -> The length of the client provided Key Entry Value is less than 5 bytes
				0x11 - Error -> RegOpenKeyExA() function failed and return value == ERROR_FILE_NOT_FOUND
				0x12 - Error -> RegOpenKeyExA() Unknown error detected
				0x13 - Error -> RegSetValueExA() Unknown error detected
				0x00 - Success -> Registry Key Entry Value was successfully written!
	*/

	// These values hold the return values from RegOpenKeyExA() - RegSetValueExA() - RegCreateKey function calls
	int creOpenKeyResp = NULL;
	int creSetValResp = NULL;

	// Key Entry Type ID
	int creKeyEntryTypeID = NULL;

	// HKEY 
	HKEY creHiveID = NULL;
	HKEY creHiveKeyRaw = NULL;

	// Index
	UINT creRegistryValueType_IDX = 6;
	UINT creRegistryKeyEntryName_IDX = 8;
	UINT creRegistryKeyEntryValue_IDX = 9;

	/*
		First things first - we must determine the type of "HIVE" that we wish to create a registry key within.
			The valid "HIVE" types can be seen in the list below :

		1 - 0x1 = HKEY_CLASSES_ROOT
			2 - 0x2 = HKEY_CURRENT_CONFIG
			3 - 0x3 = HKEY_CURRENT_USER
			4 - 0x4 = HKEY_LOCAL_MACHINE
			5 - 0x5 = HKEY_USERS
	*/
	std::cout << "\n\t[+] Server: Detecting the hive type." << std::endl;
	switch (creClientPktStruct.clientPktHiveType) {
	case 1:
		std::cout << "\t\t[!] Server: assigning hive type \"HKEY_CLASSES_ROOT\"" << std::endl;
		creHiveID = HKEY_CLASSES_ROOT;
		break;
	case 2:
		std::cout << "\t\t[!] Server: assigning hive type \"HKEY_CURRENT_CONFIG\"" << std::endl;
		creHiveID = HKEY_CURRENT_CONFIG;
		break;
	case 3:
		std::cout << "\t\t[!] Server: assigning hive type \"HKEY_CURRENT_USER\"" << std::endl;
		creHiveID = HKEY_CURRENT_USER;
		break;
	case 4:
		std::cout << "\t\t[!] Server: assigning hive type \"HKEY_LOCAL_MACHINE\"" << std::endl;
		creHiveID = HKEY_LOCAL_MACHINE;
		break;
	case 5:
		std::cout << "\t\t[!] Server: assigning hive type \"HKEY_USERS\"" << std::endl;
		creHiveID = HKEY_USERS;
		break;
	default:
		std::cout << "\t\t[!] Server: Unknown hive type detected!" << std::endl;
		std::cout << "\t\t[!] Server: Exiting!" << std::endl;
		creClientPktStruct.clientPktChallengeResp = 0x01;
		return;
	}

	std::cout << "\t[+] Server: Enumerating key entry type." << std::endl;
	if ((creClientPktStruct.clientPktHiveNameLen + creRegistryValueType_IDX) < creclientPktVect.size()) {
		if (&creclientPktVect[creClientPktStruct.clientPktHiveNameLen + creRegistryValueType_IDX] == NULL) {
			// This is a check to determine if the value provided is NULL or not - 
			std::cout << "\t\t[!] Server: Error Detected -> Value was determined to be NULL (0)" << std::endl;
			std::cout << "\t\t[!] Server: Potential NULL (0) byte read. exiting now!" << std::endl;
			creClientPktStruct.clientPktChallengeResp = 0x03;
			return;
		}
		else {
			memcpy(&creClientPktStruct.clientPktKeyEntryType, &creclientPktVect[creClientPktStruct.clientPktHiveNameLen + creRegistryValueType_IDX], 1);
			/*
				After we figure out the type of "HIVE" that the client wishes to operate on - the next step is enumerating the type of entry that the client wishes to create.
					The valid "ENTRY" types can be seen in the list below :

				1 - 0x1 - REG_BINARY
					2 - 0x2 - REG_DWORD
					3 - 0x3 - REG_DWORD_LITTLE_ENDIAN
					4 - 0x4 - REG_DWORD_BIG_ENDIAN
					5 - 0x5 - REG_EXPAND_SZ
					6 - 0x6 - REG_LINK
					7 - 0x7 - REG_MULTI_SZ
					8 - 0x8 - REG_NONE
					9 - 0x9 - REG_QWORD
					10 - 0x10 - REG_QWORD_LITTLE_ENDIAN
					11 - 0x11 - REG_SZ
			*/
			switch (creClientPktStruct.clientPktKeyEntryType) {
			case 1:
				std::cout << "\t\t[!] Server: Assigning entry type \"REG_BINARY\"" << std::endl;
				creKeyEntryTypeID = REG_BINARY;
				break;
			case 2:
				std::cout << "\t\t[!] Server: Assigning entry type \"REG_DWORD\"" << std::endl;
				creKeyEntryTypeID = REG_DWORD;
				break;
			case 3:
				std::cout << "\t\t[!] Server: Assigning entry type \"REG_DWORD_BIG_ENDIAN\"" << std::endl;
				creKeyEntryTypeID = REG_DWORD_BIG_ENDIAN;
				break;
			case 4:
				std::cout << "\t\t[!] Server: Assigning entry type \"REG_DWORD_LITTLE_ENDIAN\"" << std::endl;
				creKeyEntryTypeID = REG_DWORD_LITTLE_ENDIAN;
				break;
			case 5:
				std::cout << "\t\t[!] Server: Assigning entry type \"REG_EXPAND_SZ\"" << std::endl;
				creKeyEntryTypeID = REG_EXPAND_SZ;
				break;
			case 6:
				std::cout << "\t\t[!] Server: Assigning entry type \"REG_LINK\"" << std::endl;
				creKeyEntryTypeID = REG_LINK;
				break;
			case 7:
				std::cout << "\t\t[!] Server: Assigning entry type \"REG_MULTI_SZ\"" << std::endl;
				creKeyEntryTypeID = REG_MULTI_SZ;
				break;
			case 8:
				std::cout << "\t\t[!] Server: Assigning entry type \"REG_NONE\"" << std::endl;
				creKeyEntryTypeID = REG_NONE;
				break;
			case 9:
				std::cout << "\t\t[!] Server: Assigning entry type \"REG_QWORD\"" << std::endl;
				creKeyEntryTypeID = REG_QWORD;
				break;
			case 10:
				std::cout << "\t\t[!] Server: Assigning entry type \"REG_QWORD_LITTLE_ENDIAN\"" << std::endl;
				creKeyEntryTypeID = REG_QWORD_LITTLE_ENDIAN;
				break;
			case 11:
				std::cout << "\t\t[!] Server: Assigning entry type \"REG_SZ\"" << std::endl;
				creKeyEntryTypeID = REG_SZ;
				break;
			default:
				std::cout << "\t\t[!] Server: Unknown key entry type detected!" << std::endl;
				std::cout << "\t\t[!] Server: Exiting!" << std::endl;
				creClientPktStruct.clientPktChallengeResp = 0x04;
				return;
			}

			// Now we have to figure out the registry key entry name that the client wishes to modify
			// implement proper check to make sure were operating on data within proper bounds 
			if ((creClientPktStruct.clientPktHiveNameLen + creRegistryKeyEntryName_IDX) < creclientPktVect.size()) {
				creClientPktStruct.clientPktRegistryKeyEntryNameLen = strnlen_s((char*)& creclientPktVect[creClientPktStruct.clientPktHiveNameLen + creRegistryKeyEntryName_IDX], 254);
				if (creClientPktStruct.clientPktRegistryKeyEntryNameLen != 0) {
					if (creClientPktStruct.clientPktRegistryKeyEntryNameLen < 2) {
						std::cout << "\t\t[!] Server: Client registry key entry name provided is too short." << std::endl;
						std::cout << "\t\t[!] Server: length is shorter then 2 bytes." << std::endl;
						std::cout << "\t\t[!] Server: Exiting program now." << std::endl;
						creClientPktStruct.clientPktChallengeResp = 0x07;
						return;
					}
					else {
						memcpy(creClientPktStruct.clientpktRegistryKeyEntryName, &creclientPktVect[creClientPktStruct.clientPktHiveNameLen + creRegistryKeyEntryName_IDX], creClientPktStruct.clientPktRegistryKeyEntryNameLen);
						std::cout << "\t\t[!] Server: Client key name provided -> " << std::endl;
						std::cout << "\t\t[!] " << creClientPktStruct.clientpktRegistryKeyEntryName << std::endl;
						// make sure were not reading outside of the bounds in regards to creClientPktVect
						if ((creClientPktStruct.clientPktHiveNameLen + creRegistryKeyEntryValue_IDX + creClientPktStruct.clientPktRegistryKeyEntryNameLen) < creclientPktVect.size()) {
							creClientPktStruct.clientPktRegistryKeyEntryValueLen = strnlen_s((char*)& creclientPktVect[creClientPktStruct.clientPktHiveNameLen + creRegistryKeyEntryValue_IDX + creClientPktStruct.clientPktRegistryKeyEntryNameLen], 255);
							if (creClientPktStruct.clientPktRegistryKeyEntryValueLen != NULL) {
								if (creClientPktStruct.clientPktRegistryKeyEntryValueLen < 5) {
									std::cout << "\t\t[!] Server: Client registry key entry value provided is too little characters." << std::endl;
									std::cout << "\t\t[!] Server: Length is shorter then 5 bytes." << std::endl;
									std::cout << "\t\t[!] Server: Exiting program now." << std::endl;
									creClientPktStruct.clientPktChallengeResp = 0x10;
									return;
								}
								else {
									memcpy(creClientPktStruct.clientpktRegistryKeyEntryValue, &creclientPktVect[creClientPktStruct.clientPktHiveNameLen + creRegistryKeyEntryValue_IDX + creClientPktStruct.clientPktRegistryKeyEntryNameLen], creClientPktStruct.clientPktRegistryKeyEntryValueLen);
									std::cout << "\t\t[!] Server: Client key value provided -> " << std::endl;
									std::cout << "\t\t[!] " << creClientPktStruct.clientpktRegistryKeyEntryValue << std::endl;

									// Now we can check if the key already exists or not.
									// this is done by checking return value of 'RegOpenKeyEx' against 'ERROR_FILE_NOT_FOUND' and 'ERROR SUCCESS'"
									creOpenKeyResp = RegOpenKeyExA(creHiveID, creClientPktStruct.clientPktRegistryHiveName, 0, KEY_SET_VALUE, &creHiveKeyRaw);
									if (creOpenKeyResp == ERROR_FILE_NOT_FOUND) {
										std::cout << "\t\t[!] Server: Registry key not found!" << std::endl;
										std::cout << "\t\t[!] Server: Failed to open key -> " << creClientPktStruct.clientPktRegistryHiveName << std::endl;
										std::cout << "\t\t[!] Server: Exiting now!" << std::endl;
										creClientPktStruct.clientPktChallengeResp = 0x11;
										return;
									}
									else if (creOpenKeyResp != ERROR_SUCCESS) {
										std::cout << "\t\t[!] Server: Unknown Error!" << std::endl;
										std::cout << "\t\t[!] Server: Exiting. error code -> " << creOpenKeyResp << std::endl;
										creClientPktStruct.clientPktChallengeResp = 0x12;
										return;
									}
									else {
										std::cout << "\t\t[!] Server: Registry key exists!" << std::endl;
										std::cout << "\t\t[!] Server: Successfully opened key -> " << creClientPktStruct.clientPktRegistryHiveName << std::endl;

										creSetValResp = RegSetValueExA(creHiveKeyRaw, (LPCSTR)creClientPktStruct.clientpktRegistryKeyEntryName, NULL, creKeyEntryTypeID, (LPBYTE)& creClientPktStruct.clientpktRegistryKeyEntryValue, creClientPktStruct.clientPktRegistryKeyEntryValueLen);
										if (creSetValResp != ERROR_SUCCESS) {
											std::cout << "\t\t[!] Server: Unknown Error!" << std::endl;
											std::cout << "\t\t[!] Server: Exiting. error code -> " << creSetValResp << std::endl;
											RegCloseKey(creHiveKeyRaw);
											creClientPktStruct.clientPktChallengeResp = 0x13;
											return;
										}
										else {
											std::cout << "\t[+] Server: Registry Key Entry Value was successfully written!" << std::endl;
											RegCloseKey(creHiveKeyRaw);
											creClientPktStruct.clientPktChallengeResp = 0x00;
											return;
										}
									}
								}
							}
							else {
								std::cout << "\t\t[!] Server: Error obtaining Registry Key Entry Value Length." << std::endl;
								std::cout << "\t\t[!] Server: Potential OOB Read. exiting now!" << std::endl;
								creClientPktStruct.clientPktChallengeResp = 0x09;
								return;
							}

						}
						else {
							std::cout << "\t\t[!] Server: Error obtaining Registry Key Entry Value Length." << std::endl;
							std::cout << "\t\t[!] Server: Potential OOB Read. exiting now!" << std::endl;
							creClientPktStruct.clientPktChallengeResp = 0x08;
							return;
						}
					}
				}
				else {
					std::cout << "\t\t[!] Server: Error Detected -> The Key Entry Name length recorded is NULL (0)" << std::endl;
					creClientPktStruct.clientPktChallengeResp = 0x06;
					return;
				}
			}
			else {
				std::cout << "\t\t[!] Server: Error obtaining Registry Key Entry Name length." << std::endl;
				std::cout << "\t\t[!] Server: Potential OOB read. exiting now!" << std::endl;
				creClientPktStruct.clientPktChallengeResp = 0x05;
				return;
			}
		}
	}
	else {
		std::cout << "\t\t[!] Server: Error Detected -> The value located at " << creClientPktStruct.clientPktHiveNameLen + creRegistryValueType_IDX << " index into \"creclientPktVect\"  is not within range!" << std::endl;
		std::cout << "\t\t[!] Server: Potential OOB read. exiting now!" << std::endl;
		creClientPktStruct.clientPktChallengeResp = 0x02;
		return;
	}
}

// specific packet and response parsing functionality.
void parseTypeField(uint8_t ptfTypeValue, clientParsingStruct & ptfClientParsingStruct) {
	/*
		Arguments -

			1 - uint8_t ptfTypeValue                         - This is the value extracted from the Type field of the client packet
			2 - clientParsingStruct &ptfClientParsingStruct  - This structure holds the return value for this function and is parsed inside of "parseClientPkt()" function

		Local Variables -

			const uint8_t ptfLogicChallenges			- Acts as a potential "case" within a switch statement
			const uint8_t ptfMemoryCorruptionChallenges - Acts as a potential "case" within a switch statement

		Function Description -

			This function is responsible for parsing the value extracted from the "TYPE" field

		Return values -

			This function returns VOID however - the return values are actually recorded within the "typeFieldParsingResponse" member of the ptfClientParsingStruct structure.
			The Caller of this function (A.K.A -> parseClientPkt() ) is responsible for parsing the return values from the structure after returning from this function.

				0x1 - Value provided is valid for "Logic Challenge"
				0x3 - Value provided is not a valid value for the "TYPE" field
	*/

	// Variables
	const uint8_t ptfLogicChallenges = 0x01;
	const uint8_t ptfMemoryCorruptionChallenges = 0x02;

	switch (ptfTypeValue) {
	case ptfLogicChallenges:
		std::cout << "\t\t[!] Server: \"TYPE\" field value recorded is valid." << std::endl;
		std::cout << "\t\t[!] Server: Value is related to \"LOGIC\" challenges." << std::endl;
		ptfClientParsingStruct.typeFieldParsingResponse = 0x01;
		return;
	default:
		std::cout << "\t\t[!] Server: \"TYPE\" field value recorded is NOT valid." << std::endl;
		std::cout << "\t\t[!] Server: Value is not related to any known type." << std::endl;
		ptfClientParsingStruct.typeFieldParsingResponse = 0x03;
		return;
	}
}
void parseChallengeFieldLogic(uint8_t pcflChallengeValue, clientParsingStruct & pcflClientParsingStruct) {
	/*
	Arguments -

		1 - uint8_t				pcflChallengeValue			- This is the value extracted from the Type field of the client packet
		2 - clientParsingStruct &pcflClientParsingStruct	- This structure holds the return value for this function and is parsed inside of "parseClientPkt()" function

	Local Variables -

		const uint8_t pcflWriteFileChallenge				- Acts as a potential "case" within a switch statement if the "WriteFile" challenge is detected
		const uint8_t pcflDeleteFileChallenge				- Acts as a potential "case" within a switch statement if the "DeleteFile" challenge is detected
		const uint8_t pcflCreateRegistryKeyChallenge		- Acts as a potential "case" within a switch statement if the "CreateRegistryKey" challenge is detected
		const uint8_t pcflCreateRegistryKeyEntryChallenge	- Acts as a potential "case" within a switch statement if the "CreateRegistryKeyEntry" challenge is detected
	Function Description -

		This function is responsible for parsing the value extracted from the "Challenge" field

	Return values -
		This function returns VOID however - the return values are actually recorded within the "challengeFieldParsingResponseLogic" member of the pcflClientParsingStruct structure.
		The Caller of this function (A.K.A -> parseClientPkt() ) is responsible for parsing the return values from the structure after returning from this function.

			0x1 - Value provided is valid for "Write File"
			0x2 - Value provided is valid for "Delete File"
			0x3 - Value provided is valid for "Create Registry Key"
			0x4 - Value provided is valid for "Create Registry Key Entry"
			0x5 - Value provided is not a valid challenge type!
*/

// Variables
	const uint8_t pcflWriteFileChallenge = 0x01;
	const uint8_t pcflDeleteFileChallenge = 0x02;
	const uint8_t pcflCreateRegistryKeyChallenge = 0x03;
	const uint8_t pcflCreateRegistryKeyEntryChallenge = 0x04;

	switch (pcflChallengeValue) {
	case pcflWriteFileChallenge:
		std::cout << "\t\t\[!] Server: \"Challenge\" field value recorded is valid." << std::endl;
		std::cout << "\t\t\[!] Server: Value is related to \"Write File\" challenge." << std::endl;
		pcflClientParsingStruct.challengeFieldParsingResponseLogic = 0x01;
		return;
	case pcflDeleteFileChallenge:
		std::cout << "\t\t[!] Server: \"Challenge\" field value recorded is valid." << std::endl;
		std::cout << "\t\t[!] Server: Value is related to \"Delete File\" challenge." << std::endl;
		pcflClientParsingStruct.challengeFieldParsingResponseLogic = 0x02;
		return;
	case pcflCreateRegistryKeyChallenge:
		std::cout << "\t\t[!] Server: \"Challenge\" field value recorded is valid." << std::endl;
		std::cout << "\t\t[!] Server: Value is related to \"Create Registry Key\" challenge." << std::endl;
		pcflClientParsingStruct.challengeFieldParsingResponseLogic = 0x03;
		return;
	case pcflCreateRegistryKeyEntryChallenge:
		std::cout << "\t\t[!] Server: \"Challenge\" field value recorded is valid." << std::endl;
		std::cout << "\t\t[!] Server: Value is related to \"Create Registry Key Entry\" challenge." << std::endl;
		pcflClientParsingStruct.challengeFieldParsingResponseLogic = 0x04;
		return;
	default:
		std::cout << "\t\t[!] Server: \"Challenge\" field value recorded is NOT valid." << std::endl;
		std::cout << "\t\t[!] Server: Value is related to no known \"LOGIC\" challenge." << std::endl;
		pcflClientParsingStruct.challengeFieldParsingResponseLogic = 0x05;
		return;
	}
}

// GW - CHECKED
uint8_t parseClientPkt(const std::vector<uint8_t> & clientPktVect, BOOL debugFlag) {
	/*
		Arguments -

			1 - std::vector<uint8_t>	- clientPktVect - Raw client packet
			2 - BOOL					- debugFlag		(This is to use only for testing when we are doing quality control!!!!!)

		Local Variables -

			clientParsingStruct	- pcpClientParsingStruct	- A structure that holds the return values of the functions that are responsible for parsing the "TYPE" and "Challenge" field of the client packet.
			ClientPktStruct		- pcpClientPktStruct		- Main structure that is populated with data that is parsed from the client packet ("clientPktVect") during program execution
			uint8_t				- pcpClientType				- This holds the "TYPE" field value of the client packet (Either Logic | Unknown Value)
			uint8_t				- pcpClientChallengeNumber	- This holds the "Challenge" field value of the client packet (Either WriteFile, DeleteFile, CreateRegistryKey, CreateRegistryKeyEntry , or UnknownChallenge)
			uint8_t				- pcpClientLength			- At this moment this value is not used however, it is a place holder for potential future vulnerabilities that are added to this vulnerable application
			uint32_t			- pcpClientPktMinLen		- Acts as a boundary limit for the minimum acceptable length of a client packet
			const uint8_t		- pcpLogicChallenges		- Acts as a potential switch statement "case" for if "Logic" challenges are detected within the "Type" field of the client packet
			const uint8_t		- pcpTypeFieldCorrupt		- Acts as a potential switch statement "case" for if the "Type" field challenge is corrupted within the "Type" field of the client packet
			const uint8_t		- pcpWriteFileChallenge					- Acts as switch case for (Logic Challenge - Write File)
			const uint8_t		- pcpDeleteFileChallenge				- Acts as switch case for (Logic Challenge - Delete File)
			const uint8_t		- pcpCreateRegistryKeyChallenge			- Acts as switch case for (Logic Challenge - Registry Key Creation)
			const uint8_t		- pcpCreateRegistryKeyEntryChallenge	- Acts as switch case for (Logic Challenge - Registry Key Entry Creation)
			const uint8_t		- pcpLogicChallengeFieldCorrupt			- Acts as switch case for a potential issue where the function "parseChallengeFieldLogic()" returns a value associated with an "Unknown" challenge type that was recorded from the client packet

		Function Description -

			This function is responsible for initializing the parsing of the client provided packet.

		Potential Return Values -

				0x00 - Function executed successfully
				0x01...0x98 - Function failed
				0x99 - Debug Mode Detected
	*/

	// general structs
	clientParsingStruct pcpClientParsingStruct = {};

	// Variables that hold client packet field values
	ClientPktStruct pcpClientPktStruct = {};
	uint8_t pcpClientType, pcpClientChallengeNumber = 0x00;
	uint8_t pcpClientLength = 0x00;
	uint32_t pcpClientPktMinLen = 3;

	// ------------------------------------
	// Type Detection Switch case variables
	const uint8_t pcpLogicChallenges = 0x01;

	// +++++++++++++++++++++++++++++++++++++
	// Challenge Detection Switch case variables
	const uint8_t pcpWriteFileChallenge = 0x01;
	const uint8_t pcpDeleteFileChallenge = 0x02;
	const uint8_t pcpCreateRegistryKeyChallenge = 0x03;
	const uint8_t pcpCreateRegistryKeyEntryChallenge = 0x04;

	//check if this is a test case to trigger "Debug Mode".
	if (clientPktVect[0] == 0x99) {
		std::cout << "\t[!] Server: \"Debug Mode\" packet Type detected." << std::endl;
		std::cout << "\t[!] Server: Exiting this function now." << std::endl;
		return 0x99;
	}
	else {
		// Check and make sure client packet is min length
		std::cout << "\t[+] Server: Checking length of client packet." << std::endl;
		if (clientPktVect.size() < pcpClientPktMinLen) {
			std::cout << "\t\t[!] Server: Length of client packet is too short." << std::endl;
			std::cout << "\t\t[!] Server: Length of client packet recorded: -> " << clientPktVect.size() << std::endl;
			std::cout << "\t\t[!] Server: Exiting server now." << std::endl;
			return 0x1;
		}
		else {
			std::cout << "\t\t[!] Server: Length of client packet is safe to continue.\n" << std::endl;
			std::cout << "\t[+] Server: Extracting Values: " << std::endl;
			// cast to unsigned: https://stackoverflow.com/questions/19562103/uint8-t-cant-be-printed-with-cout
			std::cout << "\t\t[!] Type Field -> " << (unsigned)clientPktVect[0] << std::endl;
			std::cout << "\t\t[!] Challenge Field -> " << (unsigned)clientPktVect[1] << std::endl;
			std::cout << "\t\t[!] Length Field -> " << (unsigned)clientPktVect[2] << std::endl;

			// Extract values from client packet 
			pcpClientType = clientPktVect[0];
			pcpClientChallengeNumber = clientPktVect[1];
			pcpClientLength = clientPktVect[2];

			std::cout << "\n\t[+] Server: Detecting which \"Type\" of challenge client sent." << std::endl;

			// call Type parsing function.
			parseTypeField(pcpClientType, pcpClientParsingStruct);
			switch (pcpClientParsingStruct.typeFieldParsingResponse) {
			case pcpLogicChallenges:
				std::cout << "\n\t[+] Server: Detecting which logic challenge received." << std::endl;
				// call Logic Challenge parsing function.
				parseChallengeFieldLogic(pcpClientChallengeNumber, pcpClientParsingStruct);
				switch (pcpClientParsingStruct.challengeFieldParsingResponseLogic) {
				case pcpWriteFileChallenge:
					pcpClientPktStruct = getName(clientPktVect, FALSE);
					// After this call to "getName()" we need to check the return value to determine if everything executed successfully or if errors were detected
					if (pcpClientPktStruct.clientPktNameResp == 0x00) {
						std::cout << "\t[+] Server: getName() function success - continuing program execution now" << std::endl;
					}
					else {
						std::cout << "\t[+] Server: getName() function failed - aborting program execution now" << std::endl;
						return pcpClientPktStruct.clientPktNameResp;
					}
					pcpClientPktStruct = getValue(clientPktVect, pcpClientPktStruct);
					// After this call to "getValue()" we need to check the return value to determine if everything executed successfully or if errors were detected
					if (pcpClientPktStruct.clientPktDataResp == 0x00) {
						std::cout << "\t[+] Server: getValue() function success - continuing program execution now" << std::endl;
					}
					else {
						std::cout << "\t[+] Server: getName() function failed - aborting program execution now" << std::endl;
						return pcpClientPktStruct.clientPktDataResp;
					}
					// At this point getName() and getValue() both returned successfully and we are now fully set up to attempt to execute the vulnerable "write_file()" challenge
					write_file(pcpClientPktStruct);
					//  After executing "write_file()" challenge we need to check the return values stored within the member "clientPktChallengeResp" of the "pcpClientPktStruct" structure
					if (pcpClientPktStruct.clientPktChallengeResp == 0x00) {
						std::cout << "\n\t[+] Server: write_file() function success - continuing program execution now" << std::endl;
						return pcpClientPktStruct.clientPktChallengeResp;
					}
					else {
						std::cout << "\n\t[+] Server: write_file() function failed - aborting program execution now" << std::endl;
						return pcpClientPktStruct.clientPktChallengeResp;
					}
				case pcpDeleteFileChallenge:
					pcpClientPktStruct = getName(clientPktVect, FALSE);
					// After this call to "getName()" we need to check the return value to determine if everything executed successfully or if errors were detected
					if (pcpClientPktStruct.clientPktNameResp == 0x00) {
						std::cout << "\t[+] Server: getName() function success - continuing program execution now" << std::endl;
					}
					else {
						std::cout << "\t[+] Server: getName() function failed - aborting program execution now" << std::endl;
						return pcpClientPktStruct.clientPktNameResp;
					}
					// At this point getName() returned successfully and we are now fully set up to attempt to execute the vulnerable "delete_file()" challenge
					delete_file(pcpClientPktStruct);
					//  After executing "delete()" challenge we need to check the return values stored within the member "clientPktChallengeResp" of the "pcpClientPktStruct" structure
					if (pcpClientPktStruct.clientPktChallengeResp == 0x00) {
						std::cout << "\n\t[+] Server: delete_file() function success - continuing program execution now" << std::endl;
						return pcpClientPktStruct.clientPktChallengeResp;
					}
					else {
						std::cout << "\n\t[+] Server: delete_file() function failed - aborting program execution now" << std::endl;
						return pcpClientPktStruct.clientPktChallengeResp;
					}
				case pcpCreateRegistryKeyChallenge:
					pcpClientPktStruct = getName(clientPktVect, TRUE);
					// After this call to "getName()" we need to check the return value to determine if everything executed successfully or if errors were detected
					if (pcpClientPktStruct.clientPktNameResp == 0x00) {
						std::cout << "\t[+] Server: getName() function success - continuing program execution now" << std::endl;
					}
					else {
						std::cout << "\t[+] Server: getName() function failed - aborting program execution now" << std::endl;
						return pcpClientPktStruct.clientPktNameResp;
					}
					pcpClientPktStruct.clientPktRegistryChallenge = TRUE;
					pcpClientPktStruct = getValue(clientPktVect, pcpClientPktStruct);
					// After this call to "getValue()" we need to check the return value to determine if everything executed successfully or if errors were detected
					if (pcpClientPktStruct.clientPktDataResp == 0x00) {
						std::cout << "\t[+] Server: getValue() function success - continuing program execution now" << std::endl;
					}
					else {
						std::cout << "\t[+] Server: getValue() function failed - aborting program execution now" << std::endl;
						return pcpClientPktStruct.clientPktDataResp;
					}
					// At this point getName() and getValue() both returned successfully and we are now fully set up to attempt to execute the vulnerable "create_reg_key()" challenge
					create_reg_key(pcpClientPktStruct);
					//  After executing "create_reg_key()" challenge we need to check the return values stored within the member "clientPktChallengeResp" of the "pcpClientPktStruct" structure
					if (pcpClientPktStruct.clientPktChallengeResp == 0x00) {
						std::cout << "\n\t[+] Server: create_reg_key() function success - continuing program execution now" << std::endl;
						return pcpClientPktStruct.clientPktChallengeResp;
					}
					else {
						std::cout << "\n\t[+] Server: create_reg_key() function failed - aborting program execution now" << std::endl;
						return pcpClientPktStruct.clientPktChallengeResp;
					}
				case pcpCreateRegistryKeyEntryChallenge:
					pcpClientPktStruct = getName(clientPktVect, TRUE);
					// After this call to "getName()" we need to check the return value to determine if everything executed successfully or if errors were detected
					if (pcpClientPktStruct.clientPktNameResp == 0x00) {
						std::cout << "\t[+] Server: getName() function success - continuing program execution now" << std::endl;
					}
					else {
						std::cout << "\t[+] Server: getName() function failed - aborting program execution now" << std::endl;
						return pcpClientPktStruct.clientPktNameResp;
					}
					pcpClientPktStruct.clientPktRegistryChallenge = TRUE;
					pcpClientPktStruct = getValue(clientPktVect, pcpClientPktStruct);
					// After this call to "getValue()" we need to check the return value to determine if everything executed successfully or if errors were detected
					if (pcpClientPktStruct.clientPktDataResp == 0x00) {
						std::cout << "\t[+] Server: getValue() function success - continuing program execution now" << std::endl;
					}
					else {
						std::cout << "\t[+] Server: getValue() function failed - aborting program execution now" << std::endl;
						return pcpClientPktStruct.clientPktDataResp;
					}
					// At this point getName() and getValue() both returned successfully and we are now fully set up to attempt to execute the vulnerable "write_file()" challenge
					create_reg_entry(clientPktVect, pcpClientPktStruct);
					//  After executing "create_reg_entry()" challenge we need to check the return values stored within the member "clientPktChallengeResp" of the "pcpClientPktStruct" structure
					if (pcpClientPktStruct.clientPktChallengeResp == 0x00) {
						std::cout << "\n\t[+] Server: create_reg_entry() function success - continuing program execution now" << std::endl;
						return pcpClientPktStruct.clientPktChallengeResp;
					}
					else {
						std::cout << "\n\t[+] Server: create_reg_entry() function failed - aborting program execution now" << std::endl;
						return pcpClientPktStruct.clientPktChallengeResp;
					}
				default:
					std::cout << "[+] Server: Challenge value recorded from client packet is not supported." << std::endl;
					std::cout << "[+] Server: Challenge value recorded: " << std::endl;
					std::cout << "\t[+] Type value: " << std::endl;
					std::cout << "\t\t[!] Value -> " << pcpClientChallengeNumber << std::endl;
					return 0x3;
				}
			default:
				std::cout << "[+] Server: Type value recorded from client packet is not supported." << std::endl;
				std::cout << "[+] Server: Type value recorded: " << std::endl;
				std::cout << "\t[+] Type value: " << std::endl;
				std::cout << "\t\t[!] Value -> " << pcpClientType << std::endl;
				return 0x02;
			}
		}
	}
}

// GW - CHECKED
BOOL initNamedPipeServer() {
	/*
	   Modified the example code provided from here https://docs.microsoft.com/en-us/windows/win32/secauthz/creating-a-security-descriptor-for-a-new-object-in-c--
	   to output more descriptive error messages during execution

	   Link to MSFT licensing: https://github.com/MicrosoftDocs/win32/blob/docs/LICENSE

		Arguments -

		Local Variables -
			DWORD	dwRes			- The return value from the "SetEntriesInAcl()" function call
			PSID	pEveryoneSID	- Pointer to an SID structure that gets initialized during "AllocateAndInitializeSid()" function call and it is specifically in relation to well-known SID for "Everyone or World" - for more information -> https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
			PSID	pAdminSID		- Pointer to an SID structure that gets initialized during "AllocateAndInitializeSid()" function call and it is specifically in relation to well-known SID for "Builtin\Administrators" - for more information -> https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
			PACL	pACL			- This is a (pointer) to our ACL (Access Control List) which has the following structure:
				typedef struct _ACL {
					BYTE  AclRevision;
					BYTE  Sbz1;
					WORD   AclSize;
					WORD   AceCount;
					WORD   Sbz2;
				} ACL;

			PSECURITY_DESCRIPTOR	pSD	- Security descriptor
			EXPLICIT_ACCESS			ea	- EXPLICIT ACCES struct
				typedef struct _EXPLICIT_ACCESS_W
				{
					DWORD        grfAccessPermissions;
					ACCESS_MODE  grfAccessMode;
					DWORD        grfInheritance;
					TRUSTEE_W    Trustee;
				} EXPLICIT_ACCESS_W, *PEXPLICIT_ACCESS_W, EXPLICIT_ACCESSW, *PEXPLICIT_ACCESSW;

			SID_IDENTIFIER_AUTHORITY		SIDAuthWorld				- Raw Values are {0, 0, 0, 0, 0, 1} - Used in combination with "SECURITY_WORLD_RID" during "AllocateAndInitializeSid()" function call
			SID_IDENTIFIER_AUTHORITY		SIDAuthNT					- Raw Values are {0, 0, 0, 0, 0, 5} - Used in combination with "SECURITY_NT_AUTHORITY" during "AllocateAndInitializeSid()" function call
			SECURITY_ATTRIBUTES				sa						    - SECURITY_ATTRIBUTES structure that contains all information regarding permissions. This structure declares the permissions of our NamedPipe!
			BOOL							daclPresent					- Is set as "TRUE" to force the loading of our custom created DACL within our PSD during the "SetSecurityDescriptorDacl()" function call
			BOOL							defaultDacl				    - Is set as "FALSE" to force the loading of our custom created DACL during the "SetSecurityDescriptorDacl()" function call
			BOOL							AllocAndInitSidEveryone	    - This value holds the return value from the "AllocateAndInitializeSid()" function during initialization of the "pEveryoneSID" variable
			BOOL							AllocAndInitSidAdmin		- This value holds the return value from the "AllocateAndInitializeSid()" function during initialization of the "pAdminSID" variable
			BOOL							InitSecDescp				- This is used to hold the return value from the "InitializeSecurityDescriptor()" function
			UINT							uFlags					    - By using LPTR for this variable we're returning a PTR to the "PSECURITY_DESCRIPTOR" object and "zeroing" the contents of that object during our "LocalAlloc()" function call
			//
			std::vector<uint8_t>	        myVector                    - This is the vector array of "uint8_t" unsigned 8bit integers that is passed to the "parseClientPkt()" function
			HANDLE					        hPipe                       - HANDLE to our Named Pipe Server
			uint8_t					        buffer[1023]                - This is our uint8_t array that holds the data retrieved from the "ReadFile()" function call
			DWORD					        dwRead                      - This variable holds the total number of bytes read from the "ReadFile()" function call
			uint8_t					        parseClientPktResponse      - This is used to parse the response from the "parseClientPkt()" function call
			BOOL					        debugTriggered              - This is used to determine if the server is running in debug "test case" mod.
			BOOL							returnStatus				- This value is used as a "STATUS" variable and it is set to either "TRUE" or "FALSE" at different locations within in function and the value is returned to main() during the "Cleanup" routine


		Function Description -
			This function first creates our SECURITY_ATTRIBUTE then it passes this new SECURITY_ATTRIBUTE as the final argument to CreateNamedPipe() function. This will cause the NamedPipe server that is created to have
			abusable permissions so that anyone in the "Everyone" group will have "GENERIC_ALL" access (W/R) to the pipe.

		Potential Return Values -
				TRUE	- Server executed successfully.
				FALSE	- Server failed to execute properly and errors were detected.
	*/

	DWORD dwRes;
	PSID pEveryoneSID = NULL, pAdminSID = NULL;
	PACL pACL = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	EXPLICIT_ACCESS ea[2];
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
	SECURITY_ATTRIBUTES sa;
	BOOL daclPresent = TRUE;
	BOOL defaultDacl = FALSE;
	BOOL AllocAndInitSidEveryone = FALSE;
	BOOL AllocAndInitSidAdmin = FALSE;
	BOOL InitSecDescp = FALSE;
	UINT uFlags = LPTR;
	PVOID responseFreeSid = NULL;
	PVOID responseLocalFree = NULL;
	BOOL responseCNP = FALSE; // CNP = ConnectNamedPipe()

	std::vector<uint8_t> myVector(5000);
	HANDLE hPipe = INVALID_HANDLE_VALUE;
	uint8_t buffer[1023] = { 0 };
	DWORD dwRead = NULL;
	uint8_t parseClientPktResponse = 0x0;
	BOOL debugTriggered = FALSE;
	BOOL returnStatus = FALSE;

	// zero out the memory of our explicit access structure
	ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));

	// Create a well-known SID for the Everyone group. 
	// The last argument "pEveryoneSID" is a pointer to the allocated and initialized SID structure that is
	// returned from the "AllocateAndInitializeSid()" function
	// Important Links:
	//	https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
	//	https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-allocateandinitializesid
	//	https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-freesid
	AllocAndInitSidEveryone = AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSID);
	// Check if the return value is not true (FALSE a.k.a Failure)
	// If the function did not succeed then we must call the "FreeSid()" function that is implemented within the "Cleanup" routine
	if (!AllocAndInitSidEveryone) {
		std::cout << "\t[+] Server: Error creating SID for the \"Everyone\" Group." << std::endl;
		std::cout << "\t\t[!] Server: \"GetLastError()\" -> " << GetLastError() << std::endl;
		goto Cleanup;
	}

	// The ACE will allow Everyone full access to the key.
	// Populate ACE number 1 in relation to "EVERYONE" group
	ea[0].grfAccessPermissions = GENERIC_ALL;
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea[0].Trustee.ptstrName = (LPTSTR)pEveryoneSID;

	// Create a well-known SID for the BUILTIN\Administrators group. 
	// The last argument "pAdminSID" is a pointer to the allocated and initialized SID structure that is
	// returned from the "AllocateAndInitializeSid()" function
	// Important Links:
	//	https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
	//	https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-allocateandinitializesid
	//	https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-freesid
	AllocAndInitSidAdmin = AllocateAndInitializeSid(&SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminSID);
	// Check if the return value is not true (FALSE a.k.a Failure)
	// If the function did not succeed then we must call the "FreeSid()" function that is implemented within the "Cleanup" routine
	if (!AllocAndInitSidAdmin) {
		std::cout << "\t[+] Server: Error creating SID for the \"BUILTIN\\Administrators\" Group." << std::endl;
		std::cout << "\t\t[!] Server: \"GetLastError()\" -> " << GetLastError() << std::endl;
		goto Cleanup;
	}

	// The ACE will allow the Administrators group full access to
	// Populate ACE number 2 in relation to "BUILTIN\Administrators" group
	ea[1].grfAccessPermissions = GENERIC_ALL;
	ea[1].grfAccessMode = SET_ACCESS;
	ea[1].grfInheritance = NO_INHERITANCE;
	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[1].Trustee.ptstrName = (LPTSTR)pAdminSID;

	// Create a new ACL that contains the new ACEs.
	// https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setentriesinacla
	dwRes = SetEntriesInAcl(2, ea, NULL, &pACL);
	// Check to make sure that the "SetEntriesInAcl()" function executed successfully
	if (dwRes != ERROR_SUCCESS) {
		std::cout << "\t[+] Server: \"SetEntriesInAcl()\" failed." << std::endl;
		std::cout << "\t\t[!] Server: Error -> " << dwRes << std::endl;
		goto Cleanup;
	}

	// Allocate memory for a "PSECURITY_DESCRIPTOR" object
	// By using LPTR we're returning a PTR to the "PSECURITY_DESCRIPTOR" object and "zeroing" the contents of that object!
	// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localalloc
	pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(uFlags, SECURITY_DESCRIPTOR_MIN_LENGTH);
	// Check and make sure that LocalAlloc() did not fail.
	// Failure == NULL | Success == HANDLE of new Memory Object (In our case this is a PSECURITY_DESCRPITOR POINTER)
	if (pSD == NULL) {
		std::cout << "\t[+] Server: Failed to allocate \"PSECURITY_DESCRIPTOR\" object!" << std::endl;
		std::cout << "\t\t[!] Server: Error -> " << GetLastError() << std::endl;
		goto Cleanup;
	}

	//Initialize our \"PSECURITY_DESCRIPTOR\" from "pSD" (LocalAlloc) function call.
	// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-initializesecuritydescriptor
	InitSecDescp = InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION);
	if (InitSecDescp == FALSE) {
		std::cout << "\t[+] Server: Failed to initialize security descriptor!" << std::endl;
		std::cout << "\t\t[!] Server: Error -> " << GetLastError() << std::endl;
		std::cout << "\t[+] Server: Exiting now." << std::endl;
		goto Cleanup;
	}

	// Now that we have successfully created the "SECURITY_DESCRIPTOR" a.k.a "pSD" structure and initialized it
	// This step is to now assign the custom "DACL" specified by the "pACL" (ACL) structure created earlier to our new "pSD" structure
	// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-setsecuritydescriptordacl
	if (!SetSecurityDescriptorDacl(pSD, daclPresent, pACL, defaultDacl)) {
		std::cout << "\t[+] Server: Failed to initialize security descriptor!" << std::endl;
		std::cout << "\t\t[!] Server: Error -> " << GetLastError() << std::endl;
		std::cout << "\t[+] Server: Exiting now." << std::endl;
		goto Cleanup;
	}

	// Initialize a security attributes structure.
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = pSD;
	sa.bInheritHandle = FALSE;

	// Entering Named Pipe Creation
	// We have two main potential cases here and they are either "Normal" execution or "Debug Mode" execution:
	//	If "Normal" mode is detected then code executes.
	//	If "Debug Mode" is detected then another branch is taken and code execution diverts down the "Debug Mode" path.
	std::cout << "\n[+] Server: Creating Named Pipe Server now!" << std::endl;
	std::wcout << "\t[!] Name: NinjaReally\n" << std::endl;
	hPipe = CreateNamedPipe(TEXT("\\\\.\\pipe\\NinjaReally"),
		PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
		1,
		1024 * 16,
		1024 * 16,
		NMPWAIT_USE_DEFAULT_WAIT,
		&sa);
	std::cout << "[+] Server: Checking if handle was successfully gained!" << std::endl;

	// This goto routine is used during automated testing for "Debug Mode"
automatedTesting:
	// This is a check to determine if we're supposed to be executing in "Debug Mode" or not
	if (debugTriggered == TRUE) {
		// We check to make sure that the Handle to the Pipe is still valid (This is a sanity check)
		if (hPipe != INVALID_HANDLE_VALUE) {
			// This function will only return a value after execution has finished (i.e A client connects to the pipe)
			if (ConnectNamedPipe(hPipe, NULL) != FALSE) {
				std::cout << "\t[+] Server: Client Connected!" << std::endl;
				std::cout << "[+] Server: Now were waiting for data to read!" << std::endl;
				// We null out both values for "dwRead" and our "buffer" because each new time we loop
				// through this "Debug Mode" code path these values will be reused and must be reset to default each iteration
				dwRead = NULL;
				memset(&buffer, 0x00, sizeof(buffer));
				// This while loop will execute until we have read the max amount of bytes into our "buffer"
				while (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL) != FALSE) {
					// If the total number of bytes read is still "zero" even with a successful return value from "ReadFile()" function
					// Then we must error out before continuing execution
					if (dwRead == 0) {
						std::cout << "\t[!] Error - Bytes were not read from the pipe." << std::endl;
						std::cout << "\t[!] Error - exiting code execution because of error." << std::endl;
						DisconnectNamedPipe(hPipe);
						goto Cleanup;
					}
					else {
						std::cout << "\t[+] Server: Received client message!" << std::endl;
						std::cout << "[+] Server: Parsing client message now!" << std::endl;
						// We clear out all elements inside of the "myVector" vector to ensure that each time we loop
						// through this "Debug Mode" code path that the vector array is empty and reset to default values for each iteration
						if (myVector.size() != 0) {
							myVector.clear();

						}
						// With this member function call to "insert()" we're copying the contents from our source buffer array "buffer" into our vector "myVector"
						myVector.insert(myVector.end(), &buffer[0], &buffer[dwRead]);
						myVector.shrink_to_fit();
						//	After we populate our "myVector" array with the client packet data we then call upon the function responsible for parsing this data
						parseClientPktResponse = parseClientPkt(myVector, debugTriggered);
						if (parseClientPktResponse == 0x00) {
							std::cout << "\t[+] Server: Parsing Success." << std::endl;
							// The reason we are calling the "DisconnectNamedPipe()" function here is because of how packets are configured and sent using the "Client" code
							DisconnectNamedPipe(hPipe);
							printf("[+] Server: To continue automated testing please hit \"ENTER\" key.\n");
							system("pause");
							goto automatedTesting;
						}
						else if (parseClientPktResponse != 0x00) {
							std::cout << "\t[+] Server: Parsing Error." << std::endl;
							std::cout << "\t[+] Server: parseClientPkt() return code -> " << parseClientPktResponse << std::endl;
							// The reason we are calling the "DisconnectNamedPipe()" function here is because of how packets are configured and sent using the "Client" code
							DisconnectNamedPipe(hPipe);
							printf("[+] Server: To continue automated testing please hit \"ENTER\" key.\n");
							system("pause");
							goto automatedTesting;
						}
						else {
							std::cout << "\t[+] Server: Unknown Error" << std::endl;
							std::cout << "\t[+] Server: parseClientPkt() return code -> " << parseClientPktResponse << std::endl;
							DisconnectNamedPipe(hPipe);
							goto Cleanup;
						}
					}
				}
			}
			else {
				// This is executed when ever "ConnectNamedPipe()" function fails to execute properly 
				// From here instead of continuing to try and execute debug packet parsing simply bail execution and enter "Cleanup" routine
				std::cout << "\t[!] Server: \"ConnectNamedPipe()\" failed to properly execute." << std::endl;
				std::cout << "\t[!] Server: Error code -> " << GetLastError() << std::endl;
				goto Cleanup;
			}
		}
		else {
			std::cout << "[!] Server: Handle \"hPipe\" is no longer valid." << std::endl;
			std::cout << "[!] Server: Error -> " << GetLastError() << std::endl;
			goto Cleanup;
		}
	}
	else {
		// NORMAL MODE BRANCH
		// First we're checking to make sure that the Handle to the Pipe is still valid
		if (hPipe != INVALID_HANDLE_VALUE) {
			// This function will only return a value after execution has finished (i.e A client connects to the pipe)
			if (ConnectNamedPipe(hPipe, NULL) != FALSE) {
				std::cout << "\t[!] Server: Client Connected!\n" << std::endl;
				std::cout << "[+] Server: Now were waiting for data to read!" << std::endl;
				// We null out both values for "dwRead" and our "buffer" as a sanity check to make sure everything is null before continuing execution
				dwRead = NULL;
				memset(&buffer, 0x00, sizeof(buffer));
				// This while loop will execute until we have read the max amount of bytes into our "buffer"
				while (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL) != FALSE) {
					// If the total number of bytes read is still "zero" even with a successful return value from "ReadFile()" function
					// Then we must error out before continuing execution
					if (dwRead == 0) {
						std::cout << "\t[!] Error - Bytes were not read from the pipe." << std::endl;
						std::cout << "\t[!] Error - Exiting code execution because of error." << std::endl;
						DisconnectNamedPipe(hPipe);
						goto Cleanup;
					}
					else {
						std::cout << "\t[!] Server: Received client message!\n" << std::endl;
						std::cout << "[+] Server: Parsing client message now!" << std::endl;
						// We clear out all elements inside of the "myVector" vector to ensure that it is empty as a sanity check
						if (myVector.size() != 0) {
							myVector.clear();
						}
						// With this member function call to "insert()" we're copying the contents from our source buffer array "buffer" into our vector "myVector"
						myVector.insert(myVector.end(), &buffer[0], &buffer[dwRead]);
						myVector.shrink_to_fit();
						//	After we populate our "myVector" array with the client packet data we then call upon the function responsible for parsing this data
						parseClientPktResponse = parseClientPkt(myVector, debugTriggered);
						if (parseClientPktResponse == 0x00) {
							std::cout << "[+] Server: Parsing Success." << std::endl;
							// The reason we are calling the "DisconnectNamedPipe()" function here is because of how packets are configured and sent using the "Client" code
							returnStatus = TRUE;
							DisconnectNamedPipe(hPipe);
							goto Cleanup;
						}
						else if (parseClientPktResponse == 0x99) {
							std::cout << "\t[+] Server: Debug Mode in progress." << std::endl;
							// The reason we are calling the "DisconnectNamedPipe()" function here is because of how packets are configured and sent using the "Client" code
							DisconnectNamedPipe(hPipe);
							printf("[+] Server: To continue automated testing please hit \"ENTER\" key.\n");
							system("pause");
							debugTriggered = TRUE;
							goto automatedTesting;
						}
						else {
							std::cout << "\t[+] Server: Parsing Error." << std::endl;
							std::cout << "\t[+] Server: parseClientPkt() return code -> " << parseClientPktResponse << std::endl;
							// The reason we are calling the "DisconnectNamedPipe()" function here is because of how packets are configured and sent using the "Client" code
							DisconnectNamedPipe(hPipe);
							goto Cleanup;
						}
					}
				}
			}
			else {
				// This is executed when ever "ConnectNamedPipe()" function fails to execute properly 
				// From here instead of continuing to try and execute debug packet parsing simply bail execution and enter "Cleanup" routine
				std::cout << "\t[!] Server: \"ConnectNamedPipe()\" failed to properly execute." << std::endl;
				std::cout << "\t[!] Server: Error code -> " << GetLastError() << std::endl;
			}
		}
		else {
			std::cout << "[!] Server: Handle \"hPipe\" is no longer valid." << std::endl;
			std::cout << "[!] Server: Error -> " << GetLastError() << std::endl;
		}
	}
Cleanup:

	/*
		CleanUp Best Practices:
			1 - List all current locations where goto exists
			2 - If any new goto is created include it in the list and check to make sure that all other code still functions as intended
			3 - Check and make sure that every item we try to free is that valid "TYPE" before we try to free it
	*/
	// Check to only attempt to close "hPipe" if it is a VALID handle
	if (hPipe != INVALID_HANDLE_VALUE)
		CloseHandle(hPipe);

	// Check to ensure that the "SID" we attempt to free is "VALID" otherwise if we attempt to call "FreeSID()" on an invalid value we could encounter a heap access violation
	if (pEveryoneSID != NULL) {
		if (IsValidSid(pEveryoneSID))
			FreeSid(pEveryoneSID);
	}

	// Check to ensure that the "SID" we attempt to free is "VALID" otherwise if we attempt to call "FreeSID()" on an invalid value we could encounter a heap access violation
	if (pAdminSID != NULL) {
		if (IsValidSid(pAdminSID))
			FreeSid(pAdminSID);
	}

	// Check to ensure that the "ACL" we attempt to free is "VALID" before we attempt to free that allocated heap memory via "LocalFree()"
	if (pACL != NULL) {
		if (IsValidAcl(pACL))
			LocalFree(pACL);
	}

	// Check to ensure that the "SECURITY_DESCRIPTOR" object is "VALID" before we attempt to free that allocated heap memory via "LocalFree()"
	if (pSD != NULL) {
		if (IsValidSecurityDescriptor(pSD))
			LocalFree(pSD);
	}

	// Check to ensure the proper return value to main()
	if (returnStatus == TRUE) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

// GW - CHECKED
int main()
{

	BOOL parsingStatus = FALSE;

	std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << std::endl;
	std::cout << R"(
____   ____            _________            .__  __          
\   \ /   /___________/   _____/____________|__|/  |_  ____  
 \   Y   // __ \_  __ \_____  \\____ \_  __ \  \   __\/ __ \ 
  \     /\  ___/|  | \/        \  |_> >  | \/  ||  | \  ___/ 
   \___/  \___  >__| /_______  /   __/|__|  |__||__|  \___  >
              \/             \/|__|                       \/ 
)" << std::endl;
	std::cout << "\n" << "[+] VULNERABLE NAMED PIPE SERVER" << std::endl;
	std::cout << "[+] Challenges Supported: " << std::endl;
	std::cout << "\t[!] Logic Vulnerabilities." << std::endl;
	std::cout << "\t\t[+] 1: Vulnerable File Write" << std::endl;
	std::cout << "\t\t[+] 2: Vulnerable File Deletion" << std::endl;
	std::cout << "\t\t[+] 3: Vulnerable Registry Key Modification" << std::endl;
	std::cout << "\t\t[+] 4: Vulnerable Registry Key Entry Modification" << std::endl;
	std::cout << "\t[!] Memory Corruption Vulnerabilities." << std::endl;
	std::cout << "\t\t[+] Currently Not Implemented." << std::endl;
	std::cout << "\n[+] Authors: Robert Hawes" << "\n" << "[+] Twitter: @VulnMind" << "\n" << "[+] VerSprite: VS-Labs Research Team" << "\n" << std::endl;
	std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << std::endl;
	std::cout << "[+] Server: Running the named pipe server now." << std::endl;
	parsingStatus = initNamedPipeServer();
	if (parsingStatus != TRUE) {
		std::cout << "[+] Server: Error detected, exiting now." << std::endl;
		return EXIT_FAILURE;
	}
	else {
		std::cout << "[+] Server: Execution successful, Exiting now." << std::endl;
		return EXIT_SUCCESS;
	}
}