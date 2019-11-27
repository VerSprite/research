#include <iostream>
#include <windows.h> 
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <strsafe.h>
#include <wchar.h>
#include <vector>
#include <map>
#include <string>
#include <conio.h>

//This is the client code ---

// This is the general packet layout that the Named Pipe Server is expecting to receive
struct ChallengePacketFormat {
	uint8_t cpfType = 0x00;
	uint8_t cpfChallengeNumber = 0x00;
	uint8_t cpfLength = 0x00;
	std::vector<uint8_t> cpfData;
};

// Debug testing potentially malicious/malformed client packets to make sure the 
// Named Pipe Server can properly parse them without potential security issues appearing
// Challenge Testing -> CreateRegistryKeyEntry 
struct debugRegistryKeyEntry {

	// General comment of all these different arrays (client packets) 
	// Length - Currently not supported within the Named Pipe Server - value can be anything as long as it is a "byte" (a.k.a uint8_t) client side in the packet

	uint8_t spCreateRegKeyEntryClientPkt[51] = {
		0x01, // Type
		0x04, // Challenge Number
		0x11, // Length 
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x53, 0x4f, 0x46, 0x54, 0x57, 0x41, 0x52, 0x45, 0x5c, 0x5c, 0x57, 0x4f, 0x57, 0x5c, 0x5c, 0x54, 0x45, 0x53, 0x54, 0x49, 0x4e, 0x47, 0x5c, 0x5c, 0x44, 0x4f, 0x47, //Hive Name - string -> "SOFTWARE\\WOW\\TESTING\\DOG"
		0x00, // NULLBYTE
		0x01, // Type of Hive to utilize
		0x00, // NULLBYTE
		0x01, // Type of Registry Value
		0x00, // NULLBYTE
		0x57, 0x6f, 0x57, 0x5a, 0x61, 0x68, // Registry Key Entry Name - string -> "WoWZah"
		0x00, // NULLBYTE
		0x41, 0x41, 0x41, 0x43, 0x45, 0x45, 0x42, 0x43, // Registry Key Value - string -> "AAACEEBC"
		0x00 // NULLBYTE
	};
	// Test Case - Remove Hive Name
	uint8_t spCreateRegKeyEntryClientPkt_HiveName[24] = {
		0x01, // Type
		0x04, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x00, // NULLBYTE
		0x01, // Type of Hive to utilize
		0x00, // NULLBYTE
		0x01, // Type of Registry Value
		0x00, // NULLBYTE
		0x57, 0x6f, 0x57, 0x5a, 0x61, 0x68, // Registry Key Entry Name - string -> "WoWZah"
		0x00, // NULLBYTE
		0x41, 0x41, 0x41, 0x43, 0x45, 0x45, 0x42, 0x43, // Registry Key Value - string -> "AAACEEBC"
		0x00 // NULLBYTE
	};
	// Test Case - Remove NullByte after Hive
	uint8_t spCreateRegKeyEntryClientPkt_NB_HiveName[50] = {
		0x01, // Type
		0x04, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x53, 0x4f, 0x46, 0x54, 0x57, 0x41, 0x52, 0x45, 0x5c, 0x5c, 0x57, 0x4f, 0x57, 0x5c, 0x5c, 0x54, 0x45, 0x53, 0x54, 0x49, 0x4e, 0x47, 0x5c, 0x5c, 0x44, 0x4f, 0x47, //Hive Name - string -> "SOFTWARE\\WOW\\TESTING\\DOG"
		0x01, // Type of Hive to utilize
		0x00, // NULLBYTE
		0x01, // Type of Registry Value
		0x00, // NULLBYTE
		0x57, 0x6f, 0x57, 0x5a, 0x61, 0x68, // Registry Key Entry Name - string -> "WoWZah"
		0x00, // NULLBYTE
		0x41, 0x41, 0x41, 0x43, 0x45, 0x45, 0x42, 0x43, // Registry Key Value - string -> "AAACEEBC"
		0x00 // NULLBYTE
	};
	// Test Case - Remove Hive Type
	uint8_t spCreateRegKeyEntryClientPkt_HiveType[50] = {
		0x01, // Type
		0x04, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x53, 0x4f, 0x46, 0x54, 0x57, 0x41, 0x52, 0x45, 0x5c, 0x5c, 0x57, 0x4f, 0x57, 0x5c, 0x5c, 0x54, 0x45, 0x53, 0x54, 0x49, 0x4e, 0x47, 0x5c, 0x5c, 0x44, 0x4f, 0x47, //Hive Name - string -> "SOFTWARE\\WOW\\TESTING\\DOG"
		0x00, // NULLBYTE
		0x00, // NULLBYTE
		0x01, // Type of Registry Value
		0x00, // NULLBYTE
		0x57, 0x6f, 0x57, 0x5a, 0x61, 0x68, // Registry Key Entry Name - string -> "WoWZah"
		0x00, // NULLBYTE
		0x41, 0x41, 0x41, 0x43, 0x45, 0x45, 0x42, 0x43, // Registry Key Value - string -> "AAACEEBC"
		0x00 // NULLBYTE
	};
	// Test Case - Remove NullByte after Hive Type
	uint8_t spCreateRegKeyEntryClientPkt_NB_HiveType[50] = {
		0x01, // Type
		0x04, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x53, 0x4f, 0x46, 0x54, 0x57, 0x41, 0x52, 0x45, 0x5c, 0x5c, 0x57, 0x4f, 0x57, 0x5c, 0x5c, 0x54, 0x45, 0x53, 0x54, 0x49, 0x4e, 0x47, 0x5c, 0x5c, 0x44, 0x4f, 0x47, //Hive Name - string -> "SOFTWARE\\WOW\\TESTING\\DOG"
		0x00, // NULLBYTE
		0x01, // Type of Hive to utilize
		0x01, // Type of Registry Value
		0x00, // NULLBYTE
		0x57, 0x6f, 0x57, 0x5a, 0x61, 0x68, // Registry Key Entry Name - string -> "WoWZah"
		0x00, // NULLBYTE
		0x41, 0x41, 0x41, 0x43, 0x45, 0x45, 0x42, 0x43, // Registry Key Value - string -> "AAACEEBC"
		0x00 // NULLBYTE
	};
	// Test Case - Remove Type of Registry
	uint8_t spCreateRegKeyEntryClientPkt_RegistryType[50] = {
		0x01, // Type
		0x04, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x53 ,0x4f ,0x46 ,0x54 ,0x57 ,0x41 ,0x52 ,0x45 ,0x5c ,0x5c ,0x57 ,0x4f ,0x57 ,0x5c ,0x5c ,0x54 ,0x45 ,0x53 ,0x54 ,0x49 ,0x4e ,0x47 ,0x5c ,0x5c ,0x44 ,0x4f ,0x47, //Hive Name - string -> "SOFTWARE\\WOW\\TESTING\\DOG"
		0x00, // NULLBYTE
		0x01, // Type of Hive to utilize
		0x00, // NULLBYTE
		0x00, // NULLBYTE
		0x57,0x6f ,0x57 ,0x5a ,0x61 ,0x68, // Registry Key Entry Name - string -> "WoWZah"
		0x00, // NULLBYTE
		0x41, 0x41, 0x41, 0x43, 0x45, 0x45, 0x42, 0x43, // Registry Key Value - string -> "AAACEEBC"
		0x00 // NULLBYTE
	};
	// Test Case - Remove NullByte after Registry Type
	uint8_t spCreateRegKeyEntryClientPkt_NB_RegistryType[50] = {
		0x01, // Type
		0x04, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x53, 0x4f, 0x46, 0x54, 0x57, 0x41, 0x52, 0x45, 0x5c, 0x5c, 0x57, 0x4f, 0x57, 0x5c, 0x5c, 0x54, 0x45, 0x53, 0x54, 0x49, 0x4e, 0x47, 0x5c, 0x5c, 0x44, 0x4f, 0x47, //Hive Name - string -> "SOFTWARE\\WOW\\TESTING\\DOG"
		0x00, // NULLBYTE
		0x01, // Type of Hive to utilize
		0x00, // NULLBYTE
		0x01, // Type of Registry Value
		0x57, 0x6f, 0x57, 0x5a, 0x61, 0x68, // Registry Key Entry Name - string -> "WoWZah"
		0x00, // NULLBYTE
		0x41, 0x41, 0x41, 0x43, 0x45, 0x45, 0x42, 0x43, // Registry Key Value - string -> "AAACEEBC"
		0x00 // NULLBYTE
	};
	// Test Case - Remove Registry Key Entry name
	uint8_t spCreateRegKeyEntryClientPkt_RegistryKeyName[45] = {
		0x01, // Type
		0x04, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x53, 0x4f, 0x46, 0x54, 0x57, 0x41, 0x52, 0x45, 0x5c, 0x5c, 0x57, 0x4f, 0x57, 0x5c, 0x5c, 0x54, 0x45, 0x53, 0x54, 0x49, 0x4e, 0x47, 0x5c, 0x5c, 0x44, 0x4f, 0x47, //Hive Name - string -> "SOFTWARE\\WOW\\TESTING\\DOG"
		0x00, // NULLBYTE
		0x01, // Type of Hive to utilize
		0x00, // NULLBYTE
		0x01, // Type of Registry Value
		0x00, // NULLBYTE
		0x00, // NULLBYTE
		0x41, 0x41, 0x41, 0x43, 0x45, 0x45, 0x42, 0x43, // Registry Key Value - string -> "AAACEEBC"
		0x00 // NULLBYTE
	};
	// Test Case - Remove NullByte after Registry Key Name
	uint8_t spCreateRegKeyEntryClientPkt_NB_RegistryKeyName[50] = {
		0x01, // Type
		0x04, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x53, 0x4f, 0x46, 0x54, 0x57, 0x41, 0x52, 0x45, 0x5c, 0x5c, 0x57, 0x4f, 0x57, 0x5c, 0x5c, 0x54, 0x45, 0x53, 0x54, 0x49, 0x4e, 0x47, 0x5c, 0x5c, 0x44, 0x4f, 0x47, //Hive Name - string -> "SOFTWARE\\WOW\\TESTING\\DOG"
		0x00, // NULLBYTE
		0x01, // Type of Hive to utilize
		0x00, // NULLBYTE
		0x01, // Type of Registry Value
		0x00, // NULLBYTE
		0x57, 0x6f, 0x57, 0x5a, 0x61, 0x68, // Registry Key Entry Name - string -> "WoWZah"
		0x41, 0x41, 0x41, 0x43, 0x45, 0x45, 0x42, 0x43, // Registry Key Value - string -> "AAACEEBC"
		0x00 // NULLBYTE
	};
	// Test Case - Remove Registry Key Value
	uint8_t spCreateRegKeyEntryClientPkt_RegistryKeyValue[43] = {
		0x01, // Type
		0x04, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x53, 0x4f, 0x46, 0x54, 0x57, 0x41, 0x52, 0x45, 0x5c, 0x5c, 0x57, 0x4f, 0x57, 0x5c, 0x5c, 0x54, 0x45, 0x53, 0x54, 0x49, 0x4e, 0x47, 0x5c, 0x5c, 0x44, 0x4f, 0x47, //Hive Name - string -> "SOFTWARE\\WOW\\TESTING\\DOG"
		0x00, // NULLBYTE
		0x01, // Type of Hive to utilize
		0x00, // NULLBYTE
		0x01, // Type of Registry Value
		0x00, // NULLBYTE
		0x57, 0x6f, 0x57, 0x5a, 0x61, 0x68, // Registry Key Entry Name - string -> "WoWZah"
		0x00, // NULLBYTE
		0x00 // NULLBYTE
	};
	// Test Case - Remove NullByte After Registry Key Value
	uint8_t spCreateRegKeyEntryClientPkt_NB_RegistryKeyValue[50] = {
		0x01, // Type
		0x04, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x53, 0x4f, 0x46, 0x54, 0x57, 0x41, 0x52, 0x45, 0x5c, 0x5c, 0x57, 0x4f, 0x57, 0x5c, 0x5c, 0x54, 0x45, 0x53, 0x54, 0x49, 0x4e, 0x47, 0x5c, 0x5c, 0x44, 0x4f, 0x47, //Hive Name - string -> "SOFTWARE\\WOW\\TESTING\\DOG"
		0x00, // NULLBYTE
		0x01, // Type of Hive to utilize
		0x00, // NULLBYTE
		0x01, // Type of Registry Value
		0x00, // NULLBYTE
		0x57, 0x6f, 0x57, 0x5a, 0x61, 0x68, // Registry Key Entry Name - string -> "WoWZah"
		0x00, // NULLBYTE
		0x41, 0x41, 0x41, 0x43, 0x45, 0x45, 0x42, 0x43, // Registry Key Value - string -> "AAACEEBC"
	};
};

// Debug testing potentially malicious/malformed client packets to make sure the 
// Named Pipe Server can properly parse them without potential security issues appearing
// Challenge Testing -> CreateRegistryKey 
struct debugRegistryKey {

	// General comment of all these different arrays (client packets) 
	// Length - Currently not supported within the Named Pipe Server - value can be anything as long as it is a "byte" (a.k.a uint8_t) client side in the packet

	uint8_t spCreateRegKeyClientPkt[33] = {
		0x01, // Type
		0x03, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x53, 0x4f, 0x46, 0x54, 0x57, 0x41, 0x52, 0x45, 0x5c, 0x5c, 0x57, 0x4f, 0x57, 0x5c, 0x5c, 0x54, 0x45, 0x53, 0x54, 0x49, 0x4e, 0x47, 0x5c, 0x5c, 0x44, 0x4f, 0x47, //Hive Name - string -> "SOFTWARE\\WOW\\TESTING\\DOG"
		0x00, // NULLBYTE
		0x01, // Hive Type
		0x00  // NULLBYTE
	};
	// Test Case - Remove Hive Name
	uint8_t spCreateRegKeyClientPkt_HiveName[6] = {
		0x01, // Type
		0x03, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x00, // NULLBYTE
		0x01, // Hive Type
		0x00  // NULLBYTE
	};
	// Test Case - Remove Hive Type
	uint8_t spCreateRegKeyClientPkt_HiveType[32] = {
		0x01, // Type
		0x03, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x53, 0x4f, 0x46, 0x54, 0x57, 0x41, 0x52, 0x45, 0x5c, 0x5c, 0x57, 0x4f, 0x57, 0x5c, 0x5c, 0x54, 0x45, 0x53, 0x54, 0x49, 0x4e, 0x47, 0x5c, 0x5c, 0x44, 0x4f, 0x47, //Hive Name - string -> "SOFTWARE\\WOW\\TESTING\\DOG"
		0x00, // NULLBYTE
		0x00  // NULLBYTE
	};
	// Test - Case - Remove NullByte after HiveName
	uint8_t spCreateRegKeyClientPkt_NB_AfterHive[32] = {
		0x01, // Type
		0x03, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x53, 0x4f, 0x46, 0x54, 0x57, 0x41, 0x52, 0x45, 0x5c, 0x5c, 0x57, 0x4f, 0x57, 0x5c, 0x5c, 0x54, 0x45, 0x53, 0x54, 0x49, 0x4e, 0x47, 0x5c, 0x5c, 0x44, 0x4f, 0x47, //Hive Name - string -> "SOFTWARE\\WOW\\TESTING\\DOG"
		0x01, // Hive Type
		0x00  // NULLBYTE
	};
	// Test Case - Remove NullByte AFter Hive Type
	uint8_t spCreateRegKeyClientPkt_NB_AfterType[32] = {
		0x01, // Type
		0x03, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x53, 0x4f, 0x46, 0x54, 0x57, 0x41, 0x52, 0x45, 0x5c, 0x5c, 0x57, 0x4f, 0x57, 0x5c, 0x5c, 0x54, 0x45, 0x53, 0x54, 0x49, 0x4e, 0x47, 0x5c, 0x5c, 0x44, 0x4f, 0x47, //Hive Name - string -> "SOFTWARE\\WOW\\TESTING\\DOG"
		0x00, // NULLBYTE
		0x01, // Hive Type
	};
};

// Debug testing potentially malicious/malformed client packets to make sure the 
// Named Pipe Server can properly parse them without potential security issues appearing
// Challenge Testing -> DeleteFile 
struct debugDeleteFile {

	// General comment of all these different arrays (client packets) 
	// Length - Currently not supported within the Named Pipe Server - value can be anything as long as it is a "byte" (a.k.a uint8_t) client side in the packet

	uint8_t spDeleteFileClientPkt[25] = {
		0x01, // Type
		0x02, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x43, 0x3a, 0x5c, 0x5c, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x5c, 0x5c, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, // FILENAME TO DELETE - string -> "C:\\Windows\\test.txt"
		0x00  // NULLBYTE
	};
	// Test case Delete FILENAME value
	uint8_t spDeleteFileClientPkt_FileName[4] = {
		0x01, // Type
		0x02, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x00  // NULLBYTE
	};
	// Test case Delete NULL byte from packet
	uint8_t spDeleteFileClientPkt_NullByte[24] = {
		0x01, // Type
		0x02, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x43, 0x3a, 0x5c, 0x5c, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x5c, 0x5c, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, // FILENAME TO DELETE - string -> "C:\\Windows\\test.txt"
	};
};

// Debug testing potentially malicious/malformed client packets to make sure the 
// Named Pipe Server can properly parse them without potential security issues appearing
// Challenge Testing -> WriteFile
struct debugWriteFile {

	// General comment of all these different arrays (client packets) 
	// Length - Currently not supported within the Named Pipe Server - value can be anything as long as it is a "byte" (a.k.a uint8_t) client side in the packet

	uint8_t test[1] = { 0x99 };

	uint8_t spWriteFileClientPkt[37] = {
		0x01, // Type
		0x01, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x43, 0x3a, 0x5c, 0x5c, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x5c, 0x5c, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, // FILENAME TO WRITE/CREATE - string -> "C:\\Windows\\test.txt"
		0x00, // NULLBYTE
		0x41, 0x41, 0x41, 0x41, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, // DATA TO WRITE TO FILE - string -> "AAAABBBBBBB"
		0x00  // NULLBYTE
	};
	// Test - Remove First Null Byte after "FILENAME" field from client packet
	uint8_t spWriteFileClientPkt_nullbyte1[36] = {
		0x01, // Type
		0x01, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x43, 0x3a, 0x5c, 0x5c, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x5c, 0x5c, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, // FILENAME TO WRITE/CREATE - string -> "C:\\Windows\\test.txt"
		0x41, 0x41, 0x41, 0x41, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, // DATA TO WRITE TO FILE - string -> "AAAABBBBBBB"
		0x00  // NULLBYTE
	};
	// Test - Remove Second Null Byte after "DATA" field from client packet
	uint8_t spWriteFileClientPkt_nullbyte2[36] = {
		0x01, // Type
		0x01, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x43, 0x3a, 0x5c, 0x5c, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x5c, 0x5c, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, // FILENAME TO WRITE/CREATE - string -> "C:\\Windows\\test.txt"
		0x00, // NULLBYTE
		0x41, 0x41, 0x41, 0x41, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, // DATA TO WRITE TO FILE - string -> "AAAABBBBBBB"
	};
	// Test - Remove "FILENAME" field from client packet
	uint8_t spWriteFileClientPkt_Name[16] = {
		0x01, // Type
		0x01, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		// no name field.
		0x00, // NULLBYTE
		0x41, 0x41, 0x41, 0x41, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, // DATA TO WRITE TO FILE - string -> "AAAABBBBBBB"
		0x00  // NULLBYTE
	};
	// Test - Remove "DATA" field from client packet
	uint8_t spWriteFileClientPkt_Data[26] = {
		0x01, // Type
		0x01, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x43, 0x3a, 0x5c, 0x5c, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x5c, 0x5c, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, // FILENAME TO WRITE/CREATE - string -> "C:\\Windows\\test.txt"
		0x00, // NULLBYTE
		0x00  // NULLBYTE
	};
};

// Debug testing potentially malicious/malformed client packets to make sure the 
// Named Pipe Server can properly parse them without potential security issues appearing
// Structure is used during "Debug Mode" only 
struct debugChallengePacketFormat {
	uint8_t debugServerRespsonse = 0x0;
	uint8_t debugType = 0x0;
	uint8_t debugChallengeNumber = 0x0;
	uint8_t debugLength = 0x00;
	std::vector<uint8_t> debugData;
};


// Debug testing potentially malicious/malformed client packets to make sure the 
// Named Pipe Server can properly parse them without potential security issues appearing
// This Debug function is responsible for sending the "TEST" client packets to the Named Pipe Server
BOOL dbsendPkt(debugChallengePacketFormat* spClientPktFormat) {

	// Variables in relation to establishing a connection with the Named Pipe Server
	HANDLE spHandlePipe;
	DWORD spBytesWritten;
	BOOL spWriteFileResponse;

	std::cout << "\t[+] DEBUG:dbsendPkt() Establishing handle to named pipe!" << std::endl;
	spHandlePipe = CreateFile(TEXT("\\\\.\\pipe\\NinjaReally"),
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	std::cout << "\t[+] DEBUG:dbsendPkt() Checking if handle is valid or not!" << std::endl;
	if (spHandlePipe != INVALID_HANDLE_VALUE) {
		std::cout << "\t\t[+] DEBUG:dbsendPkt() Handle was successfully gained!" << std::endl;
		std::cout << "\t\t[+] DEBUG:dbsendPkt() Attempting to send data to the named pipe server!" << std::endl;
		spWriteFileResponse = WriteFile(spHandlePipe,
			&spClientPktFormat->debugData[0],
			(DWORD)spClientPktFormat->debugData.size(),
			&spBytesWritten,
			NULL);

		if (spWriteFileResponse != FALSE) {
			std::cout << "\t\t\t[!] DEBUG:dbsendPkt() Write Successful!" << std::endl;
			std::cout << "\t\t[+] DEBUG:dbsendPkt() Checking to ensure that the amount of bytes written during the \"WriteFile()\" function call match with what the client wanted" << std::endl;
			// After attempting to Write data to our file the first thing we check is to make sure that the amount of "DATA" written recorded inside of the "wfuint8_tsWritten" variable matches with the amount of bytes the client wanted to write.
			if (spBytesWritten < spClientPktFormat->debugData.size()) {
				std::cout << "\t\t\t[!] DEBUG:dbsendPkt() The amounts of bytes written do NOT match the amount the client specified" << std::endl;
				std::cout << "\t\t\t[!] DEBUG:dbsendPkt() Error -> Invalid amount of bytes were written" << std::endl;
				std::cout << "\t\t\t[!] DEBUG:dbsendPkt() Exiting client." << std::endl;
				CloseHandle(spHandlePipe);
				return FALSE;
			}
			else {
				std::cout << "\t\t\t[!] DEBUG:dbsendPkt() The amounts of bytes written do match the amount the client specified" << std::endl;
				std::cout << "\t\t\t[!] DEBUG:dbsendPkt() \"WriteFile()\" function call successfully executed" << std::endl;
				CloseHandle(spHandlePipe);
				return TRUE;
			}
		}
		else {
			std::cout << "\t\t[!] DEBUG:dbsendPkt() Write() failed!" << std::endl;
			std::cout << "\t\t[!] DEBUG:dbsendPkt() Exiting client.\n" << std::endl;
			CloseHandle(spHandlePipe);
			return FALSE;
		}
	}
	else {
		std::cout << "\t\t[!] DEBUG:dbsendPkt() Handle was NOT successfully gained!" << std::endl;
		std::cout << "\t\t[!] DEBUG:dbsendPkt() Exiting client.\n" << std::endl;
		return FALSE;
	}
}

// Debug testing potentially malicious/malformed client packets to make sure the 
// Named Pipe Server can properly parse them without potential security issues appearing
// This Debug function is responsible for checking and making sure that the client's vector is empty before trying to copy more data into its .data member
void debugVectorClear(debugChallengePacketFormat& vectorClearStruct) {
	if (vectorClearStruct.debugData.size() != 0) {
		std::cout << "\t[+] DEBUG: Elements have been found within Vector!" << std::endl;
		std::cout << "\t\t[!] DEBUG: Total elements -> " << vectorClearStruct.debugData.size() << std::endl;
		std::cout << "\t\t[!] DEBUG: Destroying all elements." << std::endl;
		vectorClearStruct.debugData.clear();
		std::cout << "\t[+] DEBUG: Total elements -> " << vectorClearStruct.debugData.size() << std::endl;
		std::cout << "\t[+] DEBUG: Continuing execution." << std::endl;
		return;
	}
	return;
}

// Debug testing potentially malicious/malformed client packets to make sure the 
// Named Pipe Server can properly parse them without potential security issues appearing
// This Debug function is responsible for displaying packet information 
void debugPacketInfo(debugChallengePacketFormat& vectorPacketInfoStruct) {
	std::cout << "\t[+] DEBUG: Packet Information: " << std::endl;
	std::cout << "\t\t[!] ClientPkt Type -> " << (unsigned)vectorPacketInfoStruct.debugType << std::endl;
	std::cout << "\t\t[!] ClientPkt Challenge Number -> " << (unsigned)vectorPacketInfoStruct.debugChallengeNumber << std::endl;
	std::cout << "\t\t[!] ClientPkt Number of Elements in Vector -> " << vectorPacketInfoStruct.debugData.size() << std::endl;
	return;
}

// Debug testing potentially malicious/malformed client packets to make sure the 
// Named Pipe Server can properly parse them without potential security issues appearing
// This Debug function is responsible for 
BOOL dbcreatePkt(uint8_t packetType) {
	// Return value status from "sendPkt()" function.
	BOOL dbcpSendPktResponse = FALSE;

	// These structures hold the specific client packets to iterate over 
	debugChallengePacketFormat dbcpClientPktStruct;
	debugRegistryKey dbcpRegistryKey;
	debugRegistryKeyEntry dbcpRegistryKeyEntry;
	debugDeleteFile dbcpDeleteFile;
	debugWriteFile dbcpWriteFile;

	// These are all total sizes of each member within dbcpRegistryKeyEntry_NormalPkt structure 
	// These values are used as the "iterator" values during the vector.insert() member function call
	unsigned dbcpRegistryKeyEntry_NormalPkt = sizeof(dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt) / sizeof(uint8_t);
	unsigned dbcpRegistryKeyEntry_Remove_HiveName = sizeof(dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_HiveName) / sizeof(uint8_t);
	unsigned dbcpRegistryKeyEntry_NullByte_AfterHiveName = sizeof(dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_NB_HiveName) / sizeof(uint8_t);
	unsigned dbcpRegistryKeyEntry_Remove_HiveType = sizeof(dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_HiveType) / sizeof(uint8_t);
	unsigned dbcpRegistryKeyEntry_NullByte_AfterHiveType = sizeof(dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_NB_HiveType) / sizeof(uint8_t);
	unsigned dbcpRegistryKeyEntry_Remove_RegistryType = sizeof(dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_RegistryType) / sizeof(uint8_t);
	unsigned dbcpRegistryKeyEntry_NullByte_AfterRegistryType = sizeof(dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_NB_RegistryType) / sizeof(uint8_t);
	unsigned dbcpRegistryKeyEntry_Remove_RegistryName = sizeof(dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_RegistryKeyName) / sizeof(uint8_t);
	unsigned dbcpRegistryKeyEntry_NullByte_AfterRegistryName = sizeof(dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_NB_RegistryKeyName) / sizeof(uint8_t);
	unsigned dbcpRegistryKeyEntry_Remove_RegistryValue = sizeof(dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_RegistryKeyValue) / sizeof(uint8_t);
	unsigned dbcpRegistryKeyEntry_NullByte_AfterRegistryValue = sizeof(dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_NB_RegistryKeyValue) / sizeof(uint8_t);

	// These are all total sizes of each member within dbcpRegistryKey structure 
	// These values are used as the "iterator" values during the vector.insert() member function call
	unsigned dbcpRegistryKey_NormalPkt = sizeof(dbcpRegistryKey.spCreateRegKeyClientPkt) / sizeof(uint8_t);
	unsigned dbcpRegistryKey_Remove_HiveName = sizeof(dbcpRegistryKey.spCreateRegKeyClientPkt_HiveName) / sizeof(uint8_t);
	unsigned dbcpRegistryKey_Remove_HiveType = sizeof(dbcpRegistryKey.spCreateRegKeyClientPkt_HiveType) / sizeof(uint8_t);
	unsigned dbcpRegistryKey_NullByte_AfterHive = sizeof(dbcpRegistryKey.spCreateRegKeyClientPkt_NB_AfterHive) / sizeof(uint8_t);
	unsigned dbcpRegistryKey_NUllByte_AfterType = sizeof(dbcpRegistryKey.spCreateRegKeyClientPkt_NB_AfterType) / sizeof(uint8_t);

	// These are all total sizes of each member within dbcpDeleteFile structure 
	// These values are used as the "iterator" values during the vector.insert() member function call
	unsigned dbcpDeleteFile_NormalPkt = sizeof(dbcpDeleteFile.spDeleteFileClientPkt) / sizeof(uint8_t);
	unsigned dbcpDeleteFile_Remove_Filename = sizeof(dbcpDeleteFile.spDeleteFileClientPkt_FileName) / sizeof(uint8_t);
	unsigned dbcpDeleteFile_NullByte = sizeof(dbcpDeleteFile.spDeleteFileClientPkt_NullByte) / sizeof(uint8_t);

	// These are all total sizes of each member within dbcpWriteFile structure 
	// These values are used as the "iterator" values during the vector.insert() member function call
	unsigned dbcpWriteFile_test = sizeof(dbcpWriteFile.test) / sizeof(uint8_t);
	unsigned dbcpWriteFile_NormalPkt = sizeof(dbcpWriteFile.spWriteFileClientPkt) / sizeof(uint8_t);
	unsigned dbcpWriteFile_NullByte_1 = sizeof(dbcpWriteFile.spWriteFileClientPkt_nullbyte1) / sizeof(uint8_t);
	unsigned dbcpWriteFile_NullByte_2 = sizeof(dbcpWriteFile.spWriteFileClientPkt_nullbyte2) / sizeof(uint8_t);
	unsigned dbcpWriteFile_Remove_Filename = sizeof(dbcpWriteFile.spWriteFileClientPkt_Name) / sizeof(uint8_t);
	unsigned dbcpWriteFile_Remove_Data = sizeof(dbcpWriteFile.spWriteFileClientPkt_Data) / sizeof(uint8_t);


	std::cout << "\n\t[+] DEBUG: WriteFile - \"enable TESTING\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x99;
	dbcpClientPktStruct.debugChallengeNumber = 0x99;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpWriteFile.test[0], &dbcpWriteFile.test[dbcpWriteFile_test]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\n\t[+] DEBUG: WriteFile - \"spWriteFileClientPkt\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x1;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpWriteFile.spWriteFileClientPkt[0], &dbcpWriteFile.spWriteFileClientPkt[dbcpWriteFile_NormalPkt]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\n\t[+] DEBUG: WriteFile - \"spWriteFileClientPkt_nullbyte1\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x1;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpWriteFile.spWriteFileClientPkt_nullbyte1[0], &dbcpWriteFile.spWriteFileClientPkt_nullbyte1[dbcpWriteFile_NullByte_1]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\n\t[+] DEBUG: WriteFile - \"spWriteFileClientPkt_nullbyte2\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x1;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpWriteFile.spWriteFileClientPkt_nullbyte2[0], &dbcpWriteFile.spWriteFileClientPkt_nullbyte2[dbcpWriteFile_NullByte_2]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\n\t[+] DEBUG: WriteFile - \"spWriteFileClientPkt_Name\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x1;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpWriteFile.spWriteFileClientPkt_Name[0], &dbcpWriteFile.spWriteFileClientPkt_Name[dbcpWriteFile_Remove_Filename]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\n\t[+] DEBUG: WriteFile - \"spWriteFileClientPkt_Name\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x1;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpWriteFile.spWriteFileClientPkt_Data[0], &dbcpWriteFile.spWriteFileClientPkt_Data[dbcpWriteFile_Remove_Data]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\n\t[+] DEBUG: DeleteFile - \"spDeleteFileClientPkt\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x2;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpDeleteFile.spDeleteFileClientPkt[0], &dbcpDeleteFile.spDeleteFileClientPkt[dbcpDeleteFile_NormalPkt]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\n\t[+] DEBUG: DeleteFile - \"spDeleteFileClientPkt_FileName\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x2;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpDeleteFile.spDeleteFileClientPkt_FileName[0], &dbcpDeleteFile.spDeleteFileClientPkt_FileName[dbcpDeleteFile_Remove_Filename]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\n\t[+] DEBUG: DeleteFile - \"spDeleteFileClientPkt_NullByte\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x2;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpDeleteFile.spDeleteFileClientPkt_NullByte[0], &dbcpDeleteFile.spDeleteFileClientPkt_NullByte[dbcpDeleteFile_NullByte]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\n\t[+] DEBUG: CreateRegKey - \"spCreateRegKeyClientPkt\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x3;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpRegistryKey.spCreateRegKeyClientPkt[0], &dbcpRegistryKey.spCreateRegKeyClientPkt[dbcpRegistryKey_NormalPkt]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\n\t[+] DEBUG: CreateRegKey - \"spCreateRegKeyClientPkt_HiveName\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x3;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpRegistryKey.spCreateRegKeyClientPkt_HiveName[0], &dbcpRegistryKey.spCreateRegKeyClientPkt_HiveName[dbcpRegistryKey_Remove_HiveName]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\n\t[+] DEBUG: CreateRegKey - \"spCreateRegKeyClientPkt_HiveType\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x3;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpRegistryKey.spCreateRegKeyClientPkt_HiveType[0], &dbcpRegistryKey.spCreateRegKeyClientPkt_HiveType[dbcpRegistryKey_Remove_HiveType]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\n\t[+] DEBUG: CreateRegKey - \"spCreateRegKeyClientPkt_NB_AfterHive\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x3;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpRegistryKey.spCreateRegKeyClientPkt_NB_AfterHive[0], &dbcpRegistryKey.spCreateRegKeyClientPkt_NB_AfterHive[dbcpRegistryKey_NullByte_AfterHive]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\n\t[+] DEBUG: CreateRegKey - \"spCreateRegKeyClientPkt_NB_AfterType\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG:To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x3;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpRegistryKey.spCreateRegKeyClientPkt_NB_AfterType[0], &dbcpRegistryKey.spCreateRegKeyClientPkt_NB_AfterType[dbcpRegistryKey_NUllByte_AfterType]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\n\t[+] DEBUG: CreateRegKeyEntry - \"spCreateRegKeyEntryClientPkt\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG :To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x4;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt[0], &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt[dbcpRegistryKeyEntry_NormalPkt]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\t[+] DEBUG: CreateRegKeyEntry - \"spCreateRegKeyEntryClientPkt_HiveName\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x4;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_HiveName[0], &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_HiveName[dbcpRegistryKeyEntry_Remove_HiveName]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\t[+] DEBUG: CreateRegKeyEntry - \"spCreateRegKeyEntryClientPkt_NB_HiveName\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x4;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_NB_HiveName[0], &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_NB_HiveName[dbcpRegistryKeyEntry_NullByte_AfterHiveName]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\t[+] DEBUG: CreateRegKeyEntry - \"spCreateRegKeyEntryClientPkt_HiveType\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x4;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_HiveType[0], &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_HiveType[dbcpRegistryKeyEntry_Remove_HiveType]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\t[+] DEBUG: CreateRegKeyEntry - \"spCreateRegKeyEntryClientPkt_NB_HiveType\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x4;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_NB_HiveType[0], &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_NB_HiveType[dbcpRegistryKeyEntry_NullByte_AfterHiveType]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\t[+] DEBUG: CreateRegKeyEntry - \"spCreateRegKeyEntryClientPkt_RegistryType\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x4;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_RegistryType[0], &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_RegistryType[dbcpRegistryKeyEntry_Remove_RegistryType]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\t[+] DEBUG: CreateRegKeyEntry - \"spCreateRegKeyEntryClientPkt_NB_RegistryType\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x4;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_NB_RegistryType[0], &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_NB_RegistryType[dbcpRegistryKeyEntry_NullByte_AfterRegistryType]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\t[+] DEBUG: CreateRegKeyEntry - \"spCreateRegKeyEntryClientPkt_RegistryKeyName\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x4;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_RegistryKeyName[0], &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_RegistryKeyName[dbcpRegistryKeyEntry_Remove_RegistryName]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\t[+] DEBUG: CreateRegKeyEntry - \"spCreateRegKeyEntryClientPkt_NB_RegistryKeyName\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x4;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_NB_RegistryKeyName[0], &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_NB_RegistryKeyName[dbcpRegistryKeyEntry_NullByte_AfterRegistryName]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\t[+] DEBUG: CreateRegKeyEntry - \"spCreateRegKeyEntryClientPkt_RegistryKeyValue\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x4;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_RegistryKeyValue[0], &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_RegistryKeyValue[dbcpRegistryKeyEntry_Remove_RegistryValue]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	std::cout << "\t[+] DEBUG: CreateRegKeyEntry - \"spCreateRegKeyEntryClientPkt_NB_RegistryKeyValue\" test case." << std::endl;
	std::cout << "\t\t[!] DEBUG: To continue automated testing hit enter." << std::endl;
	system("pause");
	debugVectorClear(dbcpClientPktStruct);
	dbcpClientPktStruct.debugType = 0x01;
	dbcpClientPktStruct.debugChallengeNumber = 0x4;
	dbcpClientPktStruct.debugData.insert(dbcpClientPktStruct.debugData.end(), &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_NB_RegistryKeyValue[0], &dbcpRegistryKeyEntry.spCreateRegKeyEntryClientPkt_NB_RegistryKeyValue[dbcpRegistryKeyEntry_NullByte_AfterRegistryValue]);
	debugPacketInfo(dbcpClientPktStruct);
	dbsendPkt(&dbcpClientPktStruct);

	return TRUE;
}


// This function is responsible for displaying packet information 
void PacketInfo(ChallengePacketFormat& vectorPacketInfoStruct) {
	std::cout << "[+] Client: Packet Information: " << std::endl;
	std::cout << "\t[!] ClientPkt Type -> " << (unsigned)vectorPacketInfoStruct.cpfType << std::endl;
	std::cout << "\t[!] ClientPkt Challenge Number -> " << (unsigned)vectorPacketInfoStruct.cpfChallengeNumber << std::endl;
	std::cout << "\t[!] ClientPkt Number of Elements in Vector -> " << vectorPacketInfoStruct.cpfData.size() << std::endl;
	return;
}

// This  function is responsible for checking and making sure that the client's vector is empty before trying to copy more data into its .data member
void VectorClear(ChallengePacketFormat& vectorClearStruct) {
	if (vectorClearStruct.cpfData.size() != 0) {
		std::cout << "[+] Client Elements have been found within Vector!" << std::endl;
		std::cout << "\t[!] Client Total elements -> " << vectorClearStruct.cpfData.size() << std::endl;
		std::cout << "\t[!] Client Destroying all elements." << std::endl;
		vectorClearStruct.cpfData.clear();
		std::cout << "\t[!] Client Total elements -> " << vectorClearStruct.cpfData.size() << std::endl;
		std::cout << "\t[!] Client Continuing execution." << std::endl;
		return;
	}
	return;
}

uint8_t sendPkt(ChallengePacketFormat* spClientPktFormat) {
	// These variables are used for creation of a "HANDLE" to a named pipe object and also for attempting to "WRITE" data to the pipe using "WriteFile()"
	HANDLE spHandlePipe = INVALID_HANDLE_VALUE;
	DWORD spBytesWritten = 0;
	BOOL spWriteFileResponse = FALSE;

	std::cout << "\t[!] Client: Establishing handle to named pipe!" << std::endl;
	spHandlePipe = CreateFile(TEXT("\\\\.\\pipe\\NinjaReally"),
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	std::cout << "\t[!] Client: Checking if handle is valid or not!" << std::endl;
	if (spHandlePipe != INVALID_HANDLE_VALUE) {
		std::cout << "\t\t[!] Client: Handle was successfully gained!" << std::endl;
		std::cout << "[+] Client: Attempting to send data to the named pipe server!" << std::endl;
		spWriteFileResponse = WriteFile(spHandlePipe,
			&spClientPktFormat->cpfData[0],
			(DWORD)spClientPktFormat->cpfData.size(),  // = length of byte array
			&spBytesWritten,
			NULL);
		if (spWriteFileResponse != FALSE) {
			std::cout << "\t[!] Client: Write Successful!" << std::endl;
			std::cout << "[+] Client: Checking to ensure that the amount of bytes written during the \"WriteFile()\" function call match with what the client wanted" << std::endl;
			// After attempting to Write data to our file the first thing we check is to make sure that the amount of "DATA" written recorded inside of the "wfuint8_tsWritten" variable matches with the amount of bytes the client wanted to write.
			if (spBytesWritten < spClientPktFormat->cpfData.size()) {
				std::cout << "\t[!] Client: The amounts of bytes written do NOT match the amount the client specified" << std::endl;
				std::cout << "\t[!] Client: Error -> Invalid amount of bytes were written" << std::endl;
				std::cout << "\t[!] Client: Exiting client." << std::endl;
				CloseHandle(spHandlePipe);
				return FALSE;
			}
			else {
				std::cout << "\t[!] Client: The amounts of bytes written do match the amount the client specified" << std::endl;
				std::cout << "\t[!] Client: \"WriteFile()\" function call successfully executed" << std::endl;
				CloseHandle(spHandlePipe);
				return TRUE;
			}
		}
		else {
			std::cout << "\t[!] Client: WriteFile() failed!" << std::endl;
			std::cout << "\t[!] Client: Exiting client.\n" << std::endl;
			return FALSE;
		}
	}
	else {
		std::cout << "\t[!] Client: Handle was NOT successfully gained!" << std::endl;
		std::cout << "\t[!] Client: Exiting client.\n" << std::endl;
		return FALSE;
	}
}

BOOL createPkt(uint8_t packetType) {
	// Return value status from "sendPkt()" function.
	BOOL spSendPktResponse = FALSE;

	// Create local version for "ChallengePacketFormat" structure
	ChallengePacketFormat spClientPktStruct;

	// Create Potential Switch case statement - cases
	const uint8_t spWriteFileChallenge = 0x1;
	const uint8_t spDeleteFileChallenge = 0x2;
	const uint8_t spCreateRegKeyChallenge = 0x3;
	const uint8_t spCreateRegKeyEntryChallenge = 0x4;
	const uint8_t spStackBasedVulnerabilityChallenge1 = 0x5;
	const uint8_t spStackBasedVulnerabilityChallenge2 = 0x6;
	const uint8_t spStackBasedVulnerabilityChallenge3 = 0x7;
	const uint8_t spStackBasedVulnerabilityChallenge4 = 0x8;

	// Create data array for each type of challenge packet.
	uint8_t spWriteFileClientPkt[37] = {
		0x01, // Type
		0x01, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x43, 0x3a, 0x5c, 0x5c, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x5c, 0x5c, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, // FILENAME TO WRITE/CREATE - string -> "C:\\Windows\\test.txt"
		0x00, // NULLBYTE
		0x41, 0x41, 0x41, 0x41, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, // DATA TO WRITE TO FILE string -> "AAAABBBBBBB"
		0x00  // NULLBYTE
	};
	uint8_t spDeleteFileClientPkt[25] = {
		0x01, // Type
		0x02, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x43, 0x3a, 0x5c, 0x5c, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x5c, 0x5c, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, // FILENAME TO DELETE - string -> "C:\\Windows\\test.txt"
		0x00  // NULLBYTE
	};
	uint8_t spCreateRegKeyClientPkt[33] = {
		0x01, // Type
		0x03, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x53, 0x4f, 0x46, 0x54, 0x57, 0x41, 0x52, 0x45, 0x5c, 0x5c, 0x57, 0x4f, 0x57, 0x5c, 0x5c, 0x54, 0x45, 0x53, 0x54, 0x49, 0x4e, 0x47, 0x5c, 0x5c, 0x44, 0x4f, 0x47, //Hive Name - string -> "SOFTWARE\\WOW\\TESTING\\DOG"
		0x00, // NULLBYTE
		0x01, // Hive Type
		0x00  // NULLBYTE
	};
	uint8_t spCreateRegKeyEntryClientPkt[51] = {
		0x01, // Type
		0x04, // Challenge Number
		0x11, // Length
		// Breaking down actual data thats parsed (VALUE section of Field)
		0x53, 0x4f, 0x46, 0x54, 0x57, 0x41, 0x52, 0x45, 0x5c, 0x5c, 0x57, 0x4f, 0x57, 0x5c, 0x5c, 0x54, 0x45, 0x53, 0x54, 0x49, 0x4e, 0x47, 0x5c, 0x5c, 0x44, 0x4f, 0x47, //Hive Name - string -> "SOFTWARE\\WOW\\TESTING\\DOG"
		0x00, // NULLBYTE
		0x01, // Type of Hive to utilize
		0x00, // NULLBYTE
		0x01, // Type of Registry Value
		0x00, // NULLBYTE
		0x57,0x6f ,0x57 ,0x5a ,0x61 ,0x68, // Registry Key Entry Name - string -> "WoWZah"
		0x00, // NULLBYTE
		0x41, 0x41, 0x41, 0x43, 0x45, 0x45, 0x42, 0x43, // Registry Key Value - string -> "AAACEEBC"
		0x00 // NULLBYTE
	};

	// These are all total sizes of each member within the four different client packet arrays
	unsigned spWriteFileClientPkt_normal = (sizeof(spWriteFileClientPkt) / sizeof(uint8_t));
	unsigned spDeleteFileClientPkt_normal = sizeof(spDeleteFileClientPkt) / sizeof(uint8_t);
	unsigned spCreateRegKeyClientPkt_normal = sizeof(spCreateRegKeyClientPkt) / sizeof(uint8_t);
	unsigned spCreateRegKeyEntryClientPkt_normal = sizeof(spCreateRegKeyEntryClientPkt) / sizeof(uint8_t);

	// Create switch statement
	switch (packetType) {

	case spWriteFileChallenge:
		// Populate our ChallengePacketFormat.
		VectorClear(spClientPktStruct);
		spClientPktStruct.cpfType = 0x01;
		spClientPktStruct.cpfChallengeNumber = packetType;
		spClientPktStruct.cpfData.insert(spClientPktStruct.cpfData.end(), &spWriteFileClientPkt[0], &spWriteFileClientPkt[spWriteFileClientPkt_normal]);
		PacketInfo(spClientPktStruct);
		std::cout << "[+] Client: Attempting to gain a handle the named pipe!" << std::endl;
		// Record success or failure from "sendPkt()" (True or False)
		spSendPktResponse = sendPkt(&spClientPktStruct);
		break;
	case spDeleteFileChallenge:
		// Populate our ChallengePacketFormat.
		VectorClear(spClientPktStruct);
		spClientPktStruct.cpfType = 0x01;
		spClientPktStruct.cpfChallengeNumber = packetType;
		spClientPktStruct.cpfData.insert(spClientPktStruct.cpfData.end(), &spDeleteFileClientPkt[0], &spDeleteFileClientPkt[spDeleteFileClientPkt_normal]);
		PacketInfo(spClientPktStruct);
		std::cout << "[+] Client: Attempting to gain a handle the named pipe!" << std::endl;
		// Record success or failure from "sendPkt()" (True or False)
		spSendPktResponse = sendPkt(&spClientPktStruct);
		break;
	case spCreateRegKeyChallenge:
		// Populate our ChallengePacketFormat.
		VectorClear(spClientPktStruct);
		spClientPktStruct.cpfType = 0x01;
		spClientPktStruct.cpfChallengeNumber = packetType;
		spClientPktStruct.cpfData.insert(spClientPktStruct.cpfData.end(), &spCreateRegKeyClientPkt[0], &spCreateRegKeyClientPkt[spCreateRegKeyClientPkt_normal]);
		PacketInfo(spClientPktStruct);
		std::cout << "[+] Client: Attempting to gain a handle the named pipe!" << std::endl;
		// Record success or failure from "sendPkt()" (True or False)
		spSendPktResponse = sendPkt(&spClientPktStruct);
		break;
	case spCreateRegKeyEntryChallenge:
		// Populate our ChallengePacketFormat.
		VectorClear(spClientPktStruct);
		spClientPktStruct.cpfType = 0x01;
		spClientPktStruct.cpfChallengeNumber = packetType;
		spClientPktStruct.cpfData.insert(spClientPktStruct.cpfData.end(), &spCreateRegKeyEntryClientPkt[0], &spCreateRegKeyEntryClientPkt[spCreateRegKeyEntryClientPkt_normal]);
		std::cout << "[+] Client: Attempting to gain a handle the named pipe!" << std::endl;
		// Record success or failure from "sendPkt()" (True or False)
		spSendPktResponse = sendPkt(&spClientPktStruct);
		break;
	case spStackBasedVulnerabilityChallenge1:
		std::cout << "\t[!] Client: Challenge not currently supported." << std::endl;
		std::cout << "\t[!] Client: Exiting Client now." << std::endl;
		spSendPktResponse = TRUE;
		break;
	case spStackBasedVulnerabilityChallenge2:
		std::cout << "\t[!] Client: Challenge not currently supported." << std::endl;
		std::cout << "\t[!] Client: Exiting Client now." << std::endl;
		spSendPktResponse = TRUE;
		break;
	case spStackBasedVulnerabilityChallenge3:
		std::cout << "\t[!] Client: Challenge not currently supported." << std::endl;
		std::cout << "\t[!] Client: Exiting Client now." << std::endl;
		spSendPktResponse = TRUE;
		break;
	case spStackBasedVulnerabilityChallenge4:
		std::cout << "\t[!] Client: Challenge not currently supported." << std::endl;
		std::cout << "\t[!] Client: Exiting Client now." << std::endl;
		spSendPktResponse = TRUE;
		break;
	}

	// This check is to operate on the return value from the "sendPkt()" function -- each potential challenge case inside of the main switch "spWriteFileChallenge" will return either 
	// TRUE for success 
	// FALSE for failure
	// To the main() function
	if (spSendPktResponse) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

int main(int argc, char* argv[])
{
	// This is the return value from "createPkt()" function 
	BOOL createPktResponse = FALSE;

	// Define switch case constants
	const uint8_t writeFileChallenge = 0x1;
	const uint8_t deleteFileChallenge = 0x2;
	const uint8_t createRegKeyChallenge = 0x3;
	const uint8_t createRegKeyEntryChallenge = 0x4;
	const uint8_t stackBasedVulnerabilityChallenge1 = 0x5;
	const uint8_t stackBasedVulnerabilityChallenge2 = 0x6;
	const uint8_t stackBasedVulnerabilityChallenge3 = 0x7;
	const uint8_t stackBasedVulnerabilityChallenge4 = 0x8;

	// Debug case - (int)99
	const uint8_t debugCase = 0x63;
	BOOL debugCasePktResponse = FALSE;


	std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << std::endl;
	std::cout << R"(
____   ____            _________            .__  __          
\   \ /   /___________/   _____/____________|__|/  |_  ____  
 \   Y   // __ \_  __ \_____  \\____ \_  __ \  \   __\/ __ \ 
  \     /\  ___/|  | \/        \  |_> >  | \/  ||  | \  ___/ 
   \___/  \___  >__| /_______  /   __/|__|  |__||__|  \___  >
              \/             \/|__|                       \/ 
)" << std::endl;
	std::cout << "\n" << "[+] VULNERABLE NAMED PIPE CLIENT" << std::endl;
	std::cout << "[+] Packet Types Supported: " << std::endl;
	std::cout << "\t[!]Logic Vulnerabilities." << std::endl;
	std::cout << "\t\t[+] 1: Vulnerable File Write" << std::endl;
	std::cout << "\t\t[+] 2: Vulnerable File Deletion" << std::endl;
	std::cout << "\t\t[+] 3: Vulnerable Registry Key Modification" << std::endl;
	std::cout << "\t\t[+] 4: Vulnerable Registry Key Entry Modification" << std::endl;
	std::cout << "[+] Packet Types Not Supported: " << std::endl;
	std::cout << "\t[!] Memory Corruption Vulnerabilities." << std::endl;
	std::cout << "\t\t[+] 5: Stack based Vulnerability" << std::endl;
	std::cout << "\t\t[+] 6: Stack based Vulnerability" << std::endl;
	std::cout << "\t\t[+] 7: Stack based Vulnerability" << std::endl;
	std::cout << "\t\t[+] 8: Stack based Vulnerability" << "\n" << std::endl;
	std::cout << "[+] Authors: Robert Hawes" << "\n" << "[+] Twitter: @VulnMind" << "\n" << "[+] VerSprite: VS-Labs Research Team" << "\n" << std::endl;
	std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << std::endl;

	// check and make user provided argument
	if (argc != 2) {
		std::cerr << "\t[+] Client: Error detected -> Invalid number of arguments provided!" << std::endl;
		std::cerr << "\t[+] Client:\n\t\t[!] Usage: <insert number 1-8>" << std::endl;
		return EXIT_FAILURE;
	}

	// use std::stoi to convert the string at index 1 of "argv" into an "int"
	uint8_t clientArg = std::stoi(argv[1]);

	// Switch case operating on type of "Packet Type" to send.
	std::cout << "\n[+] Client: Detecting type of packet to send." << std::endl;

	switch (clientArg) {
		// Debug CASE
	case debugCase:
		std::cout << "\n[+] DEBUG: Packet Testing detected." << std::endl;
		std::cout << "[+] DEBUG: Starting execution to send all potential \"TEST\" packets to named pipe server." << std::endl;
		createPktResponse = dbcreatePkt(debugCase);
		break;

		// LOGIC CASES
	case writeFileChallenge:
		std::cout << "\n[+] Client: WriteFile Packet type detected." << std::endl;
		std::cout << "\t[!] Client: Building packet to trigger WriteFile challenge!" << std::endl;
		createPktResponse = createPkt(writeFileChallenge);
		break;
	case deleteFileChallenge:
		std::cout << "\n[+] Client: DeleteFile Packet type detected." << std::endl;
		std::cout << "\t[!] Client: Building packet to trigger DeleteFile challenge!" << std::endl;
		createPktResponse = createPkt(deleteFileChallenge);
		break;
	case createRegKeyChallenge:
		std::cout << "\n[+] Client: CreateRegKey Packet type detected." << std::endl;
		std::cout << "\t[!] Client: Building packet to trigger CreateRegKey challenge!" << std::endl;
		createPktResponse = createPkt(createRegKeyChallenge);
		break;
	case createRegKeyEntryChallenge:
		std::cout << "\n[+] Client: CreateRegKeyEntry Packet type detected." << std::endl;
		std::cout << "\t[!] Client: Building packet to trigger CreateRegKeyEntry challenge!" << std::endl;
		createPktResponse = createPkt(createRegKeyEntryChallenge);
		break;

		// MEMORY CORRUPTION CASES
	case stackBasedVulnerabilityChallenge1:
		std::cout << "\n[+] Client: Stack Based Vulnerability 1 Packet type detected." << std::endl;
		std::cout << "\t[!] Client: Challenge not yet implemented." << std::endl;
		std::cout << "\t[!] Client: Exiting Program!" << std::endl;
		break;
	case stackBasedVulnerabilityChallenge2:
		std::cout << "\n[+] Client: Stack Based Vulnerability 2 Packet type detected." << std::endl;
		std::cout << "\t[!] Client: Challenge not yet implemented." << std::endl;
		std::cout << "\t[!] Client: Exiting Program!" << std::endl;
		break;
	case stackBasedVulnerabilityChallenge3:
		std::cout << "\n[+] Client: Stack Based Vulnerability 3 Packet type detected." << std::endl;
		std::cout << "\t[!] Client: Challenge not yet implemented." << std::endl;
		std::cout << "\t[!] Client: Exiting Program!" << std::endl;
		break;
	case stackBasedVulnerabilityChallenge4:
		std::cout << "\n[+] Client: Stack Based Vulnerability 4 Packet type detected." << std::endl;
		std::cout << "\t[!] Client: Challenge not yet implemented." << std::endl;
		std::cout << "\t[!] Client: Exiting Program!" << std::endl;
		break;


	default:
		std::cout << "\n[+] Client: Error." << std::endl;
		std::cout << "\t[!] Client: Unknown command passed via command line!" << std::endl;
		std::cout << "\t\t[!] Client: Exiting Program!" << std::endl;
	}

	// check return value from "createPkt()" function.
	if (!createPktResponse) {
		std::cerr << "[+] Client: Unknown Error." << std::endl;
		std::cerr << "[+] Client: GetLastError(): " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}
	else {
		std::cout << "[+] Client: Done!" << std::endl;
		return EXIT_SUCCESS;
	}
}