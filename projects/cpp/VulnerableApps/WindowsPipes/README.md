# Research
## Exploits
### CPP
#### VulnerableApps
##### WindowsPipes

This project is centered around abusing Windows Named Pipes. VS-Labs Research Team created this vulnerable application to help demonstrate common vulnerabilities that they have discovered while auditing Named Pipe Server implementations.

This project is also to be accompanied by the Blog Post here: https://versprite.com/blog/security-research/microsoft-windows-pipes-intro/

#### Example Usage

Server :
C:\Users\TESTER\Desktop>VS-Labs_NamedPipeServer.exe
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

____   ____            _________            .__  __
\   \ /   /___________/   _____/____________|__|/  |_  ____
 \   Y   // __ \_  __ \_____  \\____ \_  __ \  \   __\/ __ \
  \     /\  ___/|  | \/        \  |_> >  | \/  ||  | \  ___/
   \___/  \___  >__| /_______  /   __/|__|  |__||__|  \___  >
              \/             \/|__|                       \/


[+] VULNERABLE NAMED PIPE SERVER
[+] Challenges Supported:
        [!] Logic Vulnerabilities.
                [+] 1: Vulnerable File Write
                [+] 2: Vulnerable File Deletion
                [+] 3: Vulnerable Registry Key Modification
                [+] 4: Vulnerable Registry Key Entry Modification
        [!] Memory Corruption Vulnerabilities.
                [+] Currently Not Implemented.

[+] Authors: Robert Hawes
[+] Twitter: @VulnMind
[+] VerSprite: VS-Labs Research Team

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[+] Server: Running the named pipe server now.

[+] Server: Creating Named Pipe Server now!
        [!] Name: NinjaReally

[+] Server: Checking if handle was successfully gained!

Client :

C:\Users\TESTER\Desktop>VS-LabsNamedPipeClient.exe
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

____   ____            _________            .__  __
\   \ /   /___________/   _____/____________|__|/  |_  ____
 \   Y   // __ \_  __ \_____  \\____ \_  __ \  \   __\/ __ \
  \     /\  ___/|  | \/        \  |_> >  | \/  ||  | \  ___/
   \___/  \___  >__| /_______  /   __/|__|  |__||__|  \___  >
              \/             \/|__|                       \/


[+] VULNERABLE NAMED PIPE CLIENT
[+] Packet Types Supported:
        [!]Logic Vulnerabilities.
                [+] 1: Vulnerable File Write
                [+] 2: Vulnerable File Deletion
                [+] 3: Vulnerable Registry Key Modification
                [+] 4: Vulnerable Registry Key Entry Modification
[+] Packet Types Not Supported:
        [!] Memory Corruption Vulnerabilities.
                [+] 5: Stack based Vulnerability
                [+] 6: Stack based Vulnerability
                [+] 7: Stack based Vulnerability
                [+] 8: Stack based Vulnerability

[+] Authors: Robert Hawes
[+] Twitter: @VulnMind
[+] VerSprite: VS-Labs Research Team

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        [+] Client: Error detected -> Invalid number of arguments provided!
        [+] Client:
                [!] Usage: <insert number 1-8>


#### Server

The server code should be started from within an elevated command prompt sessions (Administrator). 
The server code accepts zero command line argument when being executed.

#### Client

The client code is fine for being executed form within a non-elevated (user) command prompt session.
The client can accept one argument. This single argument for the client is either 1-4 or 99. 

The options 1-4 signal potential to create the associate logic challenge packets to send the server.
The option 99 is to trigger debug mode and send a continuous stream of potential edge cases.

## Disclaimer 

This code is purely example code and should not be accepted as secure by any means. The current state of this projects protocol parsing server side is NOT secure. 

When deploying these example applications, the proper deployment should happen within a Virtual Environment.

