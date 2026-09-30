The OS Fingerprint project is a University project a part of a workshop in computer networks where each student was tasked to build a large networks related project. 

The programs task is to identify the operating system of a distant host using network protocols. The indetification is implemented using custom raw sockets of TCP, ICMP and UDP protocols. 
The sent packets are filled with special, irregular headers, data and destination ports which test the operating system's handling and response. 
The program analyzes the reponses from the target machine, calculates specific tests and then crafts a unique fingerprint. This fingerprint is then compared 
to an existing large database of operating system-fingerprint entries to find the operating system which fingerprint is most similar to the calculated fingerprint.
The program outputs the 10 most probable operating systems for the specified ip address.
