Command-and-Control-C2-Simulator-for-Red-Teaming-Objective
Project Overview This repository contains a Python-based Command and Control (C2) framework designed for authorized red team operations and security research. The system enables secure, encrypted communication between a C2 server and one or more remote agents. The communication uses AES-CBC encryption, and the framework allows remote shell command execution and result retrieval in real time.

Features AES-CBC Encrypted Communication: All traffic between server and agent is encrypted with a 256-bit key. Cross-Platform Agent: The agent automatically detects and reports its operating system. Interactive Server Console: The operator can send commands and receive outputs interactively. Multi-Agent Support: The server can handle multiple agents concurrently using threading. Automatic Reconnection: The agent attempts to reconnect if the connection is lost. Configurable Settings: IP, port, and encryption key can be easily customized.

#Usage Start the C2 Server python server.py [*] C2 listening on 0.0.0.0:443 Deploy the Agent python client.py Command and Control Example When an agent connects, the server provides an interactive shell for command execution:

[+] Agent connected from Initial message: check_in:Windows

c2@> whoami DESKTOP\user

c2@> ipconfig Ethernet adapter Local Area Connection: IPv4 Address. . . . . . . . . . . : 192.168.1.10

c2@> exit [-] Agent ('192.168.1.10', 54321) disconnected If the agent loses connection, it will automatically attempt to reconnect every 60 seconds.
