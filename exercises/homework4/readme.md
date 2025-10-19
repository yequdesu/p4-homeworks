## Access Control List

### Run the code

We provide a skeleton P4 program,
`acl.p4`, which initially forwards all packets. Your job is to
extend this skeleton program to properly implement an ACL with two following rules:

- drop all the UDP packets with dstPort=80
- drop all the packets with dstIP=10.0.1.4

1. In your shell, run:
   ```bash
   make run
   ```
   This will:
   * compile `acl.p4`, and
   * start a Mininet instance with one switch (`s1`) connected to four hosts (`h1`, `h2`, `h3` and `h4`). Mininet is a network simulator that can simulate a virtual network in the VM.
   * The hosts are assigned with IP addresses of `10.0.1.1`, `10.0.1.2`, `10.0.1.3` and `10.0.1.4`.
   The output of this command line may be useful when you debug.

2. You should now see a Mininet command prompt. Open two terminals
   for `h1` and `h2`, respectively:
   ```bash
   mininet> xterm h1 h2
   ```
3. Each host includes a small Python-based messaging client and
   server. In `h2`'s xterm, go to the current exercise folder (`cd exercises/acl`) and start the server with the listening port:
   ```bash
   ./receive.py 80
   ./receive.py 8080
   ```
   **Don't forget the port number when running receive.py!!**
4. In `h1`'s xterm, go to the current exercise folder (`cd exercises/acl`) and send a message to `h2`:
   ```bash
   ./send.py 10.0.1.2 UDP 80 "udp message"
   ./send.py 10.0.1.2 TCP 8080 "tcp message
   ```
   The command line means `h1` will send a message to `10.0.1.2` with udp.dstport=80.
   The message will be received and displayed in `h2`.
5. Type `exit` to leave each xterm and the Mininet command line.
   Then, to stop mininet:
   ```bash
   make stop
   ```
   And to delete all pcaps, build files, and logs:
   ```bash
   make clean
   ```
6. Follow the instructions from above, the results are as follows. 
- TCP
  - h1 -> h2 port!=80 yes, port=80 yes;
  - h1 -> h3 port!=80 yes, port=80 yes;
  - h1 -> h4 no
- UDP
  - h1 -> h2 port!=80 yes, port=80 no;
  - h1 -> h3 port!=80 yes, port=80 no;
  - h1 -> h4 no;

