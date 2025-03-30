# lsport
lsport is a command listing open ports

## Usage
```bash
Usage: 
 lsport [options]

List information about open network ports

Options:
  -h, --help              this help message
  -v, --version           version information
  -A, -e                  all ports (default is only users ports)
  -O, --output-all        output all columns
  -o, --output <list>     specified output columns

Available output columns:
          PID  Process Identifier(ID)
          CMD  Process name
        LPORT  Port on local machine
         NODE  Traffic type ie: tcp or udp
          DST  Destination IP address and remote port (DSTIP and RPORT)
        STATE  Connection state/status
         USER  Username of user who owns the process
          FDs  List of file descriptors pointing to this open port
```

## How it works
lsport simply reads, parses, and prints informaton in `/proc/net/...`
