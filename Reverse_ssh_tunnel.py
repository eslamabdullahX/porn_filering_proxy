import getpass
import os
import socket
import select
import sys
import threading
from optparse import OptionParser
import paramiko


g_verbose = True
SSH_PORT = 22
DEFAULT_PORT = 4000
HELP = "This script sets up a reverse SSH tunnel."

def main ():
    options , server , remote = parse_options()
    password = None 
    if options.readpass :
        password=getpass.getpass('Please , Enter your password : ')
        
    ssh_client=paramiko.SSHClient()
    ssh_client.load_system_host_keys()
    ssh_client.set_missing_host_key_policy(paramiko.WarningPolicy())
    
    try :
        verbose(' [*] Trying to connect with the server.')
        ssh_client.connect(server[0],server[1],
                           username=options.user,
                           key_filename=options.keyfile,
                           look_for_keys=options.look_for_keys,
                           password=password,)
        
        verbose(' [*] Connected with the server.')
    except Exception as e :
        verbose(' [!!] Failed to connect with the server.  ERROR DETAILS : %r ' %e)
        sys.exit(1)
    
    verbose(
        "Now forwarding remote port %d to %s:%d ..."
        % (options.port, remote[0], remote[1]))
    
    try :
        reverse_forward_tunnel(options.port,remote[0],remote[1],ssh_client.get_transport())
        
    except KeyboardInterrupt:
        print("C-c: Port forwarding stopped.")
        sys.exit(0)        
    
    
            




def reverse_forward_tunnel (server_port,remote_host,remote_port,transport):
    transport.request_port_forward("",server_port)
    
    while True :
        chan=transport.accept(1000)
        if chan is None:    
            continue 
        
        thr=threading.Thread(target=handler , args=(chan,remote_host,remote_port))
        thr.setDaemon(True)    
        thr.start()
    





def handler(chan, host, port):
    socket_ = socket.socket()
    try:
        socket_.connect((host, port))
    except Exception as e:
        verbose(" [!!] Handler failed to connect to final destination: %r" % e)
        return

    verbose(" [*] Tunnel opened! Path: %r -> %r -> %r" % (chan.origin_addr, chan.getpeername(), (host, port)))

    # --- Loop to transfer data ---
    while True:
        try:
            r, w, x = select.select([socket_, chan], [], [])
            
            # Data coming FROM the local service (e.g., web server)
            if socket_ in r:
                data = socket_.recv(1024)
                verbose("    <-- [RECEIVING] %d bytes from local service (port %d)." % (len(data), port))
                if not data:
                    break
                chan.send(data)
                verbose("    --> [SENDING] %d bytes to remote user." % len(data))

            # Data coming FROM the remote user
            if chan in r:
                data = chan.recv(1024)
                verbose("    --> [RECEIVING] %d bytes from remote user." % len(data))
                if not data:
                    break
                socket_.send(data)
                verbose("    <-- [SENDING] %d bytes to local service (port %d)." % (len(data), port))

        except Exception as e:
            verbose(" [!!] Error during data transfer: %r" % e)
            break
            
    verbose(" [*] Tunnel closed for %r." % (chan.origin_addr,))
    chan.close()
    socket_.close()




def verbose(s):
    if g_verbose :
        print(s)
def get_host_port (spec, default_port):
    
    "parse 'hostname:22' into a host and port, with the port optional"
    
    args=(spec.split(":" , 1)+[default_port])[:2]
    args[1]=int (args[1])
    return args[0] ,args[1]




def parse_options():
    global g_verbose

    parser = OptionParser(
        usage="usage: %prog [options] <ssh-server>[:<server-port>]",
        version="%prog 1.0",
        description=HELP,
    )
    parser.add_option(
        "-q",
        "--quiet",
        action="store_false",
        dest="verbose",
        default=True,
        help="squelch all informational output",
    )
    parser.add_option(
        "-p",
        "--remote-port",
        action="store",
        type="int",
        dest="port",
        default=DEFAULT_PORT,
        help="port on server to forward (default: %d)" % DEFAULT_PORT,
    )
    parser.add_option(
        "-u",
        "--user",
        action="store",
        type="string",
        dest="user",
        default=getpass.getuser(),
        help="username for SSH authentication (default: %s)"
        % getpass.getuser(),
    )
    parser.add_option(
        "-K",
        "--key",
        action="store",
        type="string",
        dest="keyfile",
        default=None,
        help="private key file to use for SSH authentication",
    )
    parser.add_option(
        "",
        "--no-key",
        action="store_false",
        dest="look_for_keys",
        default=True,
        help="don't look for or use a private key file",
    )
    parser.add_option(
        "-P",
        "--password",
        action="store_true",
        dest="readpass",
        default=False,
        help="read password (for key or password auth) from stdin",
    )
    parser.add_option(
        "-r",
        "--remote",
        action="store",
        type="string",
        dest="remote",
        default=None,
        metavar="host:port",
        help="remote host and port to forward to",
    )
    
    options , args = parser.parse_args()
    if len(args) != 1 :
        parser.error("Incorrect number of arguments.")
    if options.remote is None:
        parser.error("Remote address required (-r).")
        
    g_verbose=options.verbose
    server_host , server_port=get_host_port(args[0] , SSH_PORT)
    remote_host , remote_port= get_host_port(options.remote,SSH_PORT)
    return options, (server_host, server_port), (remote_host, remote_port)    
    

    

if __name__ == "__main__":
    main()

