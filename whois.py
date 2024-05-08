

import socket

def whois_lookup(domain: str):
    # Create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect to the WHOIS server (in this case, whois.iana.org) on port 43
    s.connect(("whois.iana.org", 43))
    
    # Send the domain name followed by "\r\n" to indicate end of command
    s.send(f"{domain}\r\n".encode())
    
    # Receive the response from the server (up to 4096 bytes) and decode it
    response = s.recv(4096).decode()
    
    # Close the socket connection
    s.close()
    
    # Return the response received from the WHOIS server
    return response
