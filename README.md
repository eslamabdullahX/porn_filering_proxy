Dynamic Filtering Proxy Server
This project is a comprehensive proxy server built from scratch using Python. It forwards your web traffic (HTTP & HTTPS) and allows you to block unwanted websites based on a customizable external blocklist.

Features
HTTP & HTTPS Support: Capable of handling both standard and encrypted web requests (CONNECT method).

Dynamic Filtering: Blocks websites based on an external text file that you can easily modify.

Multi-threaded: Can efficiently serve multiple client connections simultaneously.

Efficient Blocklist Loading: The blocklist is loaded into a set in memory on startup for incredibly fast lookup operations.

 How to Use
Follow these simple steps to run the proxy and start filtering your web traffic.



Run the server using the following command, replacing the values as needed:

Bash

python3 proxy.py 127.0.0.1 8080 blocklist.txt
127.0.0.1: The local host the proxy will run on.

8080: The port the proxy will listen on.

blocklist.txt: The name of your blocklist file.

If everything starts correctly, you will see the message: [*] Proxy listening on 127.0.0.1:8080. Keep this terminal window open.

Step 2: Configure Your Browser
Now, you need to tell your browser to use the proxy you just launched.

Go to your browser's Settings.

Search for Network Settings or Proxy.

Choose "Manual proxy configuration".

Enter the following details:

HTTP Proxy: 127.0.0.1

Port: 8080 (or the port you chose in the previous step).

Make sure to check the option "Also use this proxy for HTTPS" or similar.

Save the settings.

Step 3: Start Browsing
That's it! All your traffic will now go through the proxy. Try visiting a site from your blocklist, and you will see that it's successfully blocked.

How It Works
The proxy listens for connections from the browser. It then parses the request to identify the destination domain. Before forwarding the request, it checks the domain against the in-memory blocklist. If the domain is blocked, it returns a "Forbidden" error; otherwise, it establishes a connection and acts as a middleman, relaying data between you and the destination website.
