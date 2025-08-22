import sys
import socket
import threading
import select

BLOCKED_SITES = set()


def load_blocked_domains(filename):
    """
    تقوم هذه الدالة بقراءة قائمة المواقع المحجوبة من ملف
    وتحميلها في الـ set العام لعملية بحث سريعة.
    """
    global BLOCKED_SITES
    print(f"[*] Loading blocklist from: {filename}")
    try:
        with open(filename, "r", encoding="utf-8") as file_object:
            for line in file_object:
                clean_line = line.strip()
                if clean_line and not clean_line.startswith('#'):

                    parts = clean_line.split()
                    if len(parts) >= 2:
                        domain = parts[1]
                        BLOCKED_SITES.add(domain.lower())
        
        print(f"[*] Successfully loaded {len(BLOCKED_SITES)} unique domains into the blocklist.")
        return True
    except FileNotFoundError:
        print(f"[!!] FATAL ERROR: The blocklist file '{filename}' was not found.")
        return False

def my_filter_function(domain_to_check):
    """
    التحقق مما إذا كان النطاق موجودًا في القائمة المحجوبة.
    """
    domain_to_check = domain_to_check.lower()
    
    # البحث في القائمة العامة
    if domain_to_check in BLOCKED_SITES:
        print(f"[!] Blocked by list: '{domain_to_check}'")
        return True # محجوب
    
    for blocked_domain in BLOCKED_SITES:
        if domain_to_check.endswith("." + blocked_domain):
            print(f"[!] Blocked by list (subdomain): '{domain_to_check}'")
            return True # محجوب
            
    return False # غير محجوب


def hexdump(src, length=16):
    result = []
    if isinstance(src, str):
        src = src.encode('latin-1', errors='replace')
    for i in range(0, len(src), length):
        chunk = src[i:i + length]
        hexa = ' '.join([f'{byte:02X}' for byte in chunk])
        text = ''.join([chr(byte) if 32 <= byte < 127 else '.' for byte in chunk])
        result.append(f'{i:04X}  {hexa:<{length * 3}}  {text}')
    print('\n'.join(result))

def forward_tunnel(client_socket, remote_socket):
    """
    تمرير البيانات في الاتجاهين بين طرفين باستخدام select.
    """
    sockets = [client_socket, remote_socket]
    try:
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets)
            if exceptional:
                break
            
            for sock in readable:
                data = sock.recv(4096)
                if not data: # تم إغلاق الاتصال
                    return
                
                if sock is client_socket:
                    remote_socket.sendall(data)
                else:
                    client_socket.sendall(data)
    finally:
        client_socket.close()
        remote_socket.close()


def handle_https_connect(client_socket, target_host, target_port):
    """
    معالجة طلبات CONNECT الخاصة بـ HTTPS.
    """
    print(f"[*] Handling CONNECT request to {target_host}:{target_port}")
    
    # --- تطبيق الفلترة هنا ---
    if my_filter_function(target_host):
        client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by Proxy Filter.")
        client_socket.close()
        return

    try:
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((target_host, target_port))
        
        # إرسال رد النجاح للعميل
        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        
        # بدء تمرير البيانات
        forward_tunnel(client_socket, remote_socket)
        
    except Exception as e:
        print(f"[!!] CONNECT error: {e}")
        client_socket.close()

def handle_http_request(client_socket, request):
    """
    معالجة طلبات HTTP العادية.
    """
    try:
        # استخلاص الـ Host من الطلب
        host_line = next((line for line in request.split(b'\r\n') if line.lower().startswith(b'host:')), None)
        if not host_line:
            client_socket.close()
            return
            
        target_host = host_line.split(b' ')[1].decode().strip()
        target_port = 80 # المنفذ الافتراضي لـ HTTP
        
        print(f"[*] Handling HTTP request to {target_host}:{target_port}")
        
        # --- تطبيق الفلترة هنا ---
        if my_filter_function(target_host):
            client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by Proxy Filter.")
            client_socket.close()
            return

        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((target_host, target_port))
        remote_socket.sendall(request)
        
        # بدء تمرير البيانات
        forward_tunnel(client_socket, remote_socket)

    except Exception as e:
        print(f"[!!] HTTP error: {e}")
        client_socket.close()

def client_thread(client_socket):
    """
    تستقبل أول طلب من العميل وتحدد نوعه (HTTP أو HTTPS).
    """
    try:
        request = client_socket.recv(4096)
        if not request:
            return

        first_line = request.split(b'\r\n')[0]
        method, path, _ = first_line.split(b' ')
        
        if method == b'CONNECT':
            target_host, target_port_str = path.decode().split(':')
            handle_https_connect(client_socket, target_host, int(target_port_str))
        else:
            handle_http_request(client_socket, request)
    except Exception:
        pass
    finally:
        client_socket.close()


def main():
    if len(sys.argv) != 4:
        print("Usage: python3 proxy.py [local_host] [local_port] [blocklist_file]")
        print("Example: python3 proxy.py 127.0.0.1 8080 porn.txt")
        sys.exit(0)

    l_host = sys.argv[1]
    l_port = int(sys.argv[2])
    blocklist_file = sys.argv[3]
    
    # تحميل قائمة الحجب
    if not load_blocked_domains(blocklist_file):
        sys.exit(1) # الخروج إذا فشل تحميل الملف

    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((l_host, l_port))
        server.listen(10)
        print(f"[*] Proxy listening on {l_host}:{l_port}")
    except Exception as e:
        print(f"[!!] Failed to start server: {e}")
        sys.exit(1)

    while True:
        client_socket, addr = server.accept()
        print(f"\n[==>] Accepted connection from {addr[0]}:{addr[1]}")
        t = threading.Thread(target=client_thread, args=(client_socket,))
        t.start()

if __name__ == "__main__":
    main()