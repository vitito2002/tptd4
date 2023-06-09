import argparse
import socket
from scapy.all import *
from http.server import *

class HTTPServer:
    def __init__(self, port, default_content, redirects):
        self.port = port
        self.default_content = default_content
        self.redirects = redirects

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('', self.port))
        server_socket.listen(1)
        print(f"HTTP Server is running on port {self.port}...")

        while True:
            client_socket, client_address = server_socket.accept()
            request = client_socket.recv(4096).decode()

            if request:
                response = self.handle_request(request)
                client_socket.sendall(response)
                client_socket.close()

    def handle_request(self, request):
        # Parse the request
        headers, body = request.split('\r\n\r\n', 1)
        method, path, version = headers.split('\r\n')[0].split(' ')

        # Check if the request is a GET request
        if method != 'GET':
            return self.build_response(405, 'Method Not Allowed', 'Only GET requests are supported.')

        # Check if the requested domain is in the redirects
        domain = self.get_domain(headers)
        if domain in self.redirects:
            redirect_url = self.redirects[domain]
            return self.build_redirect_response(301, 'Moved Permanently', redirect_url)

        # Serve the default content
        return self.build_response(200, 'OK', self.default_content)

    def get_domain(self, headers):
        for line in headers.split('\r\n'):
            if line.startswith('Host:'):
                return line.split(' ')[1].strip()

    def build_response(self, status_code, status_text, content):
        response = f'HTTP/1.1 {status_code} {status_text}\r\n'
        response += 'Server: SimpleHTTPServer\r\n'
        response += 'Content-Type: text/html\r\n'
        response += f'Content-Length: {len(content)}\r\n'
        response += '\r\n'
        response += content
        return response.encode()

    def build_redirect_response(self, status_code, status_text, redirect_url):
        response = f'HTTP/1.1 {status_code} {status_text}\r\n'
        response += f'Location: {redirect_url}\r\n'
        response += '\r\n'
        return response.encode()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple HTTP Server')
    parser.add_argument('-p', '--port', type=int, default=8000, help='Port number to listen on')
    parser.add_argument('-c', '--default-content', type=str, default='<h1>Welcome to the Default Content!</h1>', help='Default content to serve')
    parser.add_argument('-r', '--redirects', nargs='*', type=str, default={}, help='Redirect mappings')
    args = parser.parse_args()

    server = HTTPServer(args.port, args.default_content, dict(args.redirects))
    server.start()
