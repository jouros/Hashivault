import http.server
import socketserver
import json

PORT = 8080

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Assuming your JSON file is named 'data.json' and is in the same directory as this script
        with open('data.json', 'r') as file:
            data = json.load(file)
        
        # Send response status code
        self.send_response(200)
        
        # Send headers
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        # Write the JSON data
        self.wfile.write(json.dumps(data).encode('utf-8'))

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print("serving at port", PORT)
    httpd.serve_forever()

