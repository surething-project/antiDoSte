from http.server import HTTPServer, BaseHTTPRequestHandler
import time


class Serv(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        time.sleep(0.1)
        self.end_headers()


httpd = HTTPServer(('10.0.7.100', 443), Serv)
httpd.serve_forever()

