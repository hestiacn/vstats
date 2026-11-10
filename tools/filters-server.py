#!/usr/bin/env python3
"""Private API behind the web server's existing access/authentication rules."""
import argparse
import hmac
from http.server import BaseHTTPRequestHandler
import json
import os
import socket
import socketserver
import sys
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vstats_filters import Control, IDENTIFIER, MAX_REQUEST_BYTES, canonical, decode, read_json


class Handler(BaseHTTPRequestHandler):
    server_version = 'VStatsFilters'

    def log_message(self, fmt, *args):
        # URLs and credentials do not belong in the service journal.
        pass

    def respond(self, code, value):
        raw = canonical(value)
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'private, no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(raw)

    def dispatch(self, mutation=False):
        control = self.server.control
        if self.headers.get('X-Forwarded-Proto') != 'https':
            self.respond(403, {'error': 'Open Filters over HTTPS to use browser controls.'})
            return
        try:
            # The proxy MUST overwrite this header from its real REMOTE_USER.
            user = control.web_user(self.headers.get('X-VStats-Remote-User'))
            route = urlsplit(self.path)
            if route.query or route.fragment or '%' in route.path:
                raise ValueError('Unsupported API route')
            parts = route.path.strip('/').split('/')
            if mutation:
                if (self.headers.get('Origin') not in control.settings['origins'] or
                        not hmac.compare_digest(self.headers.get('X-VStats-CSRF', ''), control.csrf(user))):
                    self.respond(403, {'error': 'Reload Filters and retry from this website.'})
                    return
                if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                    raise ValueError('JSON request required')
                length = self.headers.get('Content-Length', '')
                if not length.isdigit() or not 0 < int(length) <= MAX_REQUEST_BYTES:
                    raise ValueError('Invalid request size')
                if self.headers.get('Transfer-Encoding'):
                    raise ValueError('Chunked requests are not supported')
                body = decode(self.rfile.read(int(length)))
                if len(parts) != 3 or parts[0] != 'sites':
                    raise ValueError('Unsupported API route')
                result = control.change(parts[1], parts[2], body, user)
            elif parts == ['session']:
                sites = []
                for site in user['sites']:
                    try:
                        control.authorize(user, site, write=False)
                        sites.append(site)
                    except PermissionError:
                        pass
                result = {'actor': user['name'], 'sites': sites, 'csrf': control.csrf(user),
                          'authenticated': user['authenticated']}
            elif len(parts) == 3 and parts[0] == 'sites' and parts[2] == 'state':
                control.authorize(user, parts[1], write=False)
                result = control.state_for(parts[1])
            elif len(parts) == 3 and parts[0] == 'sites' and parts[2] == 'history':
                control.authorize(user, parts[1], write=False)
                result = control.history_for(parts[1])
            elif len(parts) == 2 and parts[0] == 'jobs' and IDENTIFIER.fullmatch(parts[1]):
                path = control.state / 'jobs' / (parts[1] + '.json')
                if path.exists():
                    result = read_json(path)
                else:
                    result = read_json(control.state / 'requests' / (parts[1] + '.json'))['queued']
                control.authorize(user, result['site'], write=False)
            else:
                raise ValueError('Unsupported API route')
            self.respond(200, result)
        except PermissionError as e:
            self.respond(403, {'error': str(e)})
        except (ValueError, TypeError, KeyError, FileNotFoundError, UnicodeError) as e:
            # Validation errors contain fixed diagnostics, never log contents.
            message = str(e) if isinstance(e, ValueError) else 'Invalid request or unavailable state'
            self.respond(400, {'error': message})
        except Exception:
            self.respond(503, {'error': 'Control service unavailable; published reports are unchanged.'})

    def do_GET(self):
        self.dispatch()

    def do_POST(self):
        self.dispatch(mutation=True)


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings', required=True)
    parser.add_argument('--socket-activation', action='store_true')
    parser.add_argument('--socket')
    args = parser.parse_args()
    settings = read_json(args.settings, root_owned=True)
    if args.socket_activation:
        if os.environ.get('LISTEN_PID') != str(os.getpid()) or os.environ.get('LISTEN_FDS') != '1':
            raise RuntimeError('One systemd listening socket is required')
        server = Server('systemd', Handler, bind_and_activate=False)
        server.socket.close()
        server.socket = socket.socket(fileno=3)
    else:
        if not args.socket:
            parser.error('--socket is required without socket activation')
        server = Server(args.socket, Handler)
        os.chmod(args.socket, 0o660)
    server.control = Control(settings)
    server.serve_forever()


if __name__ == '__main__':
    main()
