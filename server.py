#!/usr/bin/env python3
import base64
import json
import random
import socket
import os
import stat
import threading
import time

from threading import Thread

# Equivalent to CRLF, named CRLF for clarity
CRLF = "\r\n"


# Let's define some functions to help us deal with files, since reading them
# and returning their data is going to be a very common operation.

def get_file_contents(file_name):
    """Returns the text content of `file_name`"""
    with open(file_name, "r") as f:
        return f.read()


def get_file_binary_contents(file_name):
    """Returns the binary content of `file_name`"""
    with open(file_name, "rb") as f:
        return f.read()


def has_permission_other(file_name):
    """Returns `True` if the `file_name` has read permission on other group

    In Unix based architectures, permissions are divided into three groups:

    1. Owner
    2. Group
    3. Other

    When someone requests a file, we want to verify that we've allowed
    non-owners (and non group) people to read it before sending the data over.
    """
    stmode = os.stat(file_name).st_mode
    return getattr(stat, "S_IROTH") & stmode > 0


# Some files should be read in plain text, whereas others should be read
# as binary. To maintain a mapping from file types to their expected form, we
# have a `set` that maintains membership of file extensions expected in binary.
# We've defined a starting point for this set, which you may add to as necessary.
# TODO: Finish this set with all relevant files types that should be read in binary
binary_type_files = {"jpg", "jpeg", "mp3", "png", "html", "js", "css"}


def should_return_binary(file_extension):
    """
    Returns `True` if the file with `file_extension` should be sent back as
    binary.
    """
    return file_extension in binary_type_files


# For a client to know what sort of file you're returning, it must have what's
# called a MIME type. We will maintain a `dictionary` mapping file extensions
# to their MIME type so that we may easily access the correct type when
# responding to requests.
# TODO: Finish this dictionary with all required MIME types
mime_types = {
    "html": "text/html",
    "css": "text/css",
    "js": "text/javascript",
    "mp3": "audio/mpeg",
    "png": "image/png",
    "jpg": "image/jpg",
    "jpeg": "image/jpeg"
}


def get_file_mime_type(file_extension):
    """
    Returns the MIME type for `file_extension` if present, otherwise
    returns the MIME type for plain text.
    """
    mime_type = mime_types[file_extension]
    return mime_type if mime_type is not None else "text/plain"


def store_cookie(cookie, username):
    lock = threading.Lock()
    with lock:
        data2 = {username: [cookie, time.time()]}
        with open('cookie.json', 'r') as f:
            data: dict = json.load(f)
        data.update(data2)
        with open('cookie.json', 'w') as f:
            json.dump(data, f)


class HTTPServer:
    """
    Our actual HTTP server which will service GET and POST requests.
    """

    def __init__(self, host="localhost", port=9001, directory="./testdemo"):
        self.auth: dict = {}
        self.cookie: dict = {}
        print(f"Server started. Listening at http://{host}:{port}/")
        self.host = host
        self.port = port
        self.working_dir = directory
        self.load_auth()
        self.load_cookie()
        self.setup_socket()
        self.accept()
        self.teardown_socket()

    def setup_socket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))
        self.sock.listen(128)

    def load_cookie(self):
        with open('cookie.json', 'r') as f:
            self.cookie = json.load(f)

    def load_auth(self):
        with open('auth.json', 'r') as f:
            self.auth = json.load(f)

    def teardown_socket(self):
        if self.sock is not None:
            self.sock.shutdown()
            self.sock.close()

    def accept(self):
        while True:
            (client, address) = self.sock.accept()
            th = Thread(target=self.accept_request, args=(client, address))
            th.start()

    def check_keep(self, data: list[str]):
        keep = False
        for line in data:
            if line.split()[0].lower() == 'connection:' and line.split()[1].lower() == 'keep-alive':
                keep = True
                break
        return keep

    def accept_request(self, client_sock: socket, client_addr):
        client_sock.settimeout(1)
        try:
            while True:
                data = client_sock.recv(4096)
                print(data)
                if not data:
                    break
                req = data.decode("utf-8")
                response, keep = self.process_response(req)
                client_sock.sendall(response)
                print(response)
                if not keep:
                    break
        except socket.timeout:
            pass
        finally:
            client_sock.close()

    def check_has_auth(self, data: list[str]):
        has_auth = False
        for line in data:
            if line.split()[0] == 'Authorization:':
                has_auth = True
        return has_auth

    def check_auth(self, data: list[str], cookie: str):
        user_base64 = ''
        if cookie != '':
            lock = threading.Lock()
            cnt = 0
            with lock:
                self.load_cookie()
                for item in self.cookie:
                    if self.cookie[item][0] == cookie:
                        username = item
                        expire = self.cookie[item][1]
                        cnt += 1
                        break
                if cnt == 0:
                    return False, ""
                if time.time() - expire > 3600:
                    return False, ""
                else:
                    return True, username
        for line in data:
            if line.split()[0].lower() == 'authorization:' and line.split()[1].lower() == 'basic':
                user_base64 = line.split()[2]
                break
        user = base64.b64decode(user_base64).decode()
        user_name = user.split(":")[0]
        password = user.split(":")[1]
        if self.auth.get(user_name) is None or self.auth.get(user_name) != password:
            return False, ""
        else:
            return True, user_name

    def generate_cookie(self, length=32):
        characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        cookie = ''.join(random.choice(characters) for _ in range(length))
        return cookie

    def check_has_cookie(self, data: list[str]):
        has_cookie = False
        cookie = ''
        for line in data:
            if line.split()[0].lower() == 'cookie:':
                has_cookie = True
                cookie = line.split('=')[-1]
                break
        return has_cookie, cookie

    def add_cookie(self, username, builder):
        cookie = self.generate_cookie()
        if self.cookie.get(username) is not None:
            old_cookie = self.cookie[username][0]
            expire = self.cookie[username][1]
            if time.time() - expire < 3600:
                cookie = old_cookie
        store_cookie(cookie, username)
        builder.add_header("Set-Cookie", f"session-id={cookie}")

    def process_response(self, request):
        formatted_data = request.strip().split(CRLF)
        request_words = formatted_data[0].split()
        if len(request_words) == 0:
            return
        requested_file = request_words[1][1:]
        has_auth = self.check_has_auth(formatted_data)
        has_cookie, cookie = self.check_has_cookie(formatted_data)
        if not has_auth and not has_cookie:
            return self.need_authorized(formatted_data)
        else:
            true_auth, username = self.check_auth(formatted_data, cookie)
        if not true_auth:
            return self.unauthorized(formatted_data)
        if request_words[0] == "GET":
            return self.get_request(requested_file, formatted_data, username)
        if request_words[0] == "POST":
            return self.post_request(requested_file, formatted_data, username)
        if request_words[0] == "HEAD":
            return self.head_request(requested_file, formatted_data, username)
        return self.method_not_allowed(formatted_data)

    # The response to a HEADER request
    def head_request(self, requested_file, data, username):
        keep = self.check_keep(data)
        if not os.path.exists(requested_file):
            response, temp = self.resource_not_found(data, username)
        elif not has_permission_other(requested_file):
            response, temp = self.resource_forbidden(data, username)
        else:
            builder = ResponseBuilder()
            builder.set_content("")
            builder.set_status("200", "OK")
            if keep:
                builder.add_header("Connection", "Keep-Alive")
            else:
                builder.add_header("Connection", "Close")
            builder.add_header("Content-Type", get_file_mime_type(requested_file.split(".")[1]))
            self.add_cookie(username, builder)
            return builder.build(), keep
        return response, keep

    # TODO: Write the response to a GET request
    def get_request(self, requested_file, data: list[str], username):
        keep = self.check_keep(data)
        if not os.path.exists(requested_file):
            return self.resource_not_found(data, username)
        elif not has_permission_other(requested_file):
            return self.resource_forbidden(data, username)
        else:
            builder = ResponseBuilder()
            builder.set_content("")
            if should_return_binary(requested_file.split(".")[1]):
                builder.set_content(get_file_binary_contents(requested_file))
            else:
                builder.set_content(get_file_contents(requested_file))
            builder.set_status("200", "OK")
            if keep:
                builder.add_header("Connection", "Keep-Alive")
            else:
                builder.add_header("Connection", "Close")
            builder.add_header("Content-Type", get_file_mime_type(requested_file.split(".")[1]))
            self.add_cookie(username, builder)
            return builder.build(), keep

        # """
        # Responds to a GET request with the associated bytes.
        #
        # If the request is to a file that does not exist, returns
        # a `NOT FOUND` error.
        #
        # If the request is to a file that does not have the `other`
        # read permission, returns a `FORBIDDEN` error.
        #
        # Otherwise, we must read the requested file's content, either
        # in binary or text depending on `should_return_binary` and
        # send it back with a status set and appropriate mime type
        # depending on `get_file_mime_type`.
        # """

    # TODO: Write the response to a POST request
    def post_request(self, requested_file, data, username):
        keep = self.check_keep(data)
        builder = ResponseBuilder()
        builder.set_status("200", "OK")
        if keep:
            builder.add_header("Connection", "Keep-Alive")
        else:
            builder.add_header("Connection", "Close")
        builder.add_header("Content-Type", mime_types["html"])
        builder.set_content(get_file_contents("post.html"))
        self.add_cookie(username, builder)
        return builder.build(), keep

        # """
        # Responds to a POST request with an HTML page with keys and values
        # echoed per the requirements writeup.
        #
        # A post request through the form will send over key value pairs
        # through "x-www-form-urlencoded" format. You may learn more about
        # that here:
        #   https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST
        # You /do not/ need to check the POST request's Content-Type to
        # verify the encoding used (although a real server would).
        #
        # From the request, each key and value should be extracted. A row in
        # the HTML table will hold a single key-value pair. With the key having
        # the first column and the value the second. If a request sent n
        # key-value pairs, the HTML page returned should contain a table like:
        #
        # | key 1 | val 1 |
        # | key 2 | val 2 |
        # | ...   | ...   |
        # | key n | val n |
        #
        # Care should be taken in forming values with spaces. Since the request
        # was urlencoded, it will need to be decoded using
        # `urllib.parse.unquote`.
        # """

    def need_authorized(self, data):
        keep = self.check_keep(data)
        builder = ResponseBuilder()
        builder.set_status("401", "Unauthorized")
        builder.add_header("WWW-Authenticated", "Basic realm=\"Authorization Required\"")
        if keep:
            builder.add_header("Connection", "Keep-Alive")
        else:
            builder.add_header("Connection", "Close")
        builder.set_content(get_file_contents("401.html"))
        return builder.build(), keep

    def unauthorized(self, data):
        keep = self.check_keep(data)
        builder = ResponseBuilder()
        builder.set_status("401", "Unauthorized")
        if keep:
            builder.add_header("Connection", "Keep-Alive")
        else:
            builder.add_header("Connection", "Close")
        builder.set_content(get_file_contents("401.html"))
        return builder.build(), keep

    def method_not_allowed(self, data, username):
        keep = self.check_keep(data)
        """
        Returns 405 not allowed status and gives allowed methods.
        
        TODO: If you are not going to complete the `ResponseBuilder`,
        This must be rewritten.
        """
        builder = ResponseBuilder()
        builder.set_status("405", "METHOD NOT ALLOWED")
        allowed = ", ".join(["GET", "POST"])
        builder.add_header("Allow", allowed)
        if keep:
            builder.add_header("Connection", "Keep-Alive")
        else:
            builder.add_header("Connection", "Close")
        self.add_cookie(username, builder)
        return builder.build(), keep

    # TODO: Make a function that handles not found error
    def resource_not_found(self, data, username):
        keep = self.check_keep(data)
        """
        Returns 404 not found status and sends back our 404.html page.
        """
        builder = ResponseBuilder()
        builder.set_status("404", "NOT FOUND")
        if keep:
            builder.add_header("Connection", "Keep-Alive")
        else:
            builder.add_header("Connection", "Close")
        builder.add_header("Content-Type", mime_types["html"])
        builder.set_content(get_file_contents("404.html"))
        self.add_cookie(username, builder)
        return builder.build(), keep

    # TODO: Make a function that handles forbidden error
    def resource_forbidden(self, data, username):
        keep = self.check_keep(data)
        """
        Returns 403 FORBIDDEN status and sends back our 403.html page.
        """
        builder = ResponseBuilder()
        builder.set_status("403", "FORBIDDEN")
        if keep:
            builder.add_header("Connection", "Keep-Alive")
        else:
            builder.add_header("Connection", "Close")
        builder.add_header("Content-Type", mime_types["html"])
        builder.set_content(get_file_contents("403.html"))
        self.add_cookie(username, builder)
        return builder.build(), keep


class ResponseBuilder:
    """
    This class is here for your use if you want to use it. This follows
    the builder design pattern to assist you in forming a response. An
    example of its use is in the `method_not_allowed` function.

    Its use is optional, but it is likely to help, and completing and using
    this function to build your responses will give 5 bonus points.
    """

    def __init__(self):
        """
        Initialize the parts of a response to nothing.
        """
        self.headers = []
        self.status = None
        self.content = None

    def add_header(self, headerKey, headerValue):
        """ Adds a new header to the response """
        self.headers.append(f"{headerKey}: {headerValue}")

    def set_status(self, statusCode, statusMessage):
        """ Sets the status of the response """
        self.status = f"HTTP/1.1 {statusCode} {statusMessage}"

    def set_content(self, content):
        """ Sets `self.content` to the bytes of the content """
        if isinstance(content, (bytes, bytearray)):
            self.content = content
        else:
            self.content = content.encode("utf-8")

    # TODO Complete the build function
    def build(self):

        response = self.status
        response += CRLF
        for i in self.headers:
            response += i
            response += CRLF
        response += CRLF
        response = response.encode("utf-8")
        response += self.content

        return response
        # """
        # Returns the utf-8 bytes of the response.
        #
        # Uses the `self.status`, `self.headers` and `self.content` to form
        # an HTTP response in valid formatting per w3c specifications, which
        # can be seen here:
        #   https://www.w3.org/Protocols/rfc2616/rfc2616-sec6.html
        # or here:
        #   https://www.tutorialspoint.com/http/http_responses.htm
        #
        # Where CRLF is our `NEWLINE` constant.
        # """


if __name__ == "__main__":
    HTTPServer()
