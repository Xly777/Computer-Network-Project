#!/usr/bin/env python3
import argparse
import base64
import json
import random
import re
import socket
import os
import stat
import threading
import time
import mimetypes


from threading import Thread

CRLF = "\r\n"

def get_file_contents(file_name):
    with open(file_name, "r") as f:
        return f.read()


def get_file_binary_contents(file_name):
    with open(file_name, "rb") as f:
        return f.read()


def has_permission_other(file_name):
    stmode = os.stat(file_name).st_mode
    return getattr(stat, "S_IROTH") & stmode > 0

mime_types = {
    "html": "text/html",
    "css": "text/css",
    "js": "text/javascript",
    "mp3": "audio/mpeg",
    "png": "image/png",
    "jpg": "image/jpg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "pdf": "application/pdf",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xls": "application/vnd.ms-excel",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "ppt": "application/vnd.ms-powerpoint",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "zip": "application/zip",
    "txt": "text/plain",
    "json": "application/json",
    "xml": "application/xml",
}


def get_file_mime_type(file_extension):
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
    def __init__(self, host="localhost", port=8080, directory="./data"):
        self.auth: dict = {}
        self.cookie: dict = {}
        print(f"Server started. Listening at http://{host}:{port}/")
        self.host = host
        self.port = port
        self.working_dir = directory
        self.load_auth()
        self.load_cookie()
        self.load_cookie()
        self.setup_socket()
        self.accept()
        self.teardown_socket()

    def setup_socket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))
        self.sock.listen(128)

    def load_cookie(self):
        try:
            with open('cookie.json', 'r') as f:
                # 尝试加载 JSON 数据
                self.cookie = json.load(f)
        except json.decoder.JSONDecodeError:
            self.cookie: dict = {}

    def load_auth(self):
        with open('auth.json', 'r') as f:
            self.auth = json.load(f)

    def teardown_socket(self):
        if self.sock is not None:
            self.sock.shutdown(2)
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
        request = ""
        response = ""
        ifPost = 0
        ifOverSize = 0
        while True:
            data = client_sock.recv(4096)
            print(data)
            if not data:
                break
            req = data.decode("utf-8")
            request += req
            formatted_data = req.strip().split(CRLF)
            request_words = formatted_data[0].split()
            if request_words[0] == "POST":
                ifPost = 1
                for line in formatted_data:
                    if line.strip():
                        if line.split()[0] == "Content-Length:":
                            if int(line.split()[1]) > 4096:
                                ifOverSize = 1
                                break

            if ifPost == 1 and ifOverSize == 1:
                print(formatted_data)
                boundary = ""
                for line in formatted_data:
                    if line.strip():
                        if line.split()[0] == "Content-Type:":
                            boundary = line.split()[2].split("=")[1]
                            break
                while True:
                    data = client_sock.recv(4096)
                    print(data)
                    if not data:
                        break
                    temp = data.decode("utf-8")
                    request += temp
                    if boundary in temp:
                        break
                response, keep = self.process_response(request)
            else:
                ifPost = 0
                ifOverSize = 0
                response, keep = self.process_response(req)
            # print(response)
            client_sock.sendall(response)
            if not keep:
                break
        client_sock.close()

    def check_has_auth(self, data: list[str]):
        has_auth = False
        for line in data:
            if line.strip():
                if line.split()[0].lower() == 'authorization:':
                    has_auth = True
        return has_auth

    def check_auth(self, data: list[str], cookie: str):
        user_base64 = ''
        has_auth=False
        for line in data:
            if line.split()[0].lower() == 'authorization:' and line.split()[1].lower() == 'basic':
                user_base64 = line.split()[2]
                has_auth=True
                break
        if has_auth:
            user = base64.b64decode(user_base64).decode()
            user_name = user.split(":")[0]
            password = user.split(":")[1]
            if self.auth.get(user_name) is None or self.auth.get(user_name) != password:
                return False, ""
            else:
                return True, user_name
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

    def generate_cookie(self, length=32):
        characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        cookie = ''.join(random.choice(characters) for _ in range(length))
        return cookie

    def check_has_cookie(self, data: list[str]):
        has_cookie = False
        cookie = ''
        for line in data:
            if line.strip():
                if line.split()[0].lower() == 'cookie:':
                    has_cookie = True
                    cookie = line.split('=')[-1]
                    break
        return has_cookie, cookie

    def add_cookie(self, username, builder, has_cookie):
        cookie = self.generate_cookie()
        if self.cookie.get(username) is not None:
            old_cookie = self.cookie[username][0]
            expire = self.cookie[username][1]
            if time.time() - expire < 3600:
                cookie = old_cookie
        if not has_cookie:
            cookie = self.generate_cookie()
        store_cookie(cookie, username)
        builder.add_header("Set-Cookie", f"session-id={cookie}")

    def process_response(self, request):
        formatted_data = request.strip().split(CRLF)
        request_words = formatted_data[0].split()
        print(formatted_data)
        print(request_words)
        if request_words[0] == "OPTIONS":
            builder = ResponseBuilder()
            builder.set_status("200", "OK")
            builder.set_content("")
            return builder.build(), True
        if len(request_words) == 0:
            return
        PathAndParams = request_words[1]
        has_auth = self.check_has_auth(formatted_data)
        has_cookie, cookie = self.check_has_cookie(formatted_data)
        if not has_auth and not has_cookie:
            return self.need_authorized(formatted_data)
        else:
            true_auth, username = self.check_auth(formatted_data, cookie)
        if not true_auth:
            return self.unauthorized(formatted_data)

        ## if no auth's folder, create one
        if not os.path.exists(self.working_dir + "/" + username):
            os.mkdir(self.working_dir + "/" + username)
        if request_words[0] == "GET":
            if "upload" in PathAndParams or "delete" in PathAndParams:
                return self.method_not_allowed(formatted_data, username, has_cookie)
            requested_file = ''
            number = -2
            tempParams = ''
            range = []
            if "?" in PathAndParams:
                parts = PathAndParams.split("?")
                tempFile = parts[0]
                tempFile = tempFile.rstrip('/')
                requested_file = self.working_dir + tempFile
                print(requested_file)
                if not os.path.exists(requested_file):
                    return self.resource_not_found(formatted_data, username, has_cookie)
                if os.path.isdir(requested_file):
                    parts1 = requested_file.split("/")
                    authority = parts1[2] if len(parts1) >= 3 else -1
                    # if authority in self.auth and authority != -1:
                    #     if authority != username:
                            # return self.resource_forbidden(formatted_data, username, has_cookie)
                    tempParams = parts[1]
                    number = tempParams[-1]
                    if tempParams != "SUSTech-HTTP=0" and tempParams != "SUSTech-HTTP=1":
                        return self.bad_request(formatted_data, username, has_cookie)
                else:
                    parts1 = requested_file.split("/")
                    authority = parts1[2] if len(parts1) > 3 else -1
                    # if authority in self.auth and authority != -1:
                    #     if authority != username:
                            # return self.resource_forbidden(formatted_data, username, has_cookie)
                    tempParams = parts[1]
                    number = 3
                    if tempParams != "chunked=1":
                        return self.bad_request(formatted_data, username, has_cookie)
            else:
                tempFile = PathAndParams
                tempFile = tempFile.rstrip('/')
                requested_file = self.working_dir + tempFile
                print(requested_file)
                if not os.path.exists(requested_file):
                    return self.resource_not_found(formatted_data, username, has_cookie)
                if os.path.isdir(requested_file):
                    parts = requested_file.split("/")
                    # authority = parts[2] if len(parts) >= 3 else -1
                    # if authority in self.auth and authority != -1:
                    #     if authority != username:
                    #         return self.resource_forbidden(formatted_data, username, has_cookie)
                    number = 0
                else:
                    parts = requested_file.split("/")
                    authority = parts[2] if len(parts) > 3 else -1
                    # if authority in self.auth and authority != -1:
                    #     if authority != username:
                    #         return self.resource_forbidden(formatted_data, username, has_cookie)
                    number = 2
                    for line in formatted_data:
                        if line.strip():
                            if line.split()[0].lower() == 'range:':
                                range = self.processRange(line)
                                number = 4
                                break
            return self.get_request(requested_file, number, range,formatted_data, username, has_cookie)

        if request_words[0] == "POST":
            if "upload" not in PathAndParams and "delete" not in PathAndParams:
                return self.method_not_allowed(formatted_data, username, has_cookie)
            if "path" not in PathAndParams:
                return self.bad_request(formatted_data, username, has_cookie)
            if "?" in PathAndParams:
                method = PathAndParams.split("?")[0]
                params = PathAndParams.split("?")[1]
                print(method)
                params = params.split("=")[1]
                params = params.replace("%2F", "/")
                params = params.strip("/")
                requested_file = self.working_dir + "/" +params
                print(requested_file)
                parts = requested_file.split("/")
                authority = parts[2]
                if authority != username:
                    return self.resource_forbidden(formatted_data, username, has_cookie)
                elif not os.path.exists(requested_file):
                    return self.resource_not_found(formatted_data, username, has_cookie)
                elif "upload" in method:
                    return self.post_request(1, requested_file, formatted_data, username, request, has_cookie)
                elif "delete" in method:
                    return self.post_request(2, requested_file, formatted_data, username, request, has_cookie)
            else:
                return self.bad_request(formatted_data, username, has_cookie)
        if request_words[0] == "HEAD":
            if "upload" in PathAndParams or "delete" in PathAndParams:
                return self.method_not_allowed(formatted_data, username, has_cookie)
            requested_file = ''
            number = -2
            tempParams = ''
            range = []
            if "?" in PathAndParams:
                parts = PathAndParams.split("?")
                tempFile = parts[0]
                tempFile = tempFile.rstrip('/')
                requested_file = self.working_dir + tempFile
                print(requested_file)
                if not os.path.exists(requested_file):
                    return self.resource_not_found(formatted_data, username, has_cookie)
                if os.path.isdir(requested_file):
                    parts1 = requested_file.split("/")
                    authority = parts1[2] if len(parts1) >= 3 else -1
                    # if authority in self.auth and authority != -1:
                    #     if authority != username:
                    #         return self.resource_forbidden(formatted_data, username, has_cookie)
                    tempParams = parts[1]
                    number = tempParams[-1]
                    if tempParams != "SUSTech-HTTP=0" and tempParams != "SUSTech-HTTP=1":
                        return self.bad_request(formatted_data, username, has_cookie)
                else:
                    parts1 = requested_file.split("/")
                    authority = parts1[2] if len(parts1) > 3 else -1
                    # if authority in self.auth and authority != -1:
                    #     if authority != username:
                    #         return self.resource_forbidden(formatted_data, username, has_cookie)
                    tempParams = parts[1]
                    number = 3
                    if tempParams != "chunked=1":
                        return self.bad_request(formatted_data, username, has_cookie)
            else:
                tempFile = PathAndParams
                tempFile = tempFile.rstrip('/')
                requested_file = self.working_dir + tempFile
                print(requested_file)
                if not os.path.exists(requested_file):
                    return self.resource_not_found(formatted_data, username, has_cookie)
                if os.path.isdir(requested_file):
                    parts = requested_file.split("/")
                    authority = parts[2] if len(parts) >= 3 else -1
                    # if authority in self.auth and authority != -1:
                    #     if authority != username:
                    #         return self.resource_forbidden(formatted_data, username, has_cookie)
                    number = 0
                else:
                    parts = requested_file.split("/")
                    authority = parts[2] if len(parts) > 3 else -1
                    # if authority in self.auth and authority != -1:
                    #     if authority != username:
                    #         return self.resource_forbidden(formatted_data, username, has_cookie)
                    number = 2
                    for line in formatted_data:
                        if line.strip():
                            if line.split()[0].lower() == 'range:':
                                range = self.processRange(line)
                                number = 4
                                break
            return self.head_request(requested_file, number, range,formatted_data, username, has_cookie)
        return self.method_not_allowed(formatted_data, username, has_cookie)


    def processRange(self, raw_string):
        # pattern = r'\d+.*\d+'
        pattern = r'-?\d+.*\d+-?'
        # 使用正则表达式进行匹配
        match = re.search(pattern, raw_string)
        range = match[0]
        parts = []
        if "," in range:
            parts = range.split(",")
        else:
            parts.append(range)
        return parts

    def checkRangeValid(self,raw_string,file_size):
        parts = raw_string.split("-")
        if parts[0] == "" or parts[1] == "":
            if parts[0] == "":
                number2 = int(parts[1])
                if number2 >= file_size:
                    return False
            return True
        else:
            number1 = int(parts[0])
            number2 = int(parts[1])
            if number1 > number2:
                return False
            if number1 < 0 or number2 >= file_size:
                return False
        return True

    def calculateRange(self,raw_string):
        parts = raw_string.split("-")
        if parts[0] == "" or parts[1] == "":
            if parts[0] == "":
                number2 = int(parts[1])
                return "-",number2
            if parts[1] == "":
                number1 = int(parts[0])
                return number1,"-"
        else:
            number1 = int(parts[0])
            number2 = int(parts[1])
            return number1,number2

    # The response to a HEADER request
    def head_request(self, requested_file, number,range, data: list[str], username, has_cookie):
        keep = self.check_keep(data)
        if not has_permission_other(requested_file):
            return self.resource_forbidden(data, username, has_cookie)
        else:
            builder = ResponseBuilder()
            if int(number) == 1 and os.path.isdir(requested_file):
                # Case: Return directory content as JSON
                content = self.get_directory_content(requested_file)
                builder.set_content("")
                builder.add_header("Content-Type", "application/json")
                builder.add_header("Content-Length", str(len(content)))
                builder.set_status("200", "OK")
            elif int(number) == 2:
                # Case: Return file binary content
                file_content = get_file_binary_contents(requested_file)
                builder.set_content("")
                media_type, encoding = mimetypes.guess_type(requested_file)
                builder.add_header("Content-Type", media_type)
                builder.add_header("Content-Length", str(len(file_content)))
                builder.set_status("200", "OK")
            elif int(number) == 0:
                # Case: Show HTML page for directory or file
                content = self.get_directory_html(requested_file, username)
                builder.set_content("")
                builder.add_header("Content-Type", "text/html")
                builder.add_header("Content-Length", str(len(content)))
                builder.set_status("200", "OK")
            elif int(number) == 3:
                # Case: Chunked transfer
                file_content = get_file_binary_contents(requested_file)
                builder.set_content("")
                media_type, encoding = mimetypes.guess_type(requested_file)
                builder.add_header("Content-Type", media_type)
                builder.add_header("Transfer-Encoding", "chunked")
                builder.set_status("200", "OK")
            elif int(number) == 4:
                # Case: Breakpoint Transmission
                file_size = os.path.getsize(requested_file)
                file_content = get_file_binary_contents(requested_file)
                file_size = len(file_content)
                if len(range) == 2:
                    if range[0] == "0-0" and range[1] == "-1":
                        first_byte = file_content[0:1]
                        last_byte = file_content[-1:]
                        temp = first_byte + last_byte
                        builder.set_content("")
                        media_type, encoding = mimetypes.guess_type(requested_file)
                        builder.add_header("Content-Type", media_type)
                        builder.add_header("Content-Length", str(2))
                        builder.add_header("Content-Range", f"bytes 0-0,-1/{file_size}")
                        builder.set_status("200", "OK")
                        if keep:
                            builder.add_header("Connection", "Keep-Alive")
                        else:
                            builder.add_header("Connection", "Close")
                        self.add_cookie(username, builder, has_cookie)
                        return builder.build(), keep
                for item in range:
                    if not self.checkRangeValid(item,file_size):
                        return self.Range_Not_Satisfiable(data, username, has_cookie)
                if len(range) == 1:
                    start,end = self.calculateRange(range[0])
                    if start == "-":
                        builder.set_content("")
                        media_type, encoding = mimetypes.guess_type(requested_file)
                        builder.add_header("Content-Type", media_type)
                        builder.add_header("Content-Range", f"bytes -{end}/{file_size}")
                        builder.add_header("Content-Length", str(end))
                        builder.set_status("206", "Partial Content")
                    elif end == "-":
                        temp = file_size - start
                        builder.set_content("")
                        media_type, encoding = mimetypes.guess_type(requested_file)
                        builder.add_header("Content-Type", media_type)
                        builder.add_header("Content-Range", f"bytes {start}-/{file_size}")
                        builder.add_header("Content-Length", str(file_size-start))
                        builder.set_status("206", "Partial Content")
                    else:
                        builder.set_content("")
                        media_type, encoding = mimetypes.guess_type(requested_file)
                        builder.add_header("Content-Type", media_type)
                        builder.add_header("Content-Range", f"bytes {start}-{end}/{file_size}")
                        builder.add_header("Content-Length", str(end-start+1))
                        builder.set_status("206", "Partial Content")
                else:
                    builder.add_header("Content-Type", "multipart/byteranges; boundary=3d6b6a416f9b5")
                    tempContent = b''
                    media_type, encoding = mimetypes.guess_type(requested_file)
                    for item in range:
                        start, end = self.calculateRange(item)
                        if start == "-":
                            tempContent += b'--3d6b6a416f9b5\r\n'
                            tempContent += b'Content-Type: ' + media_type.encode() + b'\r\n'
                            tempContent += b'Content-Range: bytes -' + str(end).encode() + b'/' + str(file_size).encode() + b'\r\n'
                            tempContent += b'\r\n'
                            tempContent += file_content[-end:]
                            tempContent += b'\r\n'

                        elif end == "-":
                            temp = file_size - start
                            tempContent += b'--3d6b6a416f9b5\r\n'
                            tempContent += b'Content-Type: ' + media_type.encode() + b'\r\n'
                            tempContent += b'Content-Range: bytes ' + str(start).encode() + b'-/' + str(file_size).encode() + b'\r\n'
                            tempContent += b'\r\n'
                            tempContent += file_content[-temp:]
                            tempContent += b'\r\n'

                        else:
                            tempContent += b'--3d6b6a416f9b5\r\n'
                            tempContent += b'Content-Type: ' + media_type.encode() + b'\r\n'
                            tempContent += b'Content-Range: bytes ' + str(start).encode() + b'-' + str(end).encode() + b'/' + str(file_size).encode() + b'\r\n'
                            tempContent += b'\r\n'
                            tempContent += file_content[start:end + 1]
                            tempContent += b'\r\n'

                    tempContent += b'--3d6b6a416f9b5--\r\n'
                    print(tempContent.decode("utf-8"))
                    builder.set_content("")
                    builder.add_header("Content-Length", str(len(tempContent)))
                    builder.set_status("206", "Partial Content")
            if keep:
                builder.add_header("Connection", "Keep-Alive")
            else:
                builder.add_header("Connection", "Close")
            self.add_cookie(username, builder, has_cookie)
            return builder.build(), keep

    # TODO: Write the response to a GET request
    def get_request(self, requested_file, number,range, data: list[str], username, has_cookie):
        # print(number)
        # print(requested_file)
        keep = self.check_keep(data)
        if not has_permission_other(requested_file):
            return self.resource_forbidden(data, username, has_cookie)
        else:
            builder = ResponseBuilder()
            if int(number) == 1 and os.path.isdir(requested_file):
                # Case: Return directory content as JSON
                content = self.get_directory_content(requested_file)
                builder.set_content(content)
                builder.add_header("Content-Type", "application/json")
                builder.add_header("Content-Length", str(len(content)))
                builder.set_status("200", "OK")
            elif int(number) == 2:
                # Case: Return file binary content
                file_content = get_file_binary_contents(requested_file)
                builder.set_content(file_content)
                media_type, encoding = mimetypes.guess_type(requested_file)
                builder.add_header("Content-Type", media_type)
                builder.add_header("Content-Length", str(len(file_content)))
                builder.add_header("Content-Disposition", "attachment")
                builder.set_status("200", "OK")
            elif int(number) == 0:
                # Case: Show HTML page for directory or file
                content = self.get_directory_html(requested_file, username)
                builder.set_content(content)
                builder.add_header("Content-Type", "text/html")
                builder.add_header("Content-Length", str(len(content)))
                builder.set_status("200", "OK")
            elif int(number) == 3:
                # Case: Chunked transfer
                file_content = get_file_binary_contents(requested_file)
                builder.set_content(file_content)
                media_type, encoding = mimetypes.guess_type(requested_file)
                builder.add_header("Content-Type", media_type)
                builder.add_header("Transfer-Encoding", "chunked")
                builder.set_status("200", "OK")
            elif int(number) == 4:
                # Case: Breakpoint Transmission
                file_size = os.path.getsize(requested_file)
                file_content = get_file_binary_contents(requested_file)
                file_size = len(file_content)
                if len(range) == 2:
                    if range[0] == "0-0" and range[1] == "-1":
                        first_byte = file_content[0:1]
                        last_byte = file_content[-1:]
                        temp = first_byte + last_byte
                        builder.set_content(temp)
                        media_type, encoding = mimetypes.guess_type(requested_file)
                        builder.add_header("Content-Type", media_type)
                        builder.add_header("Content-Length", str(2))
                        builder.add_header("Content-Range", f"bytes 0-0,-1/{file_size}")
                        builder.set_status("200", "OK")
                        if keep:
                            builder.add_header("Connection", "Keep-Alive")
                        else:
                            builder.add_header("Connection", "Close")
                        self.add_cookie(username, builder, has_cookie)
                        return builder.build(), keep
                for item in range:
                    if not self.checkRangeValid(item,file_size):
                        return self.Range_Not_Satisfiable(data, username, has_cookie)
                if len(range) == 1:
                    start,end = self.calculateRange(range[0])
                    if start == "-":
                        builder.set_content(file_content[-end:])
                        media_type, encoding = mimetypes.guess_type(requested_file)
                        builder.add_header("Content-Type", media_type)
                        builder.add_header("Content-Range", f"bytes -{end}/{file_size}")
                        builder.add_header("Content-Length", str(end))
                        builder.set_status("206", "Partial Content")
                    elif end == "-":
                        temp = file_size - start
                        builder.set_content(file_content[-temp:])
                        media_type, encoding = mimetypes.guess_type(requested_file)
                        builder.add_header("Content-Type", media_type)
                        builder.add_header("Content-Range", f"bytes {start}-/{file_size}")
                        builder.add_header("Content-Length", str(file_size-start))
                        builder.set_status("206", "Partial Content")
                    else:
                        builder.set_content(file_content[start:end+1])
                        media_type, encoding = mimetypes.guess_type(requested_file)
                        builder.add_header("Content-Type", media_type)
                        builder.add_header("Content-Range", f"bytes {start}-{end}/{file_size}")
                        builder.add_header("Content-Length", str(end-start+1))
                        builder.set_status("206", "Partial Content")
                else:
                    builder.add_header("Content-Type", "multipart/byteranges; boundary=3d6b6a416f9b5")
                    tempContent = b''
                    media_type, encoding = mimetypes.guess_type(requested_file)
                    for item in range:
                        start, end = self.calculateRange(item)
                        if start == "-":
                            tempContent += b'--3d6b6a416f9b5\r\n'
                            tempContent += b'Content-Type: ' + media_type.encode() + b'\r\n'
                            tempContent += b'Content-Range: bytes -' + str(end).encode() + b'/' + str(file_size).encode() + b'\r\n'
                            tempContent += b'\r\n'
                            tempContent += file_content[-end:]
                            tempContent += b'\r\n'

                        elif end == "-":
                            temp = file_size - start
                            tempContent += b'--3d6b6a416f9b5\r\n'
                            tempContent += b'Content-Type: ' + media_type.encode() + b'\r\n'
                            tempContent += b'Content-Range: bytes ' + str(start).encode() + b'-/' + str(file_size).encode() + b'\r\n'
                            tempContent += b'\r\n'
                            tempContent += file_content[-temp:]
                            tempContent += b'\r\n'

                        else:
                            tempContent += b'--3d6b6a416f9b5\r\n'
                            tempContent += b'Content-Type: ' + media_type.encode() + b'\r\n'
                            tempContent += b'Content-Range: bytes ' + str(start).encode() + b'-' + str(end).encode() + b'/' + str(file_size).encode() + b'\r\n'
                            tempContent += b'\r\n'
                            tempContent += file_content[start:end + 1]
                            tempContent += b'\r\n'

                    tempContent += b'--3d6b6a416f9b5--\r\n'
                    print(tempContent.decode("utf-8"))
                    builder.set_content(tempContent)
                    builder.add_header("Content-Length", str(len(tempContent)))
                    builder.set_status("206", "Partial Content")
            if keep:
                builder.add_header("Connection", "Keep-Alive")
            else:
                builder.add_header("Connection", "Close")
            self.add_cookie(username, builder, has_cookie)
            return builder.build(), keep

    def get_directory_content(self, directory):
        content = []
        for item in os.listdir(directory):
            item_path = os.path.join(directory, item)
            if os.path.isdir(item_path):
                content.append(item + "/")
            else:
                content.append(item)
        return json.dumps(content)

    def get_directory_html(self, directory, username):
        password = self.auth[username]
        temp = username + ":" + password
        encoded_bytes = temp.encode("utf-8")
        Authorization = base64.b64encode(encoded_bytes).decode("utf-8")

        content = ("<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">" +
                   "<title>Directory listing for" + directory + "</title></head><body>")
        content += ("<h1>Directory listing for" + directory + "</h1><hr><ul>")
        result = directory.split("/", 2)[2] if directory.count("/") > 1 else ""

        # Add link for the parent directory
        if directory.count("/") > 1:
            parent_directory = '/'.join(directory.split("/")[:-1])
            if parent_directory == self.working_dir:
                request_parent = f'http://localhost:8080/'
            else:
                request_parent = f'http://localhost:8080/{"/".join(result.split("/")[:-1])}/'
            content += f"""
                         <li><a href="#" onclick="sendGetRequest('{request_parent}')">./</a></li>
                        """

        request_root = f'http://localhost:8080/'
        content += f"""
                        <li><a href="#" onclick="sendGetRequest('{request_root}')">../</a></li>
                    """
        for item in os.listdir(directory):
            temp = directory + "/" + f"{item}"
            if os.path.isdir(temp):
                request = f'http://localhost:8080/{result}/{item}'
                content += f"""
                                            <li><a href="#" onclick="sendGetRequest('{request}')">{item}/</a></li>
                                            """
            else:
                request = f'http://localhost:8080/{result}/{item}'
                content += f"""
                                            <li><a href="#" onclick="sendGetRequest('{request}')">{item}</a></li>
                                            """
        content += "</ul><hr><script>"
        content += '''
                    function sendGetRequest(request) {
                        var xhr = new XMLHttpRequest();
                        xhr.open("GET", request, true);
                    '''

        content += f'''
                        xhr.setRequestHeader("Authorization", "Basic {Authorization}");
                    '''
        content += '''
                        xhr.setRequestHeader("Connection", "Keep-Alive");
                        xhr.onreadystatechange = function () {
                            if (xhr.readyState === 4 && xhr.status === 200) {
                                console.log(xhr.responseText);
                            }
                        };
                        xhr.send();
                    }
                    '''
        content += "</script></body></html>"
        return content

    # TODO: Write the response to a POST request
    def post_request(self, number, requested_file, data, username, raw_data, has_cookie):
        keep = self.check_keep(data)
        builder = ResponseBuilder()
        if int(number) == 1:
            if not os.path.isdir(requested_file):
                return self.bad_request(data, username, has_cookie)
            boundary = ""
            for line in data:
                if line.strip():
                    if line.split()[0] == "Content-Type:":
                        boundary = line.split()[2].split("=")[1]
                        break

            sections = "".join(raw_data).split("--" + boundary)
            fileInfo = sections[1]
            # print(fileInfo)
            match = re.search(r'filename="(.+?)"', fileInfo)

            if match:
                filename = match.group(1)
                parts = fileInfo.split(filename)
                # print(parts)
                fileContent = parts[1]
                fileContent = fileContent[5:]
                fileContent = fileContent.replace("\r\n", "\n")
                # print(fileContent)
                filePath = requested_file + "/" + filename
                try:
                    with open(filePath, 'x') as file:
                        file.write(fileContent)
                except FileExistsError:
                    print(f"File '{filePath}' already exists. Choose a different file name.")
                    return self.bad_request(data, username, has_cookie)
        if int(number) == 2:
            if os.path.isdir(requested_file):
                return self.bad_request(data, username, has_cookie)
            os.remove(requested_file)
        builder.set_status("200", "OK")
        if keep:
            builder.add_header("Connection", "Keep-Alive")
        else:
            builder.add_header("Connection", "Close")
        builder.add_header("Content-Type", mime_types["html"])
        builder.set_content(get_file_contents("post.html"))
        builder.add_header("Content-Length", len(get_file_contents("post.html")))
        self.add_cookie(username, builder, has_cookie)
        return builder.build(), keep

    def need_authorized(self, data):
        keep = self.check_keep(data)
        builder = ResponseBuilder()
        builder.set_status("401", "Unauthorized")
        builder.add_header("WWW-Authenticated", "Basic realm=\"Authorization Required\"")
        if keep:
            builder.add_header("Connection", "Keep-Alive")
        else:
            builder.add_header("Connection", "Close")
        builder.add_header("Content-Type", "text/html")
        builder.add_header("Content-Length", len(get_file_contents("401.html")))
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
        builder.add_header("Content-Type", "text/html")
        builder.add_header("Content-Length", len(get_file_contents("401.html")))
        builder.set_content(get_file_contents("401.html"))
        return builder.build(), keep

    def method_not_allowed(self, data, username, has_cookie):
        keep = self.check_keep(data)
        builder = ResponseBuilder()
        builder.set_status("405", "METHOD NOT ALLOWED")
        allowed = ", ".join(["GET", "POST"])
        builder.add_header("Allow", allowed)
        builder.set_content("")
        if keep:
            builder.add_header("Connection", "Keep-Alive")
        else:
            builder.add_header("Connection", "Close")
        self.add_cookie(username, builder, has_cookie)
        builder.add_header("Content-Type", "text/plain")
        builder.add_header("Content-Length", 0)
        return builder.build(), keep

    def resource_not_found(self, data, username, has_cookie):
        keep = self.check_keep(data)
        builder = ResponseBuilder()
        builder.set_status("404", "NOT FOUND")
        if keep:
            builder.add_header("Connection", "Keep-Alive")
        else:
            builder.add_header("Connection", "Close")
        builder.add_header("Content-Type", mime_types["html"])
        builder.set_content(get_file_contents("404.html"))
        self.add_cookie(username, builder, has_cookie)
        builder.add_header("Content-Type", "text/html")
        builder.add_header("Content-Length", len(get_file_contents("404.html")))
        return builder.build(), keep

    # TODO: Make a function that handles forbidden error
    def resource_forbidden(self, data, username, has_cookie):
        keep = self.check_keep(data)
        builder = ResponseBuilder()
        builder.set_status("403", "FORBIDDEN")
        if keep:
            builder.add_header("Connection", "Keep-Alive")
        else:
            builder.add_header("Connection", "Close")
        builder.add_header("Content-Type", mime_types["html"])
        builder.set_content(get_file_contents("403.html"))
        self.add_cookie(username, builder, has_cookie)
        builder.add_header("Content-Type", "text/html")
        builder.add_header("Content-Length", len(get_file_contents("403.html")))
        return builder.build(), keep

    def bad_request(self, data, username, has_cookie):
        keep = self.check_keep(data)
        builder = ResponseBuilder()
        builder.set_status("400", "Bad Request")
        if keep:
            builder.add_header("Connection", "Keep-Alive")
        else:
            builder.add_header("Connection", "Close")
        builder.add_header("Content-Type", mime_types["html"])
        builder.set_content(get_file_contents("400.html"))
        self.add_cookie(username, builder, has_cookie)
        builder.add_header("Content-Length", len(get_file_contents("400.html")))
        return builder.build(), keep

    def Range_Not_Satisfiable(self, data, username, has_cookie):
        keep = self.check_keep(data)
        builder = ResponseBuilder()
        builder.set_status("416", "Range Not Satisfiable")
        if keep:
            builder.add_header("Connection", "Keep-Alive")
        else:
            builder.add_header("Connection", "Close")
        builder.add_header("Content-Type", mime_types["html"])
        builder.set_content(get_file_contents("416.html"))
        self.add_cookie(username, builder, has_cookie)
        builder.add_header("Content-Length", len(get_file_contents("401.html")))
        return builder.build(), keep


class ResponseBuilder:
    def __init__(self):
        self.headers = []
        self.status = None
        self.content = None

    def add_header(self, headerKey, headerValue):
        self.headers.append(f"{headerKey}: {headerValue}")

    def add_cors_headers(self):
        """添加CORS头到响应中"""
        self.add_header("Access-Control-Allow-Origin", "*")  # 允许来自任何来源的请求
        self.add_header("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS")  # 允许特定的HTTP方法
        self.add_header("Access-Control-Allow-Headers", "Content-Type,Authorization,Range,Content-Length")  # 允许特定的头部

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
        self.add_cors_headers()
        for i in self.headers:
            response += i
            response += CRLF
        response += CRLF

        if self.content != "":
            # Check if chunked transfer encoding is used
            if "Transfer-Encoding: chunked" in self.headers:
                response = response.encode("utf-8")
                chunk_size= 10
                if len(self.content) > 1000:
                    chunk_size = 1000

                chunks = [self.content[i:i + chunk_size] for i in range(0, len(self.content), chunk_size)]
                for chunk in chunks:
                    chunk_size_hex = hex(len(chunk))[2:]  # Convert to hexadecimal
                    response += chunk_size_hex.encode("utf-8") + CRLF.encode("utf-8")
                    response += chunk + CRLF.encode("utf-8")

                # Add the last chunk with size 0 to indicate the end
                response += b"0" + CRLF.encode("utf-8") + CRLF.encode("utf-8")
            else:
                # If not using chunked transfer encoding, add the entire content
                response = response.encode("utf-8")
                response += self.content
        return response

def main():
    parser = argparse.ArgumentParser(description="A simple HTTP server.")
    parser.add_argument("-i", "--host", type=str, default="localhost", help="The host to serve on.")
    parser.add_argument("-p", "--port", type=int, default=8080, help="The port to listen on.")
    parser.add_argument("-d", "--directory", type=str, default="./data", help="The directory to serve.")
    args = parser.parse_args()
    HTTPServer(args.host, args.port, args.directory)


if __name__ == "__main__":
    main()