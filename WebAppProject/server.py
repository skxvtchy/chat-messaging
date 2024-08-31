import socketserver
from util.request import Request
from util.router import Router
from util.auth import extract_credentials, validate_password
from util.multipart import parse_multipart
from util.websockets import compute_accept, generate_ws_frame, parse_ws_frame

import bcrypt
import secrets
import hashlib
import os

import json
from pymongo import MongoClient
from bson.objectid import ObjectId
import uuid

mongo_client = MongoClient("localhost")
# mongo_client = MongoClient("mongo")
db = mongo_client["cse312"]
chat_collection = db["chat"]
user_collection = db["user"]
auth_collection = db["auth"]
xsrf_collection = db["xsrf"]
clients = []
user_names = []


def readbytes(files, request, cookies):
    # nosniff = b"X-Content-Type-Options: nosniff\r\n"
    # header = b"HTTP/1.1 "
    # status = b"200 OK\r\nContent-Type: "
    # content_type = "\r\n"
    # content_length = "Content-Length: "

    response=b"HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\n"
    # response+=b""

    # file_type={b"/public/style.css": b"text/css; charset=utf-8", b"/public/functions.js": b"text/javascript; charset=utf-8",
    #             b"/public/webrtc.js": b"text/javascript; charset=utf-8", b"/public/favicon.ico": b"image/vnd.microsoft.icon", 
    #             b"/": b"text/html; charset=utf-8", b"/public/image/eagle.jpg": b"image/jpeg", b"/public/image/cat.jpg": b"image/jpeg",
    #             b"/public/image/dog.jpg": b"image/jpeg", b"/public/image/elephant.jpg": b"image/jpeg",b"/public/image/elephant-small.jpg": b"image/jpeg", b"/public/image/flamingo.jpg": b"image/jpeg",
    #             b"/public/image/kitten.jpg": b"image/jpeg" }
    
    cooky = ""

    file_type= {
    b'.css': b'text/css; charset=utf-8',
    b'.js': b'text/javascript; charset=utf-8',
    b'.ico': b'image/vnd.microsoft.icon',
    b'.jpg': b'image/jpeg',
    b'.html': b'text/html; charset=utf-8',
    b'/' : b'text/html; charset=utf-8',
    b'.mp4' : b'video/mp4;',
    b'.png' : b'image/png; charset=utf-8',
    b'.gif' : b'image/gif; charset=utf-8',
}

    if request.encode() == b'/':
        types = file_type.get(b'/')
    else:
        extension = b'.' + request.encode().split(b'.')[-1]
        types = file_type.get(extension)  
 
    # types = file_type.get(request.encode())



    if types !=None:
        content_type = b"Content-Type: " + types + b"\r\n" 

        if files == "/":
            files = "public/index.html"
            cooky=str(int(cookies.get("visited","0"))+1)
            response += b"Set-Cookie: visited=" + cooky.encode() + b"; Max-Age=3600\r\n"
            
        with open("./" + files, "rb") as file:
            
            content = file.read()
            content = content.replace(b"{{visits}}",cooky.encode())

            token_cooky = cookies.get("token")
            
            user = "Guest"
            if token_cooky != None:
                
                find_token = auth_collection.find_one({"token":hashlib.sha256(token_cooky.encode()).hexdigest()})
                if find_token != None:
                    user=find_token["username"]

            token = secrets.token_hex()
            xsrf_collection.insert_one({"username":user, "xsrf":token})
            
            content = content.replace(b"{{xsrf}}",token.encode())

            stuff_len = str(len(content))
            response += content_type + b"Content-Length: " + stuff_len.encode() + b"\r\n\r\n" + content
            
        return response
    else:
        return b'HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 21\r\n\r\nContent Was Not Found'

def route_one(request):
    # if received_data != b"":
    #     request = Request(received_data)
        files = request.path
        if request.method == "GET":
            
            # body = json.loads(request.body)
            if "/chat-messages/" in files:
                stripped = request.path.split("/")
                ids = stripped[len(stripped)-1]
                chat = chat_collection.find_one({"_id":ObjectId(ids)})


                if chat==None:
                    response = b'HTTP/1.1 404 Not Found\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 21\r\n\r\nContent Was Not Found'
                    # self.request.sendall(response.encode("utf-8"))
                    return response.encode("utf-8")
                else:
                    # body = json.loads(request.body)
                
                    dicts = {}
                    
                    dicts["username"]=chat["username"]
                    dicts["message"]=chat["message"]
                    dicts["id"]=str(chat["_id"])

                    length_json = str(len(json.dumps(dicts)))
                    
                    response = "HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain ;charset=utf-8\r\nContent-Length: " + length_json + "\r\n\r\n" +json.dumps(dicts)
                    # self.request.sendall(response.encode("utf-8"))
                    return response.encode("utf-8")
                
            elif "/chat-messages" in files:
                list1 = []
                for i in chat_collection.find({}):
                    dicts = {}
                    
                    dicts["username"]=i.get("username", "guest")
                    dicts["message"]=i.get("message", "error")
                    dicts["id"]=str(i.get("_id", "id_default"))
                    
                    list1.append(dicts)

                length_json = str(len(json.dumps(list1)))
                response = "HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain ;charset=utf-8\r\nContent-Length: " + length_json + "\r\n\r\n" +json.dumps(list1)
                
                # self.request.sendall(response.encode("utf-8"))
                return response.encode("utf-8")

            else:
                output = readbytes(files, request.path, request.cookies)
                # self.request.sendall(output)

                return output

        elif request.method == "POST":

            body = json.loads(request.body)
            body["username"] = "Guest"

            token_cooky = request.cookies.get("token")
            if token_cooky != None:
                
                find_token = auth_collection.find_one({"token":hashlib.sha256(token_cooky.encode()).hexdigest()})
                if find_token != None:
                    body["username"]=find_token["username"]
            
            xsrf = body["xsrf"]
            if body["username"] != "Guest":
                xsrf_token = xsrf_collection.find_one({"xsrf":xsrf})
                if xsrf_token == None or xsrf_token["username"]!=body["username"]:
                    return b'HTTP/1.1 403\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain\r\nContent-Length: 8\r\n\r\nrejected'

            # body["id"] = "1"

            body["message"] = body['message'].replace("&", "&amp")
            body["message"] = body['message'].replace("<", "&lt")
            body["message"] = body['message'].replace(">", "&gt")

            insert_chat = chat_collection.insert_one(body)
            # insert_chat.inserted_id

            dicts = {"message": body["message"], "username": body["username"], "id": str(insert_chat.inserted_id)}

            response = 'HTTP/1.1 201 Created\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain\r\nContent-Length: 7\r\n\r\nawesome'
            # self.request.sendall(response.encode("utf-8"))
            return response.encode("utf-8")
            # pass
        elif request.method == "DELETE":
            user="Guest"
            
            token_cooky = request.cookies.get("token")
            if token_cooky != None:
                
                find_token = auth_collection.find_one({"token":hashlib.sha256(token_cooky.encode()).hexdigest()})
                if find_token != None:
                    user=find_token["username"]

            if "/chat-messages/" in files:
                stripped = request.path.split("/")
                ids = stripped[len(stripped)-1]

                delete_chat = chat_collection.find_one({"_id":ObjectId(ids)})
                
                
                if delete_chat != None:
                    if user == delete_chat["username"]:
                        delete_chat = chat_collection.find_one_and_delete({"_id":ObjectId(ids)})

                        response = b'HTTP/1.1 204 No Content\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 0\r\n\r\n'
                    # self.request.sendall(response)
                        return response

                
                response = b'HTTP/1.1 403\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 0\r\n\r\n'
                    # self.request.sendall(response)
                return response

        elif request.method == "PUT":
            if "/chat-messages/" in files:
                stripped = request.path.split("/")
                ids = stripped[len(stripped)-1]

                update_chat = chat_collection.find_one_and_update({"_id":ObjectId(ids)},{"$set":{"username":"Jesse","message":"Welcome to CSE312!"}})

                if update_chat != None:
                    
                    dicts = {}
                        
                    dicts["username"]="Jesse"
                    dicts["message"]="Welcome to CSE312!"
                    dicts["id"]=ids

                    length_json = str(len(json.dumps(dicts)))
                    response = "HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain ;charset=utf-8\r\nContent-Length: " + length_json + "\r\n\r\n" +json.dumps(dicts)
                    # self.request.sendall(response.encode("utf-8"))
                    return response.encode("utf-8")

                else:
                    response = b'HTTP/1.1 404 Not Found\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 21\r\n\r\nContent Was Not Found'
                    # self.request.sendall(response)
                    return response   

def register(request):
    cred = extract_credentials(request)
    user = cred[0]
    password = cred[1]

    # user_collection = db["user"]
    # auth_collection = db["user"]

    insert = user_collection.find_one({"username": user})

    if insert == None and validate_password(password): 
        salt = bcrypt.gensalt()
        hashy = bcrypt.hashpw(password.encode(), salt)
        user_collection.insert_one({"username": user, "salt": salt, "hash": hashy})
        response = b'HTTP/1.1 302 Found Redirect\r\nLocation: /\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 0\r\n\r\n'
    else:
        response = b'HTTP/1.1 302 Found Redirect\r\nLocation: /\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 0\r\n\r\n'
    return response

def login(request):
    cred = extract_credentials(request)
    user = cred[0]
    password = cred[1]

    insert = user_collection.find_one({"username": user})

    cred = extract_credentials(request)
    if insert != None and validate_password(password): 
        # user_collection.insert_one({"username": user, "salt": salt, "hash": hashy})
        
        compare_pass = bcrypt.hashpw(password.encode(), insert["salt"])
        if compare_pass == insert["hash"]:
            token = secrets.token_hex()
            auth_collection.insert_one({"username":user,"token":hashlib.sha256(token.encode()).hexdigest()})
            
        response = b'HTTP/1.1 302 Found Redirect\r\nSet-Cookie: token='+ token.encode() + b'; Max-Age=3600; HTTPOnly;\r\nLocation: /\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 0\r\n\r\n'
    else:
        response = b'HTTP/1.1 302 Found Redirect\r\nLocation: /\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 0\r\n\r\n'
    return response

def logout(request):
    token = request.cookies.get("token")
    if token!=None:
        token = auth_collection.find_one_and_delete({"token":hashlib.sha256(token.encode()).hexdigest()})
        response = response = b'HTTP/1.1 302 Found Redirect\r\nLocation: /\r\nSet-Cookie: token=invalid; Max-Age=0;\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 0\r\n\r\n'
        return response
    
def upload(request):

    # parsed_data = parse_multipart(bytes(request_body))
    # content = parsed_data.parts[1].content
    # request.headers('Content-Length: ')
            # request.body
    # print(request.path)

    parsed_data = parse_multipart(request)
    for part in parsed_data.parts:
        if ('Content-Type' in part.headers):
            # if 'image/jpeg' in part.headers['Content-Type']:
            if part.content.startswith(b'\xFF\xD8\xFF'):
                content = parsed_data.parts[0].content

                unique_id = uuid.uuid4().hex
                filename = f'{unique_id}.jpg'

                directory = 'public/image'
                filepath = os.path.join(directory, filename)

                with open(filepath, 'wb') as file:
                    file.write(content)

                user = 'Guest'

                token_cooky = request.cookies.get("token")
                if token_cooky != None:
                            
                    find_token = auth_collection.find_one({"token":hashlib.sha256(token_cooky.encode()).hexdigest()})
                    if find_token != None:
                        user = find_token["username"]

                chat = f'<img src="./public/image/{filename}" />'
                chat_collection.insert_one({"username": user, "message": chat})

                response = b'HTTP/1.1 302 Found Redirect\r\nLocation: /\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 0\r\n\r\n'
                return response
            
            # elif 'video/mp4' in part.headers['Content-Type']:
            elif 'video/mp4' in part.headers['Content-Type']:
                content = parsed_data.parts[0].content

                unique_id = uuid.uuid4().hex
                filename = f'{unique_id}.mp4'

                directory = 'public/image'
                filepath = os.path.join(directory, filename)

                with open(filepath, 'wb') as file:
                    file.write(content)

                

                user = 'Guest'

                token_cooky = request.cookies.get("token")
                if token_cooky != None:
                            
                    find_token = auth_collection.find_one({"token":hashlib.sha256(token_cooky.encode()).hexdigest()})
                    if find_token != None:
                        user = find_token["username"]

                chat = f'<video controls><source src="./public/image/{filename}" type="video/mp4"></video>'
                chat_collection.insert_one({"username": user, "message": chat})

                response = b'HTTP/1.1 302 Found Redirect\r\nLocation: /\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 0\r\n\r\n'
                return response
            
            # elif 'image/png' in part.headers['Content-Type']:
            elif part.content.startswith(b'\x89PNG\r\n\x1A\n'):

                content = parsed_data.parts[0].content

                unique_id = uuid.uuid4().hex
                filename = f'{unique_id}.png'

                directory = 'public/image'
                filepath = os.path.join(directory, filename)

                with open(filepath, 'wb') as file:
                    file.write(content)

                user = 'Guest'

                token_cooky = request.cookies.get("token")
                if token_cooky != None:
                            
                    find_token = auth_collection.find_one({"token":hashlib.sha256(token_cooky.encode()).hexdigest()})
                    if find_token != None:
                        user = find_token["username"]

                chat = f'<img src="./public/image/{filename}" />'
                chat_collection.insert_one({"username": user, "message": chat})

                response = b'HTTP/1.1 302 Found Redirect\r\nLocation: /\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 0\r\n\r\n'
                return response
            
            # elif 'image/gif' in part.headers['Content-Type']:
            elif part.content.startswith(b'GIF87a') or part.content.startswith(b'GIF89a'):
                content = parsed_data.parts[0].content

                unique_id = uuid.uuid4().hex
                filename = f'{unique_id}.gif'

                directory = 'public/image'
                filepath = os.path.join(directory, filename)

                with open(filepath, 'wb') as file:
                    file.write(content)

                user = 'Guest'

                token_cooky = request.cookies.get("token")
                if token_cooky != None:
                            
                    find_token = auth_collection.find_one({"token":hashlib.sha256(token_cooky.encode()).hexdigest()})
                    if find_token != None:
                        user = find_token["username"]

                chat = f'<img src="./public/image/{filename}" />'
                chat_collection.insert_one({"username": user, "message": chat})

                response = b'HTTP/1.1 302 Found Redirect\r\nLocation: /\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 0\r\n\r\n'
                return response

def websocket(self,web_bytes):

    connection = Request(web_bytes).headers.get('Connection')
    upgrade = Request(web_bytes).headers.get('Upgrade')
    websocket_key = Request(web_bytes).headers.get('Sec-WebSocket-Key')

    # Authenticate user
    token_cookie = Request(web_bytes).cookies.get("token", None)
    username = "Guest"  # Default username
    if token_cookie:
        hashed_token = hashlib.sha256(token_cookie.encode()).hexdigest()
        user_record = auth_collection.find_one({"token": hashed_token})
        if user_record:
            username = user_record["username"]



    if connection == "Upgrade" and upgrade=='websocket' and websocket_key:
        
        accept = compute_accept(websocket_key)
      
        response_headers = [
                    "HTTP/1.1 101 Switching Protocols",
                    "Connection: Upgrade",
                    "Upgrade: websocket",
                    "Sec-WebSocket-Accept: " + accept
                ]

        self.request.sendall("\r\n".join(response_headers).encode('utf-8') + b"\r\n\r\n")

        clients.append(self.request)
        user_names.append(username)
        buffer = bytearray()


        user_message = {
                        'messageType': 'users',
                        'username': username
                    }
        
        duser_message = {
                        'messageType': 'dusers',
                        'username': username
                    }
    
        
        for i in clients: 
            users = generate_ws_frame(json.dumps(user_message).encode('utf-8'))
            if i != self.request:
                i.sendall(users)

        for bruh in user_names:
            user_message['username'] = bruh
            users = generate_ws_frame(json.dumps(user_message).encode('utf-8'))
            self.request.sendall(users)


        while True:
            if buffer==b'':
                frame_data = self.request.recv(2048) 
                # print(len(frame_data))
            else:
                # print("ojh")
                frame_data = buffer
                buffer = bytearray()

            if frame_data != b'':
                ws_bytes = frame_data

                second =  ws_bytes[1]
                payload_length = second & 0x7F
                
                if payload_length == 126:
                    payload_length = int.from_bytes(ws_bytes[2:4], byteorder='big')
                    payload_length += 2
                elif payload_length == 127:
                    payload_length = int.from_bytes(ws_bytes[2:10], byteorder='big')
                    payload_length += 8
                payload_length += 6
        

                if len(frame_data) != payload_length:
                    # print("bruh2")
                    while len(frame_data) < payload_length:
                        # print("bruh")
                        frame_data+=self.request.recv(2048)

                    if len(frame_data) > payload_length:
                        buffer=frame_data[payload_length:]
                        frame_data=frame_data[:payload_length+1]
                    
                    # size = parse_ws_frame(buffer).payload_length
                # print(len(frame_data))
                # print(payload_length)
                frame = parse_ws_frame(frame_data)

                if frame.opcode == 0x8:
                    # close = generate_ws_frame(b'', opcode=0x8)
                    for i in clients: 
                            dusers = generate_ws_frame(json.dumps(duser_message).encode('utf-8'))
                            if i != self.request:
                                i.sendall(dusers)

                    clients.remove(self.request)
                    user_names.remove(username)
                    return self.request.close()

                message = {}
                decoded = frame.payload
                message_data = json.loads(decoded.decode('utf-8'))
                message_data["message"] = (message_data['message']
                                        .replace("&", "&amp;")
                                        .replace("<", "&lt;")
                                        .replace(">", "&gt;"))
                
                if message_data.get('messageType') == 'chatMessage':
        
                    message = {
                        'messageType': 'chatMessage',
                        'username': username,
                        'message': message_data["message"],
                        'id': str(uuid.uuid4())  # Generate a unique ID for the message
                    }

                    chat_collection.insert_one({
                        "username": message['username'],
                        "message": message['message']
                    })

                    # user_list = list(user_names))
        
                    # for i in user_names:
                    #     frame = generate_ws_frame(json.dumps(user_message).encode('utf-8'))
                    #     i.sendall(frame)

                        # self.request.sendall(message)                    
                    for person in clients:
                    
                        messages = generate_ws_frame(json.dumps(message).encode('utf-8'))
                        person.sendall(messages)
            
                    
            
router = Router()
router.add_route("GET", "/$", route_one)
router.add_route("GET", "/public", route_one)
router.add_route("GET", "/chat-messages", route_one)
router.add_route("POST", "/chat-messages", route_one)
router.add_route("DELETE", "/chat-messages", route_one)
router.add_route("POST", "/login", login)
router.add_route("POST", "/register", register)
router.add_route("POST", "/logout", logout)
router.add_route("POST", "/upload", upload)
# router.add_route("GET", "/websocket", websocket)


# Abc123!!!

class MyTCPHandler(socketserver.BaseRequestHandler):
    

    def handle(self):
        received_data = self.request.recv(2048)
        print(self.client_address)
        print("--- received data ---")
        print(received_data)
        print("--- end of data ---\n\n")
        
    # TODO: Parse the HTTP request and use self.request.sendall(response) to send your response    

        # chat_collection.insert_one({"username": "James", "message": "please"})
        
        if Request(received_data).path == "/websocket":
            websocket(self, received_data)

        else:
            rec_data = received_data

            data = received_data.split(b'\r\n\r\n',1)
            
            headers = data[0]
            body = data[1] 

            content_length = 0
            for content in headers.split(b'\r\n'):
                if content.lower().startswith(b'content-length:'):
                    content_length = int(content.split(b':')[1].strip())

            total = len(body)


            while total < content_length:
                more = self.request.recv(2048)
                total += len(more)
                rec_data += more

            request = Request(rec_data)

            self.request.sendall(router.route_request(request))

        
    # request = headers + b'\r\n\r\n' + body
        # print(request)
        # print(rec_data)

        

        # self.request.sendall(router.route_request(Request(received_data)))

                                     

def main():
    host = "0.0.0.0"
    port = 8080

    socketserver.TCPServer.allow_reuse_address = True

    server = socketserver.ThreadingTCPServer((host, port), MyTCPHandler)

    print("Listening on port " + str(port))

    server.serve_forever()


if __name__ == "__main__":
    main()
