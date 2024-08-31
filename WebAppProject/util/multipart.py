# from request import Request

def parse_multipart(request):

    class multipart:
        def __init__(self, boundary, parts):
            
            self.boundary = boundary
            self.parts = parts
            
    class parts:
        def __init__(self,  headers, name, content):
            self.headers = headers
            self.name = name
            self.content = content

    boundary = ''
    part = []
    
    contents = request.headers['Content-Type']

    length_bound = len("boundary=")
    bound_idx = contents.find("boundary=")

    if bound_idx != -1:
        idx_parts = length_bound + bound_idx
        boundary = contents[idx_parts:]

    bound_headers = request.body.split(b'--'+boundary.encode())

    for heads in bound_headers[1:len(bound_headers)-1]:
        headers = {}
        name = ''
        content = ''

 
        stuff = heads.split(b"\r\n\r\n",1)
        
        heady = stuff[0].split(b":")
        
        # print(heady)
        # for j in range(0,len(heady),2):
        #     for i in range(1,len(heady),2):
        #         headers[heady[i].strip().decode()] = heady[j].strip().decode()
        head_kill = stuff[0].split(b"\r\n")
        # header_list = {}
        for j in head_kill:
            head_split = j.decode().split('\r\n')
            # print(head_split)
            for x in head_split:
                if x != '':
                    wow = x.split(':')
                    # print(wow)
                    # print(head_split)
                    headers[wow[0].strip()]=wow[1].strip()
        

        content = stuff[1][:len(stuff[1])-2]
        # print(content)

        idx_name = stuff[0].find(b"name=")
        len_name = len(b"name=")
        name_parts = idx_name + len_name

        # print(name_parts)
        name = stuff[0][name_parts+1:len(stuff[0])-1].split(b'"')[0]
        
        part.append(parts(headers,name.decode(),content))
        
    # print(part)
    # print(boundary)

    return multipart(boundary, part)

test = b'POST /form-path HTTP/1.1/\r\nContent-Length: 9937\r\nContent-Type: multipart/form-data; boundary=----WebKitFormBoundarycriD3u6M0UuPR1ia\r\n\r\n------WebKitFormBoundarycriD3u6M0UuPR1ia\r\nContent-Disposition: form-data; name="commenter"\r\n\r\nJesse\r\n------WebKitFormBoundarycriD3u6M0UuPR1ia\r\nContent-Disposition: form-data; name="upload"; filename="discord.png"\r\nContent-Type: image/png\r\n\r\n<bytes_of_the_file>\r\n------WebKitFormBoundarycriD3u6M0UuPR1ia--'
# re = Request(test)
# print(re.body)
# print(re.headers)
# parsed = parse_multipart(re)

# print(parsed.parts[0].name)
# print(parsed.parts[0].headers)
# print(parsed.parts[0].content)
# print(parsed.parts[1].name)
# print(parsed.parts[1].headers)
# print(parsed.parts[1].content)