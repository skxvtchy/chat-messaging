class Request:

    def __init__(self, request: bytes):
        # TODO: parse the /bytes of the request and populate the following instance variables
        
        body = request.split(b"\r\n\r\n",1)
        stuff = body[0].decode().split("\r\n")

        first = stuff[0].split()

        self.body = body[1]
        self.method = first[0]
        self.path = first[1]
        self.http_version = first[2]
        self.headers = {}
        self.cookies = {}
        
        for head in range(1, len(stuff)):
            things = stuff[head].split(":",1)

            if things[0] == "Cookie":
                cookie_id = things[1].split(";")
                for ids in cookie_id:
                    cookie_stuff = ids.strip()
                    cookie_stuff = cookie_stuff.split("=")
                    self.cookies[cookie_stuff[0]] = cookie_stuff[1]
            self.headers[things[0].strip()] =  things[1].strip()
        
        # print(self.body)
        # print(self.method)
        # print(self.path)
        # print(self.http_version)
        # print(self.headers)
        # print(self.cookies)


def test1():
    request = Request(b'GET / HTTP/1.1\r\nHost: localhost:8080\r\nConnection: keep-alive\r\n\r\n')
    assert request.method == "GET"
    assert "Host" in request.headers
    assert request.headers["Host"] == "localhost:8080"  # note: The leading space in the header value must be removed
    assert request.body == b""  # There is no body for this request.
    # When parsing POST requests, the body must be in bytes, not str

    # This is the start of a simple way (ie. no external libraries) to test your code.
    # It's recommended that you complete this test and add others, including at least one
    # test using a POST request. Also, ensure that the types of all values are correct

    print("Passed")

def test2():
    request = Request(b'GET / HTTP/1.1\r\nHost: localhost:8080\r\nCookie: id=1; id2=2;id3=3\r\nConnection: keep-alive\r\n\r\n')
    assert request.method == "GET"
    assert "Host" in request.headers
    assert request.headers["Host"] == "localhost:8080"  # note: The leading space in the header value must be removed
    assert request.body == b""  # There is no body for this request.
    # When parsing POST requests, the body must be in bytes, not str
    # print(request.headers)
    # This is the start of a simple way (ie. no external libraries) to test your code.
    # It's recommended that you complete this test and add others, including at least one
    # test using a POST request. Also, ensure that the types of all values are correct
    # print(request.path)
    # print(request.headers)
    # print(request.body)
    print("Passed")

def test3():
    request = Request(b'POST /form-path HTTP/1.1\r\nContent-Length: 10000\r\nContent-Type: multipart/form-data; boundary=----thisboundary\r\n\r\n------thisboundary\r\nContent-Disposition: form-data; name="commenter"\r\n\r\nJesse\r\n------thisboundary\r\nContent-Disposition: form-data; name="upload"; filename="cat.png"\r\nContent-Type: image/png\r\n\r\n<bytes_of_file>\r\n------thisboundary--')
    assert request.method == "POST"
    assert "Host" in request.headers
    assert request.headers["Host"] == "localhost:8080"  # note: The leading space in the header value must be removed
    assert request.body == b""

if __name__ == '__main__':
    # test1()
    test2()
    # test3()
   