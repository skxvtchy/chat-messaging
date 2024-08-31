import re
# from util.request import Request
class Router:
    def __init__(self):
        self.routes = []
        self.error = b'HTTP/1.1 404 Not Found\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 21\r\n\r\nContent Was Not Found'
        
    # def function(self,request):
    #     pass


    def add_route(self, method, path, function):
        
     
        path_fix = re.compile('^' + path)        
        self.routes.append({"method": method, "path": path_fix, "function": function})
 
    def route_request(self, request):
        
        # if request.method in self.routes:
        #     for path, function in self.routes[request.method]:
        #         if path.match(request.path):
        #             return function(request)
                
        # else:
        #     self.request.sendall(self.error)

        for i in self.routes:
            if i['method'] == request.method and i['path'].match(request.path):
                function = i['function']
                return function(request)
            
        return self.error

