import re

def extract_credentials(request):
    credentials = []
    
    # login = request.body.decode('ascii').split("&", 1)

    decode = ''
    i = 0
    length = len(request.body.decode('ascii'))

    while i < length :
        if request.body.decode('ascii')[i] == '%':
            if i + 2 < length:
                hex_thing = request.body.decode('ascii')[i+1:i+3]
                hex_to_dec = int(hex_thing, 16)
                decode += chr(hex_to_dec)
                i += 3
        else:
            decode += request.body.decode('ascii')[i]
            i += 1
    
    login = decode.split("&", 1)
    
    username = login[0].split("=", 1)
    password = login[1].split("=", 1)

    username = username[1]
    password = password[1]    
    
    credentials.append(username)
    credentials.append(password)

    return credentials

def validate_password(password:str):
    
    special =  {'!', '@', '#', '$', '%', '^', '&', '(', ')', '-', '_', '='}
    
    count = len(password)
    upperflag=0
    lowerflag=0
    specialflag=0
    numberflag=0
    invalidflag=0

    for char in password:
        if char.isupper():
            upperflag = 1
        elif char.islower():
            lowerflag = 1
        elif char.isdigit():
            numberflag = 1
        elif char in special:
            specialflag = 1
        else:
            invalidflag = 1
            break 

    flags = upperflag + lowerflag + specialflag + numberflag
    if count >= 8 and flags == 4 and invalidflag == 0:
        return True
    
    else:
        return False


def test_validate(password):
    print(validate_password(password))

if __name__ == '__main__':
    test_validate("abcdefghijklmnop")
    test_validate("1#oP4")
    test_validate("123415167")
    test_validate("12np3)n+")
    test_validate("12np3)Nsdf3")
    test_validate("12np3)Fs")


