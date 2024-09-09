import socket
import random
import pickle
import hashlib 
import uuid
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64


#curve configuration
# y^2 = x^3 + a*x + b = y^2 = x^3 + 7
a = 0; b = 7

#base point
G=(55066263022277343669578718895168534326250603453777594175500187360389116729240,32670510020758816978083085130507043184471273380659243275938904335757337482424)
 
#finite field
p = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
SK1=[]
DID1=[]

def add_points(P, Q, p):
    x1, y1 = P
    x2, y2 = Q
     
    if x1 == x2 and y1 == y2:
        beta = (3*x1*x2 + a) * pow(2*y1, -1, p)
    else:
        beta = (y2 - y1) * pow(x2 - x1, -1, p)
     
    x3 = (beta*beta - x1 - x2) % p
    y3 = (beta * (x1 - x3) - y1) % p
     
    is_on_curve((x3, y3), p)
         
    return x3, y3
 
def is_on_curve(P, p):
    x, y = P
    assert (y*y) % p == ( pow(x, 3, p) + a*x + b ) % p
     
def apply_double_and_add_method(G, k, p):
    target_point = G
     
    k_binary = bin(k)[2:] #0b1111111001
     
    for i in range(1, len(k_binary)):
        current_bit = k_binary[i: i+1]
         
        # doubling - always
        target_point = add_points(target_point, target_point, p)
         
        if current_bit == "1":
            target_point = add_points(target_point, G, p)
     
    is_on_curve(target_point, p)
     
    return target_point



# Generate a symmetric key from the shared secret key Sk
def generate_symmetric_key(Sk):
    # Convert the tuple of integers to bytes
    key_bytes = b''.join(x.to_bytes((x.bit_length() + 7) // 8, 'big') for x in Sk)
    
    # Hash the key bytes using SHA-256 and take the first 32 bytes as the key
    key_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    key_hash.update(key_bytes)
    hashed_key = key_hash.finalize()[:32]
    
    # Encode the key in base64 for Fernet
    base64_encoded_key = base64.urlsafe_b64encode(hashed_key)
    
    return base64_encoded_key


# Encrypt the DIDi using the symmetric key
def encrypt_didi(DIDi, Sk):
    symmetric_key = generate_symmetric_key(Sk)
    fernet = Fernet(symmetric_key)
    encrypted_didi = fernet.encrypt(bytes(str(DIDi), 'utf-8'))
    return encrypted_didi

# Decrypt the encrypted DIDi using the symmetric key
def decrypt_didi(encrypted_didi, Sk):
    symmetric_key = generate_symmetric_key(Sk)
    fernet = Fernet(symmetric_key)
    decrypted_didi = fernet.decrypt(encrypted_didi)
    return decrypted_didi.decode('utf-8')

def generate_keys():
    kb = random.getrandbits(128)
    Qb = apply_double_and_add_method(G = G, k = kb, p = p)
    return kb,Qb

def gen_points():
    kb = random.getrandbits(128)
    Qb = apply_double_and_add_method(G = G, k = kb, p = p)
    return Qb

def calculate_shared_key(Qa,kb):
    Sk=apply_double_and_add_method(G = Qa, k = kb, p = p)
    return Sk

def handle_client1(client_socket):
    
    request = client_socket.recv(1024) #msg1
    UIDi = pickle.loads(request) 
    
    # msg = input("Enter message: ")
    # if(msg=="denied"):
    #     print("Reply sent to CPS Device: " ,msg)
    #     client_socket.send(msg.encode())
    if (UIDi[1]=="r"):
        print("UIDi recieved:",UIDi[0])
        #sending back the point X to CPS device and also the parameters a and b
        X= (a,b,G)
        X = pickle.dumps(X)
        client_socket.sendall(X) #msg2
        # print("Reply sent to CPS Device: " ,X)

        msg3= client_socket.recv(4096) #msg3
        Qa = pickle.loads(msg3) 
        kb,Qb=generate_keys()
        Sk=calculate_shared_key(Qa,kb)
        SK1.append(Sk)

        print("Calculated Shared Key ",Sk)
        # Generate a random UUID (UUID4)
        DIDi =  uuid.uuid4()
        DID1.append(DIDi)
        print("DIDi:",DIDi)
    
        encrypted_didi = encrypt_didi(DIDi, Sk)
        print("Encrypted DIDi:",encrypted_didi)
        msg4=(Qb,encrypted_didi)
        msg4 = pickle.dumps(msg4)
        client_socket.sendall(msg4) #msg4

        client_socket.close()
        return Sk
    
    if (UIDi[1]=="a"):
        dec_DIDi=decrypt_didi(UIDi[0],SK1[0])
        if dec_DIDi != DID1[0]:
            
            _G=gen_points()
            _H=gen_points()
            msg2=(_G,_H)
            

            # send (G,H) msg2
            msg2= pickle.dumps(msg2)
            client_socket.sendall(msg2) #msg2
            print("Sent G and H")

            #recieve (xG, xH) msg3
            msg3= client_socket.recv(4096) #msg3
            msg3 = pickle.loads(msg3) 

            #send c msg4
            c=random.getrandbits(128)
            msg4= pickle.dumps(c)
            client_socket.sendall(msg4) #msg2
            print("Sent c")

            #recieve (vG,vH, r) msg5
            msg5= client_socket.recv(4096) #msg3
            msg5 = pickle.loads(msg5) 

            if (msg5[0] == add_points(calculate_shared_key(_G,msg5[2]),(calculate_shared_key(msg3[0],c)),p) and msg5[1] == add_points(calculate_shared_key(_H,msg5[2]),(calculate_shared_key(msg3[1],c)),p) ):
                print("Denied")
            else:
                print("Accepted")
 

serverIP="127.0.0.1"
serverPort=8000
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((serverIP, serverPort))
server_socket.listen(1)
print("Server listening on", serverIP + ":" + str(serverPort))
while True :
    client_socket, addr = server_socket.accept()
    print("Connection established with device", addr)
    handle_client1(client_socket)
    print(DID1)
    print(SK1)
