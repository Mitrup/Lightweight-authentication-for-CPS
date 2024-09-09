import socket
import random
import pickle
import time
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

def generate_keys(X):
    ka = random.getrandbits(256)
    Qa = apply_double_and_add_method(G = X, k = ka, p = p)
    return ka,Qa

def calculate_shared_key(Qb,ka):
    Sk=apply_double_and_add_method(G = Qb, k = ka, p = p)
    return Sk

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

    
def run_client_reg():
    # create a socket object
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_ip = "127.0.0.1"  
    server_port = 8000  
    # establish connection with server
    client.connect((server_ip, server_port))
    
    # Send MAC address to the server
    msg1 = ("00327-35856-96741-AAOEM","r")
    msg1=pickle.dumps(msg1)
    client.sendall(msg1)

    # receive message from the server
    msg2 = client.recv(4096) #msg2
    msg2= pickle.loads(msg2)
    print("Received (a,b,X) : ", msg2)
    ka,Qa=generate_keys(msg2[2])
    
    Qa = pickle.dumps(Qa)
    client.sendall(Qa) #msg3

    response1 = client.recv(4096) #msg4
    msg4 = pickle.loads(response1)
    print("Received:(Qb,Enc({DIDI,SK}))", msg4)
    
    Qb=msg4[0]     
    Sk=calculate_shared_key(Qb,ka)
    print("Calculated Shared Key",Sk)
    DIDi=decrypt_didi(msg4[1], Sk)
    print("Recieved Device ID(DIDi):",DIDi)
        
        

    # if server sent us "denied" in the payload, we break out of the loop and close our socket
    # response1 = response.decode("utf-8")
    # if response1.lower() == "denied":
    #     print(f"Received response: {response1}")
    #     break

        

    # close client socket (connection to the server)
    client.close()
    print("Connection to server closed after registration")
    return DIDi,Sk

def run_client_auth(Stored_msg,Sk):
    # create a socket object
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_ip = "127.0.0.1"  
    server_port = 8000  
    # establish connection with server
    client.connect((server_ip, server_port))

    
    # Send Encrypted DIDi to the server
    msg1 = encrypt_didi(Stored_msg, Sk)
    msg1=(msg1,"a")
    msg1 = pickle.dumps(msg1)
    client.sendall(msg1) #msg1
    
    # receive message from the server
    msg2 = client.recv(4096) #msg2
    msg2= pickle.loads(msg2)
    print("Received (G,H) : ", msg2)

    # Compute x, xH, xG and send
    x=hash(str(Stored_msg)+str(random.getrandbits(128)))
    xG=calculate_shared_key(msg2[0],x)
    xH=calculate_shared_key(msg2[1],x)
    msg3=(xG,xH)
    msg3 = pickle.dumps(msg3)
    client.sendall(msg3) #msg3


    # recieve c and generate v, r, vG, vH
    msg4 = client.recv(4096)
    v=random.getrandbits(256)
    r=v-msg4[0]*x
    vG=calculate_shared_key(msg2[0],v)
    vH=calculate_shared_key(msg2[1],v)
    msg5=(vG,vH,r)

    # send vG, vH and r 
    msg5 = pickle.dumps(msg5)
    client.sendall(msg5) #msg5        

    # close client socket (connection to the server)
    client.close()
    print("Connection to server closed after auth")

start_time = time.time()
Stored_DIDi,Sk=run_client_reg()

run_client_auth(Stored_DIDi,Sk)
end_time = time.time()
processing_time = end_time - start_time
print("Processing Time:", processing_time, "seconds")