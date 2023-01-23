"""
    @Author: Murat Güç
    @Date:   December 28, 2022

    NOTES:
        - Script works only for 2 user. 
        - In two terminals under the same folder, you can initialize them.
        - In the beginning server.txt must be empty. 
        - Script does not handle that, but it creates it does not exist.
        - After seeing the message, "You may start chatting!", you can write your message.
        - This script must be run under UNIX based OS.
        - Additional dependency can be installed by the following command:
            "pip install pycryptodome"            
"""
from Crypto.Util import number #used for isPrime & GCD functions
import random
import base64
import time
import os # used for fork() - r&w server file is parallel
 
private_key=0
seperator = "******************************************************************************\n"
another_users_FHQG = []

def generate_F_h_q_g():
    global private_key
    #randomly choose a large prime number q between (2^1023-2^1024)
    q=0
    while not number.isPrime(q):
        q = random.randrange(2 ** 1023, 2 ** 1024)
    #cyclic group Fq is a list containing just start and end point due to memory issues
    #list starting from zero to q incerementing by one is not created 
    Fq = [0,q]
    #choose random generator g
    g = random.randrange(Fq[0],Fq[1])
    #while number.GCD(g, q) != 1:
    #    g = random.randrange(Fq[0],Fq[1])
    #generate b and retain as a private key
    b = random.randrange(Fq[0],Fq[1])
    while number.GCD(b, q) != 1:
        b = random.randrange(Fq[0],Fq[1])
    #store
    private_key=b
    #calculate hash
    h = pow(g, b, q)

    return Fq,h,q,g

def encrypt_message(message,Fq,h,q,g):
    global private_key
    #choose a from cyclic group Fq
    a = random.randrange(Fq[0],Fq[1])
    while number.GCD(a, q) != 1:
        a = random.randrange(Fq[0],Fq[1])
    #compute p=g^a
    p = pow(g,a,q)
    #compute s=h^a
    s = pow(h,a,q)
    #transform message to utf-8 mode and the int mode
    message = int.from_bytes(message.encode('ascii'), 'big')
    #encrypt message with s
    encrypted_message = (message * s) % q
    #implement b64 encoding
    encrypted_message_b64 = base64.b64encode(encrypted_message.to_bytes((encrypted_message.bit_length() + 7) // 8, 'big'))

    return p, encrypted_message_b64.decode('ascii')

def decrypt(p, encrypted_message_b64, b, q):
    # Decode the encrypted message from type of base64
    encrypted_message = int.from_bytes(base64.b64decode(encrypted_message_b64), 'big')
    # s' = p^b = g^ab
    s_prime = pow(p,b,q)
    # By using s', decrypt encrypted_message
    decrypted_message = (encrypted_message * pow(s_prime, -1, q)) % q
    # Transform the decrypted_message to the string
    decrypted_message_bytes = decrypted_message.to_bytes((decrypted_message.bit_length() + 7) // 8, 'big')
    decrypted_message_string = decrypted_message_bytes.decode('ascii')

    return decrypted_message_string

#this function detects other user and store its public key components in another_users_FHQG
#inner flag is used for avoiding recontrol
def detect_other_user():
    global another_users_FHQG
    flag = 0
    with open("server.txt", "r") as f:
        data = f.read()
        sections = data.split(seperator)
        for section in sections:
            if flag==1:
                break
            if section:
                lines = section.split("\n")    
                if len(lines)==5:
                    F = []
                    F.append(int(lines[0]
                                .split(": ")[1]
                                .replace("[","")
                                .replace("]","")
                                .split(", ")[0]))
                    F.append(int(lines[0]
                                .split(": ")[1]
                                .replace("[","")
                                .replace("]","")
                                .split(", ")[1]))             
                    H, Q, G = int(lines[1].split(": ")[1]), \
                                int(lines[2].split(": ")[1]), \
                                int(lines[3].split(": ")[1])
                    #if their public keys are different store components
                    if H!=h:
                        another_users_FHQG.append(F)
                        another_users_FHQG.append(H)
                        another_users_FHQG.append(Q)
                        another_users_FHQG.append(G)
                        flag=1
            else:
                print("Waiting for the other user...")
#this function checks last message
def check_message_and_decrypt():
    with open("server.txt", "r") as f:
        data = f.read()
        sections = data.split(seperator)
        for i in range(len(sections)-1,-1,-1):
            section = sections[i]
            if section:
                lines = section.split("\n")
                if len(lines)==3:
                    lines = section.split("\n")
                    p_in,enc_mess_in=int(lines[0].split(": ")[1]), \
                               bytes(lines[1].split(": ")[1], encoding='ascii')
                    decrypted_message = decrypt(p_in, enc_mess_in, private_key, q)
                    time.sleep(5)
                    print(f"-{decrypted_message}")
                    #removes this secion from server
                    with open("server.txt", "w") as f:
                        section = section+seperator
                        f.write(data.replace(section,""))
                else:
                    break
#takes input from user and encrypts it with other user's public key components
def send_message():
    message = input()
    p, enc_message = encrypt_message(message,another_users_FHQG[0],another_users_FHQG[1],another_users_FHQG[2],another_users_FHQG[3])
    #write p, encrypted message on the server
    with open("server.txt", "a") as f:
        f.write(f"P: {p}\nM: {enc_message}\n")
        f.write(seperator)
    

Fq,h,q,g = generate_F_h_q_g()

with open("server.txt", "a") as f:
    f.write(f"F: {Fq}\nH: {h}\nQ: {q}\nG: {g}\n")
    f.write(seperator)

while len(another_users_FHQG)!=4:
    detect_other_user()
    time.sleep(2)

print("You may start chatting!")
n = os.fork()
#parent process
if n > 0:
    while True:
        try:
            send_message()
        except:
            continue
        time.sleep(5)

#child process
else:
    while True:
        try:
            check_message_and_decrypt()
        except:
            continue