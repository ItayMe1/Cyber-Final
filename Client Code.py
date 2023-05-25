from logging import exception
import socket
import threading
import tkinter as tk
import numpy as np
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import struct
import pyperclip
import mss
import pyaudio
from tkinter import scrolledtext
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from zlib import compress
import pyshine as ps
import pickle
class Owner:
    global shift
    shift=10
    def __init__(self):
        self.clients=[]
        self.ip_addresses=[]
        self.list_of_keys=[]
    
    def decrypt_msg(self,encrypted_message, key):
        private_key = RSA.import_key(key)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_message = cipher_rsa.decrypt(encrypted_message)
        return decrypted_message.decode()
    
    def encrypt_msg(self,public_key, message):
        key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(key)
        encrypted_message = cipher_rsa.encrypt(message.encode())
        return encrypted_message
    
    def get_ip_address(self):
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.connect(("8.8.8.8",80))
        return s.getsockname()[0]
        
    def start_Call(self):
        my_server_port = 9999

        # Generate RSA key pair
        self.key = RSA.generate(2048)
        self.private_key = self.key.export_key()
        self.public_key = self.key.publickey().export_key()

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind(('0.0.0.0', my_server_port))       
        self.start_Guis()    
    
    def start_Guis(self):
        threading.Thread(target=self.active_chat).start()
        threading.Thread(target=self.Owner_Zoom_Gui).start()
        threading.Thread(target=self.Owner_Chat_Gui).start()
           
    def active_chat(self):
        self.s.listen()
        while True:
            client, ip = self.s.accept()
            threading.Thread(target=self.Audio_Server).start()
            ##The Protocol
            client.send(self.public_key)##sending the client the server p_key
            client_public_key=client.recv(1024)
            self.list_of_keys.append(client)
            self.list_of_keys.append(client_public_key)
            self.handle_client(client,ip)           
            threading.Thread(target=self.receive_messages,args=(client,)).start()
           
            
    def handle_client(self,client, ip):
        if not self.is_ip_exist(ip):
            self.ip_addresses.append(ip)
            self.clients.append(client) 
            
    def Audio_Server(self):
        # Socket Create
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host_ip = '192.168.56.1'  # replace with the actual IP
        port = 7777
        socket_address = (host_ip, port)
        server_socket.bind(socket_address)
        server_socket.listen()
        client, ip = server_socket.accept()
        threading.Thread(target=self.send_microphone_output,args=(client,)).start()
        
    def send_microphone_output(self,client_socket):
        mode = 'send'
        audio, context = ps.audioCapture(mode=mode)
        try:
            while True:
                frame = audio.get()
                a = pickle.dumps(frame)
                message = struct.pack("Q", len(a)) + a
                client_socket.sendall(message)
        except:
            pass
            
    def Send_Audio(self):
        HOST = socket.gethostname()
        PORT = 5000
        FORMAT = pyaudio.paInt16
        CHANNELS = 1
        RATE = 44100
        CHUNK = 1024

        p = pyaudio.PyAudio()
        stream = p.open(format=FORMAT,
                        channels=CHANNELS,
                        rate=RATE,
                        output=True,
                        frames_per_buffer=CHUNK)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((HOST, PORT))
            print("Connected to", HOST + ":" + str(PORT))

            while True:
                try:
                    data = client_socket.recv(CHUNK)
                    stream.write(data)
                except:
                    pass
  
        
    def Find_p_key(self,client):
        time=0
        for i in self.clients:
            if i==client: 
                return self.list_of_keys[time+1]
            time+=1
                        
    def receive_messages(self,client):
        if isinstance(client, socket.socket):
            try:
                while True:
                    message = client.recv(1024)#not receiving the msg,check why
                    print(message)
                    decrypted_message=self.decrypt_msg(message,self.private_key)
                    msg=decrypted_message.split(':')
                    self.name=msg[0]
                    self.txt=msg[1]
                    self.Msg_to_All(self.name,self.txt)
                    self.Update_window(decrypted_message)
            except:
                pass

    def Find_clients_public_key(self,client):
        times=0
        for i in self.clients:
            if i==client:
                return self.list_of_keys[times+1]
            times+=1

           
    def is_ip_exist(self,ip):
        return ip in self.ip_addresses          
            
    def Owner_Zoom_Gui(self):
        self.window=tk.Tk()
        self.window.title("ZoOm")
        self.window.geometry('300x300')

        btn_video=tk.Button(self.window,text='Copy Invite Link to the Call',width=50,command=self.ip2int)
        btn_video.pack(anchor=tk.CENTER,expand=True)

        btn_listen=tk.Button(self.window, text='Share Screen', width=50)#add a function
        btn_listen.pack(anchor=tk.CENTER,expand=True)

        btn_video=tk.Button(self.window,text='start share microphone',width=50,command=self.Send_Audio)
        btn_video.pack(anchor=tk.CENTER,expand=True)

        self.window.mainloop()               
        
    def ip2int(self):#converting your ip into numbers,working
        ip = self.get_ip_address()
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        pyperclip.copy(ip_int)   
        
    def Owner_Chat_Gui(self):
        self.chat_window = tk.Tk()
        self.chat_window.title("Chat Owner")
        
        self.chat_messages = scrolledtext.ScrolledText(self.chat_window, height=10, width=50)
        self.chat_messages.pack(anchor=tk.W,expand=True)

        message_label = tk.Label(self.chat_window, text="Chat Messages:")
        message_label.pack()
        
        name_label = tk.Label(self.chat_window, text="Enter your name:")
        name_label.pack()
        self.name_entry = tk.Entry(self.chat_window)
        self.name_entry.pack()

        message_label = tk.Label(self.chat_window, text="Enter message:")
        message_label.pack()
        self.message_entry2 = tk.Entry(self.chat_window)
        self.message_entry2.pack()
        
                    
        self.chat_window.bind('<Return>', lambda event: self.Owner_send_button_clicked())
        send_button = tk.Button(self.chat_window, text="Send", command=lambda: self.Owner_send_button_clicked())
        send_button.pack()
        self.chat_window.mainloop()
                   
    def Owner_send_button_clicked(self):#caused if the owner sends a message
        name = self.name_entry.get()
        message = self.message_entry2.get()
        self.Msg_to_All(name, message)
        self.Update_window_for_Owner(name, message)
        
        self.message_entry2.delete(0, tk.END)#deleting the message box after sending#######check why not working
        
    def Msg_to_All(self,name,msg):
        txt=(f"{name}:{msg}")
        ##encrypted_txt=self.caesar_encrypt(txt)
        for client in self.clients:
            clients_public_key=self.Find_clients_public_key(client)
            encrypted_txt=self.encrypt_msg(clients_public_key,txt)
            client.send(encrypted_txt)   
    
    def Update_window(self,decrypted_msg):
        y_position=25
        self.chat_messages.insert(tk.END, decrypted_msg + "\n")
        y_position += 1
        if y_position >= 6:
            self.chat_messages.yview_scroll(1, tk.UNITS)  # Scroll down one unit if y_position reaches 6
        self.chat_window.update_idletasks()       
        
        
    def Update_window_for_Owner(self,name,msg):
        txt=(f"{name}:{msg}")
        y_position=25
        self.chat_messages.insert(tk.END, txt + "\n")
        y_position += 1
        if y_position >= 6:
            self.chat_messages.yview_scroll(1, tk.UNITS)  # Scroll down one unit if y_position reaches 6
        self.chat_window.update_idletasks()       
        self.chat_window.mainloop()
                        
class Client:
    def __init__(self):
            self.key = RSA.generate(2048)
            self.private_key = self.key.export_key()
            self.public_key = self.key.publickey().export_key()
            
    def decrypt_msg(self,encrypted_message,key):#key = RSA.generate(2048), the encrypted msg dont need to be encoded
        cipher_rsa = PKCS1_OAEP.new(key)
        decrypted_message = cipher_rsa.decrypt(encrypted_message)
        return decrypted_message
    
    def encrypt_msg(self,public_key, message):
        key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(key)
        encrypted_message = cipher_rsa.encrypt(message.encode())
        return encrypted_message
    
    def Join_Call(self):
        global ip_entry
        global shift
        shift=10
        #Tempararly window
        self.window=tk.Tk()
        self.window.title("ZoOm")
        self.window.geometry('300x300')
        #Buttons   
        ip_entry = tk.Entry(self.window)#The text area
        ip_entry.pack(side="top")
        self.window.bind('<Return>', lambda x: self.Getip())
        send_button = tk.Button(self.window,text="Send", command=self.Getip)
        send_button.pack(side="top")
        
        self.window.mainloop()
            
    def Getip(self):#get the message and delete the text field, and call the convert funtion with the text collected
        global msg
        msg=ip_entry.get() 
        ip_entry.delete(0,len(msg))  
        self.int2ip(msg) 
        
    def Recieve_audio(self):
        FORMAT = pyaudio.paInt16
        CHANNELS = 1
        RATE = 44100
        CHUNK = 1024
        HOST = socket.gethostname()
        PORT = 5000

        frames = []

        p = pyaudio.PyAudio()
        stream = p.open(format=FORMAT,
                        channels=CHANNELS,
                        rate=RATE,
                        input=True,
                        frames_per_buffer=CHUNK)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((HOST, PORT))
            server_socket.listen(1)
            conn, address = server_socket.accept()
            while True:
                try:
                    data = stream.read(CHUNK)
                    conn.sendall(data)
                    frames.append(data)
                except:
                    pass
   
    def int2ip(self,msg):#getting the ip from button, and then convert it and connect   
        self.s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)   
        ip=socket.inet_ntoa(struct.pack('!I', int(msg)))#Returning a ip from numbers,working
        print(ip)
        server_port = 9999
        self.s.connect((ip, server_port))   
        self.Join_Audio_Server()    
        try:  
            self.window.destroy()
            self.servers_public_key=self.s.recv(1024)
            self.s.send(self.public_key)

            threading.Thread(target=self.Recieve_audio).start()
            threading.Thread(target=self.Client_Zoom_Gui).start()
            threading.Thread(target=self.Chat_Gui).start()
            threading.Thread(target=self.recieve_msg).start()
        except Exception as e: print(e)

    def Join_Audio_Server(self):
        host_ip='192.168.56.1'
        port=7777
        client_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        client_socket.connect((host_ip,port))
        threading.Thread(target=self.receive_microphone_output,args=(client_socket,)).start()
    
    def receive_microphone_output(self,client_socket):
        mode = 'get'
        audio, _ = ps.audioCapture(mode=mode)

        data = b""
        payload_size = struct.calcsize("Q")
        while True:
            while len(data) < payload_size:
                packet = client_socket.recv(4*1024) # 4K
                if not packet:
                    break
                data += packet
            packed_msg_size = data[:payload_size]
            data = data[payload_size:]
            msg_size = struct.unpack("Q", packed_msg_size)[0]

            while len(data) < msg_size:
                data += client_socket.recv(4*1024)
            frame_data = data[:msg_size]
            data = data[msg_size:]
            frame = pickle.loads(frame_data)
            audio.put(frame)
    
    def send_screenshot(self):
        WIDTH = 1900
        HEIGHT = 1000
        with mss() as sct:
        # The region to capture
            rect = {'top': 0, 'left': 0, 'width': WIDTH, 'height': HEIGHT}

        while 'recording':
            # Capture the screen
            img = sct.grab(rect)
            # Tweak the compression level here (0-9)
            pixels = (img.rgb, 6)

            # Send the size of the pixels length
            size = len(pixels)
            size_len = compress(size.bit_length() + 7) // 8
            self.s.send(bytes([size_len]))

            # Send the actual pixels length
            size_bytes = size.to_bytes(size_len, 'big')
            self.send(size_bytes)

            # Send pixels
            self.sendall(pixels)  
            
    def recieve_msg(self):#recv msg and decrypt it, dispaly on screen,working
        y_position=25
        while True:
            try:
                message=self.s.recv(1024)
                print(message)
                decrypted_message=self.decrypt_msg(message,self.key).decode()               
                self.chat_messages.insert(tk.END, decrypted_message + "\n")
                y_position += 1
                if y_position >= 6:
                    self.chat_messages.yview_scroll(1, tk.UNITS)  # Scroll down one unit if y_position reaches 6
                self.chatwindow.update_idletasks()       
                self.chatwindow.mainloop()
            except:
                pass
        
    def Client_Zoom_Gui(self):
        self.window=tk.Tk()
        self.window.title("ZoOm")
        self.window.geometry('300x300')
        btn_listen=tk.Button(self.window, text='Share Screen', width=50,command=self.send_screenshot)#add a function
        btn_listen.pack(anchor=tk.CENTER,expand=True)

        btn_video=tk.Button(self.window,text='Share Camera',width=50)
        btn_video.pack(anchor=tk.CENTER,expand=True)
        self.window.mainloop()
        
    def Chat_Gui(self):
        global name_entry,message_entry
        self.chatwindow = tk.Tk()
        self.chatwindow.title("Chat Client")
        
        self.chat_messages = scrolledtext.ScrolledText(self.chatwindow, height=10, width=50)
        self.chat_messages.pack(anchor=tk.W,expand=True)

        message_label = tk.Label(self.chatwindow, text="Chat Messages:")
        message_label.pack()
        
        name_label = tk.Label(self.chatwindow, text="Enter your name:")
        name_label.pack()
        name_entry = tk.Entry(self.chatwindow)
        name_entry.pack()

        message_label = tk.Label(self.chatwindow, text="Enter message:")
        message_label.pack()
        message_entry = tk.Entry(self.chatwindow)
        message_entry.pack()
                    
        self.chatwindow.bind('<Return>', lambda event: self.Client_send_button_clicked())
        send_button = tk.Button(self.chatwindow, text="Send", command=lambda: self.Client_send_button_clicked())
        send_button.pack()
        self.chatwindow.mainloop()
    
    def Client_send_button_clicked(self):
        name = name_entry.get()
        message = message_entry.get()
        self.Client_send_message(name, message)
        message_entry.delete(0, tk.END)#deleting the message box after sending
  
    def Client_send_message(self,name, message):#sending the encrypted txt,working
            txt=(f"{name}:{message}")
            encrypt_txt=self.encrypt_msg(self.servers_public_key,txt)
            self.s.send(encrypt_txt)
        
        
def Home_Screen_GUI():
    global window
    window=tk.Tk()
    window.title("ZoOm")
    window.geometry('300x300')
    
    btn_listen=tk.Button(window, text='Start a Call', width=50, command=Create_Owner)
    btn_listen.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    btn_video=tk.Button(window,text='Join a Call',width=50,command=Create_Client)
    btn_video.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    
    window.mainloop()

def Create_Owner():
    window.destroy()
    owner=Owner()  
    owner.start_Call()  
    
def Create_Client():
    window.destroy()
    client=Client()  
    client.Join_Call()  
    
try:    
    Home_Screen_GUI()
except :
    pass
