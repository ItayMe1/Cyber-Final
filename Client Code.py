from logging import exception
import socket
import threading
import tkinter as tk
import numpy as np
import pyautogui 
import cv2
import struct
import pyperclip
import mss
import pyaudio
from tkinter import scrolledtext
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from zlib import compress
class Owner:
    global shift
    shift=10
    def __init__(self):
        self.clients=[]
        self.ip_addresses=[]
        
    def start_Call(self):##start a new server for the call
        local_ip = socket.gethostbyname(socket.gethostname())
        my_server_port=9999
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((local_ip,my_server_port))
        self.start_Guis()    
    
    def start_Guis(self):
        threading.Thread(target=self.active_chat).start()
        threading.Thread(target=self.Owner_Zoom_Gui).start()
        threading.Thread(target=self.Owner_Chat_Gui).start()
           
    def active_chat(self):
        while True:
            self.s.listen(5)
            client, ip = self.s.accept()
            self.handle_client(client, ip)
            threading.Thread(target=self.Recieve_audio).start()
            threading.Thread(target=self.receive_messages,args=(client,)).start()      
        
    def handle_client(self,client, ip):
        if not self.is_ip_exist(ip):
            self.ip_addresses.append(ip)
            self.clients.append(client) 
            
            
    def Recieve_audio(self):
        HOST = socket.gethostname()
        PORT = 5000
        # Audio
        FORMAT = pyaudio.paInt16
        CHANNELS = 1
        RATE = 44100
        CHUNK = 1024

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
    
            
    def caesar_encrypt(self,plaintext):
        ciphertext = ""
        for char in plaintext:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                shifted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
                ciphertext += shifted_char
            else:
                ciphertext += char
        return ciphertext

    def caesar_decrypt(self, plaintext):
        ciphertext = ""
        for char in plaintext:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                shifted_char = chr((ord(char) - ascii_offset + shift * -1) % 26 + ascii_offset)
                ciphertext += shifted_char
            else:
                ciphertext += char
        return ciphertext


    
    def Update_window(self):
        y_position=25
        self.chat_messages.insert(tk.END, self.message + "\n")
        y_position += 1
        if y_position >= 6:
            self.chat_messages.yview_scroll(1, tk.UNITS)  # Scroll down one unit if y_position reaches 6
        self.chat_window.update_idletasks()       
        self.chat_window.mainloop()
        
        
    def Update_window_for_Owner(self,name,msg):
        txt=(f"{name}:{msg}")
        y_position=25
        self.chat_messages.insert(tk.END, txt + "\n")
        y_position += 1
        if y_position >= 6:
            self.chat_messages.yview_scroll(1, tk.UNITS)  # Scroll down one unit if y_position reaches 6
        self.chat_window.update_idletasks()       
        self.chat_window.mainloop()    
                        
    def receive_messages(self,client):
        while True:
            try:
                self.message = client.recv(1024).decode()
                self.message=self.caesar_decrypt(self.message)
                msg=self.message.split(':')
                self.name=msg[0]
                self.txt=msg[1]
                self.Msg_to_All(self.name,self.txt)
                self.Update_window()
            except:
                pass

                

           
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

        btn_video=tk.Button(self.window,text='start Camera',width=50)
        btn_video.pack(anchor=tk.CENTER,expand=True)

        self.window.mainloop()               
        
    def ip2int(self):#converting your ip into numbers,working
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
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
        self.message_entry = tk.Entry(self.chat_window)
        self.message_entry.pack()
        
                    
        self.chat_window.bind('<Return>', lambda event: self.Owner_send_button_clicked())
        send_button = tk.Button(self.chat_window, text="Send", command=lambda: self.Owner_send_button_clicked())
        send_button.pack()
        self.chat_window.mainloop()
                   
    def Owner_send_button_clicked(self):
        name = self.name_entry.get()
        message = self.message_entry.get()
        self.Msg_to_All(name, message)
        self.Update_window_for_Owner(name, message)
        
        self.message_entry.delete(0, tk.END)#deleting the message box after sending#######check why not working
        
    def Msg_to_All(self,name,msg):
        txt=(f"{name}:{msg}")
        encrypted_txt=self.caesar_encrypt(txt)
        for client in self.clients:
            client.send(encrypted_txt.encode())      
                        
class Client:
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
        self.int2ip() 
        
    def Send_Audio(self):
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

        while True:
                try:
                    data = self.s.recv(CHUNK)
                    stream.write(data)
                except:
                    pass
        
    def caesar_encrypt(self,plaintext):
        ciphertext = ""
        for char in plaintext:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                shifted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
                ciphertext += shifted_char
            else:
                ciphertext += char
        return ciphertext

    def caesar_decrypt(self, plaintext):
        ciphertext = ""
        for char in plaintext:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                shifted_char = chr((ord(char) - ascii_offset + shift * -1) % 26 + ascii_offset)
                ciphertext += shifted_char
            else:
                ciphertext += char
        return ciphertext
 
    
    def int2ip(self):#getting the ip from button, and then convert it and connect    
        try:   
            ip=socket.inet_ntoa(struct.pack('!I', int(msg)))#Returning a ip from numbers,working
        except:
            pass        
        server_port = 9999
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   
            print(ip,server_port)
            self.s.connect((ip, server_port))
            self.window.destroy()
            threading.Thread(target=self.recieve_msg).start()
            threading.Thread(target=self.Client_Zoom_Gui).start()
            threading.Thread(target=self.Chat_Gui).start()
        except:
            pass
    
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
    
    
    def Send_Audio(self):
        HOST = socket.gethostname()
        PORT = 5000
        # Audio
        FORMAT = pyaudio.paInt16
        CHANNELS = 1
        RATE = 44100
        CHUNK = 20000

        p = pyaudio.PyAudio()
        stream = p.open(format=FORMAT,
                        channels=CHANNELS,
                        rate=RATE,
                        output=True,
                        frames_per_buffer=CHUNK)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((HOST, PORT))


            while True:
                try:
                    data = client_socket.recv(CHUNK)
                    stream.write(data)
                except:
                    pass
            
    def recieve_msg(self):
        y_position=25
        while True:
            try:
                message=self.s.recv(1024).decode() 
                message=self.caesar_decrypt(message) 
                self.chat_messages.insert(tk.END, message + "\n")
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

        btn_video=tk.Button(self.window,text='Active Microhphone',width=50,command=self.Send_Audio)
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
        try:
            txt=(f"{name}:{message}")
            encrypt_txt=self.caesar_encrypt(txt)
            self.s.send(encrypt_txt.encode())
        except:
            print("An error occurred while sending the message.")
        
        
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
