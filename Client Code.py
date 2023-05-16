from logging import exception
import socket
import threading
import tkinter as tk
import numpy as np
import pyautogui 
import cv2
import zlib
import struct
import pyperclip
import mss
import pickle
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
class Owner:
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
            threading.Thread(target=self.handle_client, args=(client, ip)).start()
            threading.Thread(target=self.receive_messages).start()      
        
    def handle_client(self,client, ip):
        if not self.is_ip_exist(ip):
            self.ip_addresses.append(ip)
            self.clients.append(client)     
                        
    def receive_messages(self):
        print(1)
        while True:
            try:
                message = self.s.recv(1024).decode()
                print(message)
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
        window = tk.Tk()
        window.title("Chat Client")

        message_label = tk.Label(window, text="Chat Messages:")
        message_label.pack()
        messages_text = tk.Text(window, height=10, width=50)
        messages_text.pack()
        messages_text.config(state=tk.DISABLED)

        name_label = tk.Label(window, text="Enter your name:")
        name_label.pack()
        name_entry = tk.Entry(window)
        name_entry.pack()

        message_label = tk.Label(window, text="Enter message:")
        message_label.pack()
        message_entry = tk.Entry(window)
        message_entry.pack()
                    
        window.bind('<Return>', lambda event: self.Owner_send_button_clicked(self.s,))
        send_button = tk.Button(window, text="Send", command=lambda: self.Owner_send_button_clicked(self.s,))
        send_button.pack()
        window.mainloop()
                   
    def Owner_send_button_clicked(self,s):
        name = name_entry.get()
        message = message_entry.get()
        self.Msg_to_All(s, name, message)
        message_entry.delete(0, tk.END)#deleting the message box after sending
        
    def Msg_to_All(self,name,msg):
        for client in self.clients:
            client.send(f"{name}:{msg}".encode())       
            
            
class Client:
    def Join_Call(self):
        global ip_entry
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
    
    def int2ip(self):#getting the ip from button, and then convert it and connect    
        ip=socket.inet_ntoa(struct.pack('!I', int(msg)))#Returning a ip from numbers,working
        server_port = 9999
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   
            print(ip,server_port)
            self.s.connect((ip, server_port))
            self.window.destroy()
            threading.Thread(target=self.Client_Zoom_Gui).start()
            threading.Thread(target=self.Chat_Gui).start()
        except:
            pass
        
    def Client_Zoom_Gui(self):
        self.window=tk.Tk()
        self.window.title("ZoOm")
        self.window.geometry('300x300')
        btn_listen=tk.Button(self.window, text='Share Screen', width=50)#add a function
        btn_listen.pack(anchor=tk.CENTER,expand=True)

        btn_video=tk.Button(self.window,text='start Camera',width=50)
        btn_video.pack(anchor=tk.CENTER,expand=True)
        self.window.mainloop()
        
    def Chat_Gui(self):
        global name_entry,message_entry
        self.chatwindow = tk.Tk()
        self.chatwindow.title("Chat Client")

        message_label = tk.Label(self.chatwindow, text="Chat Messages:")
        message_label.pack()
        messages_text = tk.Text(self.chatwindow, height=10, width=50)
        messages_text.pack()
        messages_text.config(state=tk.DISABLED)

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
  
    def Client_send_message(self,name, message):
        try:
            self.s.send(f"{name}:{message}".encode())
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
