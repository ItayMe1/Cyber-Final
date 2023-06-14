import socket
import threading
import tkinter as tk
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import struct
import pyperclip
from tkinter import scrolledtext
import pyshine as ps
import pickle
import customtkinter as ctk
from tkinter.filedialog import askopenfilename
import os
import platform
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
        
                         
    def receive_messages(self,client):
        if isinstance(client, socket.socket):
            try:
                while True:
                    message = client.recv(1024)
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
        self.window=ctk.CTk()
        print(type(self.window))
        self.window.title("ZoOm")
        self.window.geometry('300x200')

        btn_listen = ctk.CTkButton(master=self.window,text='Copy Invite Link to the Call',command=self.ip2int)
        btn_listen.pack(pady=50,padx=50)
        

        self.window.mainloop()               
        
    def ip2int(self):#converting your ip into numbers
        global ip_server
        ip_server = self.get_ip_address()
        ip_int = struct.unpack("!I", socket.inet_aton(ip_server))[0]
        pyperclip.copy(ip_int)   
        
    def Owner_Chat_Gui(self):
        self.chat_window = ctk.CTk()
        self.chat_window.title("Chat Owner")
        self.chat_messages = scrolledtext.ScrolledText(self.chat_window, height=10, width=50)
        self.chat_messages.pack(anchor=tk.W,expand=True)
        
        message_label = ctk.CTkLabel(master=self.chat_window,text="Chat Messages:")
        message_label.pack()
        
        name_label = ctk.CTkLabel(master=self.chat_window, text="Enter your name:")
        name_label.pack()
        
        self.name_entry = ctk.CTkEntry(master=self.chat_window)
        self.name_entry.pack()

        message_label = ctk.CTkLabel(master=self.chat_window, text="Enter message:")
        message_label.pack()
        
        self.message_entry2 = ctk.CTkEntry(master=self.chat_window)
        self.message_entry2.pack()
        
                    
        self.chat_window.bind('<Return>', lambda event: self.Owner_send_button_clicked())
        send_button = ctk.CTkButton(master=self.chat_window, text="Send", command=lambda: self.Owner_send_button_clicked())
        send_button.pack()
        self.chat_window.mainloop()
                   
    def Owner_send_button_clicked(self):#caused if the owner sends a message
        name = self.name_entry.get()
        message = self.message_entry2.get()
        self.message_entry2.delete(0, len(message))
        self.Msg_to_All(name, message)
        self.Update_window_for_Owner(name, message)
        
        
    def Msg_to_All(self,name,msg):
        txt=(f"{name}:{msg}")
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
        self.window=ctk.CTk()
        self.window.title("ZoOm")
        self.window.geometry('300x300')
        #Buttons   
        name_label = ctk.CTkLabel(master=self.window, text="Enter Room Code to enter!")
        name_label.pack(side="top")
        ip_entry = ctk.CTkEntry(self.window)#The text area
        ip_entry.pack(side="top")
        self.window.bind('<Return>', lambda x: self.Getip())
        send_button = ctk.CTkButton(master=self.window,text="send", command=self.Getip)
        send_button.pack(side="top")
        
        self.window.mainloop()
            
    def Getip(self):#get the message and delete the text field, and call the convert funtion with the text collected
        global msg
        msg=ip_entry.get() 
        ip_entry.delete(0,len(msg))  
        self.int2ip(msg) 
   
    def int2ip(self,msg):#getting the ip from button, and then convert it and connect  
        global ip_for_client
        self.s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)   
        ip_for_client=socket.inet_ntoa(struct.pack('!I', int(msg)))#Returning a ip from numbers
        server_port = 9999
        self.s.connect((ip_for_client, server_port))     
        try:  
            self.window.destroy()
            self.servers_public_key=self.s.recv(1024)
            self.s.send(self.public_key)
            
            threading.Thread(target=self.Chat_Gui).start()
            threading.Thread(target=self.recieve_msg).start()
        except Exception as e: print(e)


            
    def recieve_msg(self):#recv msg and decrypt it, dispaly on screen
        y_position=25
        while True:
            try:
                message=self.s.recv(1024)
                decrypted_message=self.decrypt_msg(message,self.key).decode()               
                self.chat_messages.insert(tk.END, decrypted_message + "\n")
                y_position += 1
                if y_position >= 6:
                    self.chat_messages.yview_scroll(1, tk.UNITS)  # Scroll down one unit if y_position reaches 6
                self.chatwindow.update_idletasks()       
                self.chatwindow.mainloop()
            except:
                pass
    def Client_send_message(self,name, message):#sending the encrypted txt
        txt=(f"{name}:{message}")
        encrypt_txt=self.encrypt_msg(self.servers_public_key,txt)
        self.s.send(encrypt_txt) 
        
    def Chat_Gui(self):
        global name_entry,message_entry
        self.chatwindow = ctk.CTk()
        self.chatwindow.title("Chat Client")
        
        self.chat_messages = scrolledtext.ScrolledText(self.chatwindow, height=10, width=50)
        self.chat_messages.pack(anchor=tk.W,expand=True)

        message_label = ctk.CTkLabel(master=self.chatwindow, text="Chat Messages:")
        message_label.pack()
        
        name_label = ctk.CTkLabel(master=self.chatwindow, text="Enter your name:")
        name_label.pack()
        name_entry = ctk.CTkEntry(master=self.chatwindow)
        name_entry.pack()

        message_label = ctk.CTkLabel(master=self.chatwindow, text="Enter message:")
        message_label.pack()
        message_entry = ctk.CTkEntry(master=self.chatwindow)
        message_entry.pack()
                    
        self.chatwindow.bind('<Return>', lambda event: self.Client_send_button_clicked())
        send_button = ctk.CTkButton(master=self.chatwindow, text="Send", command=lambda: self.Client_send_button_clicked())
        send_button.pack()
        self.chatwindow.mainloop()
    
    def Client_send_button_clicked(self):
        name = name_entry.get()
        message = message_entry.get()
        self.Client_send_message(name, message)
        message_entry.delete(0, tk.END)#deleting the message box after sending
class Receive_Audio:
    def Join_Audio_Server(self):
        host_ip=ip_for_client
        port=7777
        client_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        client_socket.connect((host_ip,port))
        threading.Thread(target=self.receive_microphone_output,args=(client_socket,)).start()
    
    def receive_microphone_output(self,client_socket):
        try:
            mode = 'get'
            audio, _ = ps.audioCapture(mode=mode)

            data = b""
            payload_size = struct.calcsize("Q")
            while True:
                while len(data) < payload_size:
                    packet = client_socket.recv(4*1024) 
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
        except:
            pass        
class Send_Audio:
    def Audio_Server(self):
        # Socket Create
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host_ip = '0.0.0.0'
        port = 7777
        socket_address = (host_ip, port)
        server_socket.bind(socket_address)
        server_socket.listen()
        client, ip = server_socket.accept()
        threading.Thread(target=self.send_microphone_output,args=(client,)).start()
        
    def send_microphone_output(self,client_socket):
        try:
            mode = 'send'
            audio, context = ps.audioCapture(mode=mode)#capture audio
            try:
                while True:
                    frame = audio.get()#take frames from it
                    a = pickle.dumps(frame)#bytes
                    message = struct.pack("Q", len(a)) + a#pack it in a length,binary-q 8 bytes
                    client_socket.sendall(message)
            except:
                pass
        except:
            pass
class Send_file:
    def __init__(self):
        self.clients=[]
    def establish_connection(self):
        global ip_server
        HOST = ip_server
        PORT = 5555 
        # Create a socket object
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind the socket to a specific address and port
        server_socket.bind((HOST, PORT))

        # Listen for incoming connections
        server_socket.listen()

        print('Server listening on {}:{}'.format(HOST, PORT))
        threading.Thread(target=self.send_file_gui).start()
        # Accept a client connection
        client_socket, client_address = server_socket.accept()
        self.clients.append(client_socket)
        print('Connected to client:', client_address)

    def send_file_gui(self):
        self.file_gui = ctk.CTk()
        self.file_gui.geometry('300x300')
        self.file_gui.title("File sender")
        send_file_button = ctk.CTkButton(master=self.file_gui, text="Pick a file to send", command=self.send_file)
        send_file_button.pack()
        self.file_gui.mainloop()
        
    def send_file(self):
        for i in self.clients:
            # Send the file to the client
            file_path = askopenfilename()

            # Send the file name to the client
            file_name = os.path.basename(file_path)
            i.send(file_name.encode())

            # Open the file for reading
            with open(file_path, 'rb') as file:
                # Read file data and send it to the client
                while True:
                    data = file.read(1024)
                    if not data:
                        break
                    i.sendall(data)
            
            print('File sent successfully')
class Receive_file:
    def connect_to_server(self):
        HOST = ip_for_client
        PORT = 5555 
        # Create a socket object
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to the server
        client_socket.connect((HOST, PORT))
        print('Connected to server')
        threading.Thread(target=self.receive_file,args=(client_socket,)).start()
    
    def open_file(self,file_path):
        system = platform.system()
        if system == 'Windows':
            os.startfile(file_path)
        else:  
            pass

    def receive_file(self,client_socket):
        # Receive the file name
        file_name = client_socket.recv(1024).decode()

        # Receive the file content and save it
        with open(file_name, 'wb') as file:
            while True:
                data = client_socket.recv(1024)
                data2=data
                if not data or data2==data:
                    break
                file.write(data)

        print('File received successfully')
        self.open_file(file_name)
class Start_Gui:
    def Welcome_Page(self):
        ctk.set_default_color_theme("green")
        self.first_screen=ctk.CTk()
        self.first_screen.geometry('700x700')
        label = ctk.CTkLabel(self.first_screen,text="Welcome!")
        label.pack(pady=10,padx=10)
        label2 = ctk.CTkLabel(master=self.first_screen,text='Click to join our Comuunity')
        label2.pack(pady=10,padx=10)
        button = ctk.CTkButton(master=self.first_screen,text='Start',command=self.close_first_screen)
        button.pack(pady=10,padx=10)        
    
        self.first_screen.mainloop()
    
    def close_first_screen(self):
        self.first_screen.destroy()
        self.Home_Screen_GUI()
        
    def Home_Screen_GUI(self):
        global window
        window=ctk.CTk()
        window.title("ZoOm")
        window.geometry('300x300')
        
        btn_listen = ctk.CTkButton(master=window,text='Start a Call',command=self.Create_Owner)
        btn_listen.pack(pady=10,padx=10)  
        
        btn_listen = ctk.CTkButton(master=window,text='Join a Call',command=self.Create_Client)
        btn_listen.pack(pady=10,padx=10)
        
        window.mainloop()

    def Create_Owner(self):
        window.destroy()
        owner=Owner()  
        owner.start_Call() 
        send_audio=Send_Audio()
        send_audio.Audio_Server()
        send_file=Send_file()
        send_file.establish_connection()
    
    def Create_Client(self):
        window.destroy()
        client=Client()  
        client.Join_Call()
        receive_audio=Receive_Audio()
        receive_audio.Join_Audio_Server()
        recv_file=Receive_file()
        recv_file.connect_to_server()

if __name__=='__main__':
    Gui=Start_Gui()
    Gui.Welcome_Page()
