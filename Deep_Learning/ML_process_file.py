from keras.models import Sequential, load_model
from keras.layers import Dense, LSTM, Bidirectional
#from keras.utils import plot_model
#from keras.utils.np_utils import to_categorical
#from keras.utils import np_utils

from sklearn.model_selection import train_test_split
from sklearn import preprocessing
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import confusion_matrix

from cryptography.fernet import Fernet

import numpy as np

import pandas as pd

import time

import sys
import os

with open('filekey.key', 'rb') as filekey:
    key = filekey.read()
        
fernet = Fernet(key)

while 1:    

    x = os.listdir(r"aux_files")
    for packets in x:
        if "prediction" not in packets and "encrypted" in packets:
            while os.stat("aux_files/" + packets).st_size == 0:
                time.sleep(0.1)

            capture = []
            
            with open("aux_files/" + packets, 'rb') as enc_file:
                encrypted = enc_file.read()
  
            # decrypting the file
            decrypted = fernet.decrypt(encrypted)
            line = decrypted.decode('UTF-8').split('\n')
            for entry in line:
                capture.append(entry.split(' ')[:len(entry.split(' ')) - 1])
                
            capture.pop()


            frame_data ={"Time": [],"No.": [],"Length": [],"src_port": [],"dst_port": [],"Syn": [],"Acknowledgment": [],"Reset": [],"Time to live": [], "Protocol": []}
            for packet in capture:
                frame_data["Time"].append(float(packet[0]))
                frame_data["No."].append(int(packet[1]))
                frame_data["Length"].append(int(packet[2]))
                frame_data["src_port"].append(int(packet[3]))
                frame_data["dst_port"].append(int(packet[4]))
                frame_data["Syn"].append(int(packet[5]))
                frame_data["Acknowledgment"].append(int(packet[6]))
                frame_data["Reset"].append(int(packet[7]))
                frame_data["Time to live"].append(int(packet[8]))
                frame_data["Protocol"].append(int(packet[9]))



            df = pd.DataFrame(frame_data)
            df["No."] = df["No."].astype(int)
            df["Length"] = df["Length"].astype(int)
            df["Protocol"] = df["Protocol"].astype(int)
            features = ["Time","No.","Length", "src_port","dst_port","Syn","Acknowledgment", "Reset", "Time to live", "Protocol"]
            df_control = pd.read_csv('Sample_packets.csv')
            #df_control["Time"] = df_control["Time"] + frame_data["Time"][0]
            X_capture = df[features].values
            X_normal = df_control[features].values
            X = np.concatenate((X_normal, X_capture))

            le = preprocessing.LabelEncoder()
            le.fit(["TCP", "HTTP", "ICMP"])
            
            for i in range(0,len(X)):
                X[i][1] = int(X[i][1])
                X[i][2] = int(X[i][2])

                if X[i][5] == "Set" or X[i][5] == 1.0:
                    X[i][5]=1
                elif X[i][5] == "Not set" or X[i][5] == 0.0:
                    X[i][5]=0
                if X[i][6] == "Set" or X[i][6] == 1.0:
                    X[i][6]=1
                elif X[i][6] == "Not set" or X[i][6] == 0.0:
                    X[i][6]=0
                if X[i][7] == "Set" or X[i][7] == 1.0:
                    X[i][7]=1
                elif X[i][7] == "Not set" or X[i][7] == 0.0:
                    X[i][7]=0
            for i in range(0,len(X)):
                if i < len(X_normal): 
                    X[i][9] = le.transform([X[i][9]])[0]
                else:
                    X[i][9] = int(X[i][9])
            
            print(X[0])
            print(X[len(X) - 1])

            scalar = StandardScaler(copy=True, with_mean=True, with_std=True)
            scalar.fit(X)
            X = scalar.transform(X)
                
            features = len(X[0])
            samples = X.shape[0]
            train_len = 25
            input_len = samples - train_len
            I = np.zeros((samples - train_len, train_len, features))

            for i in range(input_len):
                temp = np.zeros((train_len, features))
                for j in range(i, i + train_len - 1):
                    temp[j-i] = X[j]
                I[i] = temp

            #model = load_model('CROSS_model.h5')
            model = load_model('test_model2.h5')
            predict = model.predict(I, verbose=1)
            #print(predict)

            predictn = predict.flatten().round()
            predictn = predictn.tolist()

            #print(predictn)

            with open("aux_files/" + packets.split('.')[0] + "_prediction.txt", 'w') as f:
                for entry in predictn:
                    f.write(str(entry) + " ")
                f.write('\n')
                
            # opening the original file to encrypt
            with open("aux_files/" + packets.split('.')[0] + "_prediction.txt", 'rb') as file:
                original = file.read()
      
            # encrypting the file
            encrypted = fernet.encrypt(original)
  
            # opening the file in write mode and 
            # writing the encrypted data
            with open("aux_files/" + packets.split('.')[0] + "_encrypted_prediction.txt", 'wb') as encrypted_file:
                encrypted_file.write(encrypted)

            os.remove("aux_files/" + packets)
            os.remove("aux_files/" + packets.split('.')[0] + "_prediction.txt")
