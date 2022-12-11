import sklearn
#from scipy import stats
#import seaborn as sns
#import matplotlib.pyplot as plt
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
#from sklearn.metrics import classification_report
#from sklearn.metrics import confusion_matrix
import joblib 

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

    x = os.listdir(r"normal_behavior")
    for packets in x:
        if "prediction" not in packets and "encrypted" in packets:
            while os.stat("normal_behavior/" + packets).st_size == 0:
                time.sleep(0.1)

            capture = []
            
            with open("normal_behavior/" + packets, 'rb') as enc_file:
                encrypted = enc_file.read()
  
            # decrypting the file
            decrypted = fernet.decrypt(encrypted)
            line = decrypted.decode('UTF-8').split('\n')
            for entry in line:
                capture.append(entry.split(' ')[:len(entry.split(' ')) - 1])
                
            capture.pop()


            frame_data ={"Time": [],"No.": [],"Length": [],"src_port": [],"dst_port": [],"Syn": [],"Acknowledgment": [],"Time to live": [], "Protocol": [], "Version": [], "Request": [], "Data": []}
            for packet in capture:
                frame_data["Time"].append(float(packet[0]))
                frame_data["No."].append(int(packet[1]))
                frame_data["Length"].append(int(packet[2]))
                frame_data["src_port"].append(int(packet[3]))
                frame_data["dst_port"].append(int(packet[4]))
                frame_data["Syn"].append(int(packet[5]))
                frame_data["Acknowledgment"].append(int(packet[6]))
                frame_data["Time to live"].append(int(packet[7]))
                frame_data["Protocol"].append(int(packet[8]))
                frame_data["Version"].append(float(packet[9]))
                frame_data["Request"].append(int(packet[10]))
                frame_data["Data"].append(int(packet[11]))


            
            features = ["Time","No.","Length", "src_port","dst_port","Syn","Acknowledgment", "Time to live", "Protocol", "Version", "Request", "Data"]
            df = pd.DataFrame(frame_data)
            df["No."] = df["No."].astype(int)
            df["Length"] = df["Length"].astype(int)
            df["Protocol"] = df["Protocol"].astype(int)
            df["Request"] = df["Request"].astype(int)
            df["Data"] = df["Data"].astype(int)
            X = df[features].values
            """
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
            """
            

            #model = load_model('CROSS_model.h5')
            model = joblib.load("ML_CROSS_model_test.sav")
            predictions_net_benign = model.predict(X)
            #print(predict)

            predictn = predictions_net_benign.tolist()

            print(predictn)

            with open("normal_behavior/" + packets.split('.')[0] + "_prediction.txt", 'w') as f:
                for entry in predictn:
                    f.write(str(entry) + " ")
                f.write('\n')
                
            # opening the original file to encrypt
            with open("normal_behavior/" + packets.split('.')[0] + "_prediction.txt", 'rb') as file:
                original = file.read()
      
            # encrypting the file
            encrypted = fernet.encrypt(original)
  
            # opening the file in write mode and 
            # writing the encrypted data
            with open("normal_behavior/" + packets.split('.')[0] + "_encrypted_prediction.txt", 'wb') as encrypted_file:
                encrypted_file.write(encrypted)

            os.remove("normal_behavior/" + packets)
            os.remove("normal_behavior/" + packets.split('.')[0] + "_prediction.txt")
