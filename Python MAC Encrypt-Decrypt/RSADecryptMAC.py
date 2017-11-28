import os
from workspace.EncryptThenMAC import MyencryptMAC,MydecryptMAC,MyfileEncryptMAC,MyfileDecryptMAC,MyRSAEncryptMAC,MyRSADecryptMAC,GenerateRSAKeyPair
fileList = os.listdir("C:\\Users\\Kevin\\Desktop\\Work")
for i in [x for x in fileList if x != "RSA_Privatekey.pem" and x != "RSA_Publickey.pem"]:
	MyRSADecryptMAC("C:\\Users\\Kevin\\Desktop\\Work\\"+i,"C:\\Users\\Kevin\\Desktop\\Work\\RSA_Privatekey.pem")
	os.remove("C:\\Users\\Kevin\\Desktop\\Work\\"+i)
	print(i,"was recovered")
