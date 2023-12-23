from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes

ciphertext = "5999132603786515694957273606987251938960846251616857790319282952067471416160532445969753742022349402239881632818063061443208911252375978592059780660007751950789363015458851255071282948626823620357678575521276876890697220610835566118430705506789107445993666306026930071961388409536610958087692678358030672988672509813665298499071826836226920929145713575804401996420510840341658995543292921264185965194133049691940534609242323814139884782702996228520653358951414473579584737165450120652431329674412363554387882918038423851326540691314394857705588551803761033868771616490863194000807028327726852465587109639467888230672"
rsa_key = RSA.import_key(open("private.pem", "r").read())
phi = (rsa_key.p - 1) * (rsa_key.q - 1)
d = inverse(rsa_key.e * 101, phi)
plaintext = long_to_bytes(pow(int(ciphertext),d,rsa_key.n))
print(plaintext.decode())