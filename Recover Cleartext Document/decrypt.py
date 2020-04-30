from Crypto.Cipher import DES
from tqdm import tqdm
import sys

seed = 0

def decrypt(key, filebytes):
    initialValue = bytes.fromhex("0000000000000000")
    santasCipher = DES.new(key, DES.MODE_CBC, iv=initialValue)

    return santasCipher.decrypt(filebytes)

def super_secure_srand(newSeed):
    global seed
    seed = newSeed

def super_secure_random():
    # Mutating the original seed
    global seed
    newSeed = seed
    newSeed = newSeed * 0x343fd
    newSeed = newSeed + 0x269ec3
    # Saving a changed seed
    seed = newSeed

    # Mixing it up a little more
    newSeed = newSeed >> 0x10
    newSeed = newSeed & 0x7fff
    return newSeed

def generate_key(randomSeed):
    keystring = ""
    super_secure_srand(randomSeed)
    for i in range(8):
        #We convert the random number we get into a bytearray, then we save the first byte for future operations
        keyElement = super_secure_random().to_bytes(10,byteorder="little")[0]

        keyElement = keyElement & 0xff
        keystring = keystring + format(keyElement, '02x')
    return keystring

def bruteforceFileSeed(filebytes, firstTimestamp, secondTimestamp):
    #Using tqdm to display a fancy progress bar as we loop through every time between our two timestamps
    for seed in tqdm(range(firstTimestamp,secondTimestamp)):
        key = generate_key(seed)
        decryptedFilebytes = decrypt(bytes.fromhex(key), filebytes)

        #Checking for PDF magic number
        if decryptedFilebytes[0:4] == bytes.fromhex("25504446"):
            tqdm.write("Success with key "+ str(key) + " and seed " + str(seed))
            return decryptedFilebytes
    #If we haven't found anything in the range, exit with an error
    print("Failure!")
    return None

with open(sys.argv[1], 'rb') as encryptedfile:
    #Begin the process
    decryptedFilebytes = bruteforceFileSeed(encryptedfile.read(), 1575658800, 1575666000)
    #If we've succeeded, write our decrypted bytes to the second file
    if decryptedFilebytes != None:
        with open(sys.argv[2], 'wb') as decryptedfile:
            decryptedfile.write(decryptedFilebytes)
