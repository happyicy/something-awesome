import os
from Crypto.Util.number import long_to_bytes

class StepUpCounter(object):
    def __init__(self, step_up=False):
        self.value = os.urandom(16).hex()
        self.step = 1
        self.stup = step_up

    def increment(self):
        if self.stup:
            self.newIV = hex(int(self.value, 16) + self.step)
        else:
            self.newIV = hex(int(self.value, 16) - self.stup)
        self.value = self.newIV[2:len(self.newIV)]
        return bytes.fromhex(self.value.zfill(32))

    def __repr__(self):
        self.increment()
        return self.value
    

ctr = StepUpCounter()


fr = open("symmetric/bean_counter/image.txt", "r")
fw = open("symmetric/bean_counter/image_as_bytes.png", "wb")

b = bytes.fromhex(fr.read(32))

header = [137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82]

key = [x^y for x, y in zip(b, header)]
while b:
    for x,y in zip(b, key):
        fw.write(long_to_bytes(x^y))
    b = bytes.fromhex(fr.read(32))
    