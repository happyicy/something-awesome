a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
b = a[:26][::-1] + a[26:][::-1]

s = "MTNR3X6VPNGF3X6FYAOSTZ6FYIP"
result = ""
for x in s:
    if 'A' <= x <= 'Z' or 'a' <= x <= 'z':
        result += b[a.find(x)]
    else:
        result += x
        
print(result)