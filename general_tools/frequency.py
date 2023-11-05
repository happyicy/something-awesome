s = "DXBNTWM GF ZGVVADXR WLGON NCT LGITB DX AGOV GVRWXDJWNDGXWQ ECWVN LT EGXETVXTM ZDNC NCT UTGUQT ZCG WVT LGITM DX"
freq = [0] * 26

for x in s:
    if x != ' ':
        freq[ord(x) - ord('A')] += 1
print(freq)