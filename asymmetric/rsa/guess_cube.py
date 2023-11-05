# Brute force cube via binary search
cube = 243251053617903760309941844835411292373350655973075480264001352919865180151222189820473358411037759381328642957324889519192337152355302808400638052620580409813222660643570085177957
r = 10**61
l = 1

while l <= r:
    mid = (l + r)//2
    if mid**3 <= cube:
        best_so_far = mid
        l = mid+1
    else:
        r = mid-1
print(best_so_far)