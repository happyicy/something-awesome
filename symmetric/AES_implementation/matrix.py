def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """

    return bytes(sum(matrix, []))

# matrix = [[99, 114, 121, 112], [116, 111, 123, 100], [49, 102, 102, 85], [115, 51, 82, 125]]
# print(matrix2bytes(matrix))