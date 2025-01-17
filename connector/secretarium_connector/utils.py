def increment_by(src: bytes, offset: bytes) -> bytes:
    inc = bytearray(src)
    sz_diff = len(src) - len(offset)

    for j in range(len(offset) - 1, -1, -1):
        carry = offset[j]
        for i in range(j + sz_diff, -1, -1):
            if inc[i] + carry > 255:
                inc[i] = (inc[i] + carry) - 256
                carry = 1
            else:
                inc[i] += carry
                break

    return bytes(inc)
