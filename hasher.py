import hashlib


def test(src):
    bffer = 65536  # lets read stuff in 64kb chunks!

    md5 = hashlib.sha512()

    with open(src, "rb") as f:
        while True:
            data = f.read(bffer)
            if not data:
                break
            md5.update(data)

    print("MD5: {0}".format(md5.hexdigest()))
