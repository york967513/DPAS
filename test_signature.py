from app.key_manager import generate_key_pair


private_key, public_key = generate_key_pair()


challenge = b"DPAS-V03-TEST-CHALLENGE"


signature = private_key.sign(
    challenge
)


print("Challenge:", challenge)
print("Signature length:", len(signature))


try:
    public_key.verify(
        signature,
        challenge
    )

    print("Signature verification: True")

except Exception:
    print("Signature verification: False")


try:
    public_key.verify(
        signature,
        b"WRONG-CHALLENGE"
    )

    print("Wrong challenge accepted: True")

except Exception:
    print("Wrong challenge accepted: False")
