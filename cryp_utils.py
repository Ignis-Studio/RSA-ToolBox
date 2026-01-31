from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def generate_rsa_keys(bits=2048):
    """
    生成 RSA 密钥对
    """
    try:
        key = RSA.generate(bits)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key
    except Exception as e:
        print(f"生成失败: {e}")
        return None, None

def sign_message(private_key_data, message):
    """
    签名
    """
    try:
        key = RSA.import_key(private_key_data)
        if isinstance(message, str):
            message = message.encode('utf-8')
        h = SHA256.new(message)
        signature = pkcs1_15.new(key).sign(h)
        return signature
    except Exception as e:
        print(f"签名失败: {e}")
        return None

def verify_signature(public_key_data, message, signature):
    """
    验签
    """
    try:
        key = RSA.import_key(public_key_data)
        if isinstance(message, str):
            message = message.encode('utf-8')
        h = SHA256.new(message)
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def check_key_validity(key_data):
    """
    验证密钥有效性：
    pycryptodome 在 import_key 时会自动校验密钥参数(n, e, d, p, q)的一致性。
    如果能成功 import，说明密钥就是有效的。
    """
    try:
        key = RSA.import_key(key_data)
        # 如果是私钥，可以检查是否有私钥部分
        if key.has_private():
            return True # 私钥有效
        else:
            return True # 公钥有效
    except Exception:
        return False

# --- 测试 ---
if __name__ == "__main__":
    # 1. 生成
    priv, pub = generate_rsa_keys(2048)
    
    # 2. 验证有效性 (修正版)
    print(f"私钥有效性: {check_key_validity(priv)}")
    print(f"公钥有效性: {check_key_validity(pub)}")
    print(f"错误数据测试: {check_key_validity(b'Im not a key')}")

    # 3. 签名与验签
    msg = "Test Message"
    sig = sign_message(priv, msg)
    if sig:
        verify_result = verify_signature(pub, msg, sig)
        print(f"验签结果: {verify_result}")