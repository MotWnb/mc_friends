import base64
import socket
import string
import stun

# Base62 编码和解码的字符集
BASE62_CHARS = string.ascii_uppercase + string.ascii_lowercase + string.digits


# Base62 编码函数
def base62_encode(num):
    if num == 0:
        return BASE62_CHARS[0]
    chars = []
    while num:
        num, rem = divmod(num, 62)
        chars.append(BASE62_CHARS[rem])
    return ''.join(reversed(chars))


# Base62 解码函数
def base62_decode(encoded_str):
    num = 0
    for char in encoded_str:
        num = num * 62 + BASE62_CHARS.index(char)
    return num


# 获取 STUN 服务器提供的公网 IP 和端口
def get_public_ip_port():
    nat_type, external_ip, external_port = stun.get_ip_info(stun_host="stun.syncthing.net")
    return f"{external_ip}:{external_port}"


# 加密 IP:Port
def encrypt_ip_port(ip_port):
    ip, port = ip_port.split(':')
    port_num = int(port)
    encoded_port = base62_encode(port_num)
    encoded_ip = base64.urlsafe_b64encode(ip.encode()).decode().rstrip('=')
    return f"{encoded_ip}:{encoded_port}"


# 解密 IP:Port
def decrypt_ip_port(encoded_ip_port):
    encoded_ip, encoded_port = encoded_ip_port.split(':')
    ip = base64.urlsafe_b64decode(encoded_ip.encode() + b'=' * (-len(encoded_ip) % 4)).decode()
    port_num = base62_decode(encoded_port)
    return f"{ip}:{port_num}"


# UDP 打洞尝试
def udp_hole_punching(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # 尝试发送数据到目标 IP 和端口
        sock.sendto(b"Hello", (ip, port))
        # 等待接收数据
        data, _ = sock.recvfrom(1024)
        print(f"Received: {data}")
    except socket.error as e:
        print(f"UDP hole punching failed: {e}")
    finally:
        sock.close()


# 主程序
if __name__ == "__main__":
    # 获取并加密公网 IP 和端口
    public_ip_port = get_public_ip_port()
    print(f"Public IP:Port: {public_ip_port}")
    encrypted_ip_port = encrypt_ip_port(public_ip_port)
    print(f"Encrypted IP:Port: {encrypted_ip_port}")

    # 让用户输入加密后的信息进行解密
    user_input = input("Enter the encrypted IP:Port to decrypt: ")
    decrypted_ip_port = decrypt_ip_port(user_input)
    print(f"Decrypted IP:Port: {decrypted_ip_port}")

    # UDP 打洞尝试
    ip, port = decrypted_ip_port.split(':')
    udp_hole_punching(ip, int(port))
