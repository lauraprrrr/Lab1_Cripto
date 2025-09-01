from scapy.all import IP, ICMP, send
import sys, os, time, struct

def cifrado_cesar(texto, desplazamiento):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha(): 
            base = ord('a') if caracter.islower() else ord('A')
            resultado += chr((ord(caracter) - base + desplazamiento) % 26 + base)
        else:
            resultado += caracter
    return resultado

def linux_ping_payload_with_char(ch: str) -> bytes:
    now = time.time()
    tv_sec = int(now)
    tv_usec = int((now - tv_sec) * 1_000_000)
    timeval = struct.pack("<qq", tv_sec, tv_usec)  

    pattern = bytearray(range(0x10, 0x10 + 40))
    pattern[0] = ord(ch) & 0xFF 

    return timeval + bytes(pattern)  

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(f"Uso: sudo python3 {sys.argv[0]} <texto> <desplazamiento> <ip_destino>")
        sys.exit(1)

    texto = sys.argv[1]
    desplazamiento = int(sys.argv[2])
    destino = sys.argv[3]

    cifrado = cifrado_cesar(texto, desplazamiento)
    print(f"Texto cifrado: {cifrado}")

    icmp_id = os.getpid() & 0xFFFF 

    for i, ch in enumerate(cifrado):
        payload = linux_ping_payload_with_char(ch)
        paquete = IP(dst=destino)/ICMP(type="echo-request", id=icmp_id, seq=i)/payload
        print(f"Enviando carácter '{ch}' en paquete ICMP seq={i}")
        send(paquete, verbose=False)
