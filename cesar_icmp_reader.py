from scapy.all import sniff, ICMP
import string


FREQ_ES = {
    'a': 12.53, 'b': 1.42, 'c': 4.68, 'd': 5.86, 'e': 13.68, 'f': 0.69,
    'g': 1.01, 'h': 0.70, 'i': 6.25, 'j': 0.44, 'k': 0.00, 'l': 4.97,
    'm': 3.15, 'n': 6.71, 'o': 8.68, 'p': 2.51, 'q': 0.88, 'r': 6.87,
    's': 7.98, 't': 4.63, 'u': 3.93, 'v': 1.05, 'w': 0.01, 'x': 0.22,
    'y': 0.90, 'z': 0.52
}


def descifrar_cesar(texto_cifrado, desplazamiento):
    resultado = ""
    for c in texto_cifrado:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            resultado += chr((ord(c) - base - desplazamiento) % 26 + base)
        else:
            resultado += c
    return resultado


def score_frecuencia(texto):
    texto = texto.lower()
    score = 0
    for c in texto:
        if c in FREQ_ES:
            score += FREQ_ES[c]
    return score


def capturar_caracteres(interface=None, filtro=None, max_paquetes=50):
    caracteres = []

    def procesar_pkt(pkt):
        if ICMP in pkt and pkt[ICMP].type == 8:  
            payload = bytes(pkt[ICMP].payload)
            if len(payload) >= 17: 
                ch = chr(payload[16])
                caracteres.append(ch)
                print(f"Carácter recibido: '{ch}'")

    sniff(iface=interface, filter=filtro, prn=procesar_pkt, count=max_paquetes)
    return "".join(caracteres)

if __name__ == "__main__":
    print("Capturando paquetes ICMP... presiona Ctrl+C para detener si es necesario.")
    texto_cifrado = capturar_caracteres(filtro="icmp", max_paquetes=50)
    print(f"\nTexto cifrado recibido: {texto_cifrado}\n")


    resultados = []
    for desplazamiento in range(26):
        descifrado = descifrar_cesar(texto_cifrado, desplazamiento)
        score = score_frecuencia(descifrado)
        resultados.append((desplazamiento, descifrado, score))


    mejor_score = max(r[2] for r in resultados)
    mejores = [r for r in resultados if r[2] == mejor_score]


    for desplazamiento, descifrado, score in resultados:
        if score == mejor_score:
            print(f"\033[92mDesplazamiento {desplazamiento}: {descifrado}\033[0m")
        else:
            print(f"Desplazamiento {desplazamiento}: {descifrado}")


    print(f"\nTexto más probable: \033[92m{mejores[0][1]}\033[0m")
