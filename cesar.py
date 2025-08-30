def cifrado_cesar(texto, desplazamiento):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha(): 
            base = ord('a') if caracter.islower() else ord('A')
            resultado += chr((ord(caracter) - base + desplazamiento) % 26 + base)
        else:
            resultado += caracter
    return resultado


if __name__ == "__main__":
    entrada = input().strip().split()
    texto = entrada[0]
    desplazamiento = int(entrada[1])
    print(cifrado_cesar(texto, desplazamiento))
