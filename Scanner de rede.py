
from datetime import datetime, timedelta
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
import nmap
import traceback


def escanear_rede(rede):
    """Escaneia a rede e retorna uma lista de dispositivos ativos."""
    requisicao_arp = ARP(pdst=rede)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    pacote = broadcast / requisicao_arp
    resposta = srp(pacote, timeout=1, verbose=False)[0]

    dispositivos = []
    for _, recebido in resposta:
        dispositivos.append({"ip": recebido.psrc, "mac": recebido.hwsrc})

    return dispositivos


def escanear_portas(ip):
    """Escaneia as portas abertas em um IP específico usando Nmap."""
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments='-p 1-1024 --open')  # Escaneia portas de 1 a 1024
    portas_abertas = []

    # Verifica se o IP está no resultado do escaneamento antes de tentar acessar as portas
    if ip in scanner.all_hosts():
        for porta in scanner[ip]['tcp']:
            if scanner[ip]['tcp'][porta]['state'] == 'open':
                portas_abertas.append(porta)
    else:
        print(f"\n[!] Nmap não conseguiu escanear o IP: {ip}")

    return portas_abertas


def scanner_continuo(rede, duracao):
    """Executa o scanner continuamente até o tempo determinado pelo usuário."""
    fim = datetime.now() + timedelta(minutes=duracao)

    print(f"\n[+] Executando scanner por {duracao} minutos...\n")

    try:
        while datetime.now() < fim:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Escaneando a rede...\n")
            dispositivos = escanear_rede(rede)

            if not dispositivos:
                print("Nenhum dispositivo encontrado.\n")
            else:
                print("Dispositivos encontrados:")
                for idx, dispositivo in enumerate(dispositivos, start=1):
                    print(f"{idx}. IP: {dispositivo['ip']} - MAC: {dispositivo['mac']}")

                print("\n[+] Escaneando portas abertas...\n")
                for dispositivo in dispositivos:
                    ip = dispositivo["ip"]
                    try:
                        portas = escanear_portas(ip)
                        print(f"IP: {ip} - Portas abertas: {portas if portas else 'Nenhuma'}")
                    except Exception as e:
                        print(f"\n[!] Erro ao escanear {ip}:")
                        print(traceback.format_exc())  # Exibe o erro completo

            # Se o tempo acabou, o loop para automaticamente
            if datetime.now() >= fim:
                print("\n[+] Tempo de execução atingido. Encerrando o scanner.")
                break

    except KeyboardInterrupt:
        print("\n[!] Scanner interrompido pelo usuário.")


def main():
    rede = input("Digite a rede (ex: 192.168.1.0/24): ")
    duracao = int(input("Digite o tempo de execução (em minutos): "))

    scanner_continuo(rede, duracao)


if __name__ == "__main__":
    main()
