from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime

# Cria um contador automático de pacotes recebidos por IP de origem.
acessos_por_ip = defaultdict(int)

""" 
Exibe uma mensagem formatada 
- Com o tipo de ameaça, IP de origem e destino, hora do evento e detalhes adicionais
"""
def alerta(tipo, ip_src, ip_dst, detalhes=""):
    hora = datetime.now().strftime("%H:%M:%S")
    print(f"[{hora}] ALERTA ({tipo}): {ip_src} → {ip_dst} {detalhes}")

"""
Verifica as camadas de IP
src - ip de origem 
dst - ip de destino
"""
def analisar_pacote(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        acessos_por_ip[ip_src] += 1

        # Alerta de spoofing (origem igual ao destino - Falsificação de indetidade IP)
        if ip_src == ip_dst:
            alerta("SPOOFING", ip_src, ip_dst)

        # Alerta de varredura (acima de 100 pacotes do mesmo IP)
        if acessos_por_ip[ip_src] > 100:
            alerta("VARREDURA DE PORTAS", ip_src, ip_dst, "[+100 pacotes detectados]")

        """ 
        Verifica se o pacote contém protocolo TCP.
        Extrai as portas de origem (sport) e destino (dport) e os flags TCP
        Se uma porta estiver ausente, pode ser pacote malformado ou tentativa de evasão.
        """
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            flags = pkt[TCP].flags
            if not sport or not dport:
                alerta("TCP MALFORMADO", ip_src, ip_dst, f"Flags: {flags}")

        """
        Verifica se o pacote contém protocolo UDP.
        Se alguma porta estiver faltando, pode ser anomalia.
        """
        if UDP in pkt:
            if not pkt[UDP].sport or not pkt[UDP].dport:
                alerta("UDP MALFORMADO", ip_src, ip_dst)

        """
        Verifica se o pacote contém protocolo ICMP.
        Atacantes para reconhecimento de rede
        """
        if ICMP in pkt:
            alerta("ICMP", ip_src, ip_dst, "→ Detecção de pacote ICMP")

"""
Função principal que inicia a captura de pacotes.

- prn=analisar_pacote: para cada pacote capturado, executa a função analisar_pacote.
- store=False: não armazena os pacotes na memória (evita sobrecarga).
- iface=interface: permite definir a interface de rede
"""
def iniciar_sniffer(interface=None):
    print("Monitoramento de rede iniciado com Scapy...")
    sniff(prn=analisar_pacote, store=False, iface=interface)

"""
Executa a função principal ao rodar o script.
"""
if __name__ == "__main__":
    iniciar_sniffer()  