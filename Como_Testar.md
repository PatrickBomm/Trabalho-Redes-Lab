Requisitos

    Sistema Operacional: O código foi desenvolvido e testado em sistemas Unix-like (Linux).
    Permissões de Superusuário: É necessário rodar o script como superusuário (root) para criar e manipular sockets raw.
    Python: Python 3.x deve estar instalado no sistema.

Passo 1: Preparar o Ambiente

    Instalar Dependências: Certifique-se de ter o Python 3.x instalado.

`sudo apt-get update`
`sudo apt-get install python3`

Passo 2: Rodar o Script

    Rodar o Script:
        Execute o script como superusuário, especificando a interface de rede e o endereço IP para spoofing. Por exemplo:

`sudo python3 dhcp_dns_spoofer.py enp0s3 192.168.1.100`

    Aqui, enp0s3 é a interface de rede que será usada para capturar e enviar pacotes. 192.168.1.100 é o endereço IP que será usado para spoofing nas respostas DHCP e DNS.

Testar o Spoofing DHCP:

Em outro terminal, execute o seguinte comando para solicitar um endereço IP via DHCP:
`sudo dhclient -v enp0s3`

    Este comando força a interface enp0s3 a solicitar um novo endereço IP do servidor DHCP (que será o seu spoofer). O -v habilita a saída verbose para visualizar o processo.

Passo 3: Verificar os Logs

    Logs de Solicitações e Respostas:
        O script imprime logs detalhados no terminal sobre as solicitações DHCP e DNS recebidas, bem como as respostas enviadas. Verifique os logs para confirmar que o spoofing está ocorrendo conforme esperado.

# Exemplo de Uso

Iniciar o Spoofer:
`sudo python3 dhcp_dns_spoofer.py enp0s3 192.168.1.100`

Saída esperada:


    Iniciando servidor DHCP...
    Solicitação DHCP Recebida:
    MAC de Origem: 08:00:27:5b:5b:5b, MAC de Destino: ff:ff:ff:ff:ff:ff
    IP de Origem: 0.0.0.0, IP de Destino: 255.255.255.255
    Construindo uma oferta DHCP!
    Resposta DHCP Enviada:
    MAC de Origem: 08:00:27:5b:5b:5b, MAC de Destino: ff:ff:ff:ff:ff:ff
    IP de Origem: 192.168.1.100, IP de Destino: 0.0.0.0
