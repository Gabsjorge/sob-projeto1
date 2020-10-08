# sob-projeto1
Projeto de Sistemas Operacionais B - Módulo Crypto

Passos para execução do módulo:

1º) Baixar os seguintes arquivos e os salvar na mesma pasta:
	
	- Makefile [1]
	- moduloCrypto.c [1]
	- test_file.c [2]
	
	Observações: [1] Ambos os arquivos estão na pasta moduloCriptografia.
			[2] Está na pasta test.	
			
2º) No terminal do Linux entrar com o comando sudo su para dar permissão de administrador;

	- $username@nome-da-maquina:~$sudo su
      [sudo] password for username: digite a senha

3º) Entrar na pasta onde estão salvos os arquivos;

	- cd caminho/ da/ pasta/
	
4º) Entrar com o comando make para compilar o módulo e o programa teste;

5º) Depois de finalizada a compilação entrar com o seguinte comando:

	-  insmod moduloCrypto.ko iv="0123456789ABCDEF" key="0123456789ABCDEF"
	
	Observação: iv e key podem conter outros valores de até 16 bytes, este é só um exemplo.

6º) Agora para executar o programa teste para ver o modulo em funcionamento digite:

	- ./teste
	
7º) Se quiser ver as mensagens enviadas pelo módulo utilizar o seguinte comando:

	- journalctl --since "1 hour ago" | grep kernel
	
8º) Caso precise remover o módulo dê o seguinte comando:

	- make clean