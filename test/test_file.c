/**
 * @file    test_file.c
 * @author  Beatriz Nunes, Gabriela Jorge e José Pires
 * @date    30 September 2020
 * @version 0.1
 * @brief   Program used for testing the moduloCrypto module created by the authors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_LENGTH 256                       ///< The buffer length
static char messageReceived[BUFFER_LENGTH];     ///< The received message from the moduloCrypto

int main() {
    int ret, fd, input_op = 0;
    char messageToSend[BUFFER_LENGTH], option = 'a';

    fflush(stdin);
    // Opens the module file created inside folder /dev
    printf("Começando testes no módulo de criptografia: moduloCrypto\n");
    fd = open("/dev/moduloCrypto", O_RDWR);
    if (fd < 0) {
        perror("[ERRO] Falha ao abrir o dispositivo moduloCrypto...");
        return errno;
    }

    // Menu loop
    do {
        printf("----- Programa Teste: moduloCrypto -----\n");
        // Gets user input for using string message or hex message
        printf("Deseja enviar em string (1) ou em hexadeximal (2)? \n");
        scanf("%i", input_op);

        // Menu options after choosing message send type
        printf("Comandos: [opcoes] [mensagem]\n");
        printf("Opcoes disponiveis:\n  c -> Cifrar\n  d - Decrifar\n  h- Gerar Hash\n");
        printf("A mensagem pode ser qualquer coisa, desde que tenha ate 254 caracteres, sendo que os dois primeiro serao o comando e um espaco.\n");
        printf("Digite o comando que deseja executar:\n");
        scanf("%[^\n]%*c", messageToSend);
        // Sugested by the teacher, to set the message using memset instead of strcpy
        memset(messageReceived,0,BUFFER_LENGTH);

        // Setting operation and space before the message
        messageReceived[0] = messageToSend[0];
        messageReceived[1] = messageToSend[1];


        printf("Mensagem enviada ao modulo: [%s].\n", messageReceived);

        // Handle message send type chosen by user
        if (input_op == 1) {
            
        }

    } while(option != 'q');

    
    ret = write(fd, messageToSend, strlen(messageToSend));    // Send the string to the LKM
    if (ret < 0) {
        perror("[ERRO] Falha ao escrever mensagem no dispositivo moduloCrypto.");
        return errno;
    }

    printf("Pressione ENTER para ler a resposta do dispositivo...\n");
    getchar();

    printf("Lendo do arquivo do dispositivo moduloCrypto...\n");
    ret = read(fd, messageReceived, BUFFER_LENGTH);
    if (ret < 0) {
        perror("[ERRO] Falha ao ler mensagem vinda do dispositivo moduloCrypto.");
        return errno;
    }

    close(fd);                          // Closes the module file
    printf("Fim do programa de testes: moduloCrypto\n");
    return 0;
}