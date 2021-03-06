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
static char messageReceived[BUFFER_LENGTH * 2];     ///< The received message from the moduloCrypto

int main() {
    int ret, fd, j, input_op = 0;
    char messageToSend[BUFFER_LENGTH], messageHexa[BUFFER_LENGTH], option = 'a';

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
        system("clear");
        printf("----- Programa Teste: moduloCrypto -----\n");
        // Gets user input for using string message or hex message

        // Having problems with \n when pressing ENTER, to fix it, using a getchar helps
      //  getchar();

        // Menu options after choosing message send type
        printf("\nOpcoes disponiveis:\n c -> Cifrar\n d -> Decrifar\n h -> Gerar Hash\n");
        printf("\nFormato da mensagem: [opcao escolhida] [mensagem]\n");
        printf("  A mensagem pode ser qualquer coisa, desde que tenha ate 254 caracteres.\n");
        printf("\nDigite a [opcao escolhida] seguida de um [espaco] depois escreva a [mensagem desejada]:\n");
        scanf(" %[^\n]%*c", messageToSend);
        // Sugested by the teacher, to set the message using memset instead of strcpy
        memset(messageHexa,0,BUFFER_LENGTH);

        // Setting operation and space before the message
        messageHexa[0] = messageToSend[0];
        messageHexa[1] = messageToSend[1];


        strcpy(messageHexa, messageToSend);

        ret = write(fd, messageToSend, strlen(messageToSend));    // Send the string to the LKM
        if (ret < 0) {
            perror("[ERRO] Falha ao escrever mensagem no dispositivo moduloCrypto.\n");
            return errno;
        }

        printf("Pressione ENTER para ler a resposta do dispositivo...\n");
        getchar();

        printf("Lendo do arquivo do dispositivo moduloCrypto...\n");

        ret = read(fd, messageReceived, BUFFER_LENGTH);
        if (ret < 0) {
            perror("[ERRO] Falha ao ler mensagem vinda do dispositivo moduloCrypto.\n");
            return errno;
        }

        printf("Messagem recebida do moduloCrypto:\n");
        printf("%s\n", messageReceived);
        printf("\n");

        printf("Deseja continuar os testes? (s - sim, n - não): ");
        scanf("%c", &option);
        getchar();
    } while(option != 'n');

    // Closes the module file
    close(fd);
    printf("Fim do programa de testes: moduloCrypto\n");
    return 0;
}