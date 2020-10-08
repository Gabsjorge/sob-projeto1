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
        printf("----- Programa Teste: moduloCrypto -----\n");
        // Gets user input for using string message or hex message
        printf("Deseja enviar em string (1) ou em hexadeximal (2)? \n");
        scanf("%i", &input_op);
        // Having problems with \n when pressing ENTER, to fix it, using a getchar helps
        getchar();

        // Menu options after choosing message send type
        printf("Comandos: [opcoes] [mensagem]\n");
        printf("Opcoes disponiveis:\n  c -> Cifrar\n  d - Decrifar\n  h- Gerar Hash\n");
        printf("A mensagem pode ser qualquer coisa, desde que tenha ate 254 caracteres, sendo que os dois primeiro serao o comando e um espaco.\n");
        printf("Digite o comando que deseja executar:\n");
        scanf(" %[^\n]%*c", messageToSend);
        // Sugested by the teacher, to set the message using memset instead of strcpy
        memset(messageHexa,0,BUFFER_LENGTH);

        // Setting operation and space before the message
        messageHexa[0] = messageToSend[0];
        messageHexa[1] = messageToSend[1];

        /* Handle message send type chosen by user
         * Always changing to hexa, so the process of creating the hexa variable is easier
         * But prints the user message according to choise made earlier
         */
        if (input_op == 1) {    // Option: String

            /* Prints the message in hexadecimal format
             * Using i as the first hex character
             * And j as second hex character, for each character read in messageToSend
             */
            //for(int i = 2, j = 2; i < strlen(messageToSend); i++, j+=2)
            //    snprintf(&messageHexa[j], BUFFER_LENGTH-1, "%02hhx", (unsigned char)messageToSend[i]);
            //messageToSend[j] = '\0';

            //printf("Mensagem enviada ao dispositivo moduloCrypto [em string]:\n");

            // Prints the user message correctly
            //for(int i = 2; i < strlen(messageHexa); i++)
            //    printf("%02hhx ", (unsigned char)messageToSend[i]);
            //printf("\n");

            // In case the current fix doesn't work, make no treatment
            strcpy(messageHexa, messageToSend);

            printf("Mensagem enviada ao dispositivo moduloCrypto [em hexa]:\n");
            printf("%s\n", messageHexa);

        } else {                // Option: Hexadecimal
            // No treatment is needed because user already sent message in hexadecimal format
            strcpy(messageHexa, messageToSend);

            printf("Mensagem enviada ao dispositivo moduloCrypto [em hexa]:\n");
            printf("%s\n", messageHexa);
        }

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
        printf("A mensagem recebida do modulo eh: %s\n", messageReceived);

        printf("Deseja continuar os testes? (s para sim, q para sair): ");
        scanf("%c", &option);
        getchar();
    } while(option != 'q');

    // Closes the module file
    close(fd);
    printf("Fim do programa de testes: moduloCrypto\n");
    return 0;
}