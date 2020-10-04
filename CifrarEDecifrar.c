//1- Será que é preciso alocar uma nova região do Kernel para a criptografica e descriptografia?
//2- crypto_skcipher_encrypt x crypto_skcipher_encrypt?
//3- Linha 175. Usando o KERN_ERR para sucesso
//4- crypto_alloc_skcipher x crypto_alloc_tfm


/* 
 * Simple demo explaining usage of the Linux kernel CryptoAPI.
 * By Michal Ludvig <michal@logix.cz>
 *    http://www.logix.cz/michal/
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <asm/scatterlist.h>

#define PFX "cryptoapi-demo: "

MODULE_AUTHOR("Michal Ludvig <michal@logix.cz>");
MODULE_DESCRIPTION("Simple CryptoAPI demo");
MODULE_LICENSE("GPL");

/* ====== CryptoAPI ====== */

#define DATA_SIZE       16

#define FILL_SG(sg,ptr,len)     do { (sg)->page = virt_to_page(ptr); (sg)->offset = offset_in_page(ptr); (sg)->length = len; } while (0)

static void
hexdump(unsigned char *buf, unsigned int len)//O len está recebendo o tamanho da scatterlist
{
        while (len--)
                printk("%02x", *buf++);

        printk("\n");
}

static void
cryptoapi_demo(void)
{
        /* config options */
        char *algo = "aes";
        int mode = CRYPTO_TFM_MODE_CBC;
        char key[16], iv[16];

        /* local variables */
        struct crypto_tfm *tfm;
        struct scatterlist sg[8];
        int ret;
        char *input, *encrypted, *decrypted;

        memset(key, 0, sizeof(key));//Preenchendo todos os espaços com 0 (Será melhor explicada depois)
        memset(iv, 0, sizeof(iv));//Preenchendo todos os espaços com 0

        tfm = crypto_alloc_tfm (algo, mode); //Alocando o tfm (Entretanto ñ achei a explicação da função)
		

        if (tfm == NULL) {
                printk("failed to load transform for %s %s\n", algo, mode == CRYPTO_TFM_MODE_CBC ? "CBC" : "");
                return;
        }



        ret = crypto_cipher_setkey(tfm, key, sizeof(key)); //Esta função seta uma key para o cipher
		//0 para sucesso e -0 para fracasso

        if (ret) {
                printk(KERN_ERR PFX "setkey() failed flags=%x\n", tfm->crt_flags);
                goto out;
        }

        input = kmalloc(GFP_KERNEL, DATA_SIZE);//kmalloc aloca memória
		//Primeiro argumento: quantos bytes de memória são necessários. GFP_KERNEL: Aloca una memória normal pro Kernel
		//Segundo argumento: tipo de memória que se deseja alocar. GFP_KERNEL: definido como 16
		
		
		
        if (!input) {
                printk(KERN_ERR PFX "kmalloc(input) failed\n");
                goto out;
        }
		
		
		
		
		

        encrypted = kmalloc(GFP_KERNEL, DATA_SIZE);
		
		
		
		
		
		
        if (!encrypted) {
                printk(KERN_ERR PFX "kmalloc(encrypted) failed\n");
                kfree(input);
                goto out;
        }
		
		
		
		
		

        decrypted = kmalloc(GFP_KERNEL, DATA_SIZE);
		
		
        if (!decrypted) {
                printk(KERN_ERR PFX "kmalloc(decrypted) failed\n");
                kfree(encrypted);
                kfree(input);
                goto out;
        }





        memset(input, 0, DATA_SIZE);//Primeiro argumento: ponteiro para um bloco de memória para preencher
									//Segundo argumento: valor que será preenchido
									//Terceiro argumento: número de bytes que será setado
		//Seta os primeiros num (terceiro parâmetro - DATA_SIZE) do bloco que é apontado por ptr (primeiro parâmetro - input)
		//com um número específico (segundo parâmetro - 0)
		
		
		
		//As 3 próximas funções serão necessárias para preenchimento das scatterlist
		//Nesse exemplo temos 8 posições de scatterlist
        FILL_SG(&sg[0], input, DATA_SIZE); //Primeiro input
        FILL_SG(&sg[1], encrypted, DATA_SIZE);//Segundo criptografia
        FILL_SG(&sg[2], decrypted, DATA_SIZE);//Terceiro descriptografia
		
		
		

        crypto_cipher_set_iv(tfm, iv, crypto_tfm_alg_ivsize (tfm));//Mesmo esta linha setando o IV, imagino que está linha seja dispensável, pois a próxima função pode receber o iv como parâmetro
		
		
		
		
		
        ret = crypto_cipher_encrypt(tfm, &sg[1], &sg[0], DATA_SIZE); //crypto_cipher_decrypt x crypto_skcipher_encrypt????
		//ret = crypto_cipher_encrypt(tfm, &sg[1], &sg[0], DATA_SIZE, iv);//Adicionando mais 1 argumento a função (iv)
		
		
        if (ret) {
                printk(KERN_ERR PFX "encryption failed, flags=0x%x\n", tfm->crt_flags);
                goto out_kfree;
        }






        crypto_cipher_set_iv(tfm, iv, crypto_tfm_alg_ivsize (tfm));//Mesma situação das linhas anteriores
		
		
		
        ret = crypto_cipher_decrypt(tfm, &sg[2], &sg[1], DATA_SIZE);
        if (ret) {
                printk(KERN_ERR PFX "decryption failed, flags=0x%x\n", tfm->crt_flags);
                goto out_kfree;
        }

        printk(KERN_ERR PFX "IN: "); hexdump(input, DATA_SIZE);//Printk é um print para as coisas do kernel
        printk(KERN_ERR PFX "EN: "); hexdump(encrypted, DATA_SIZE);
        printk(KERN_ERR PFX "DE: "); hexdump(decrypted, DATA_SIZE);

        if (memcmp(input, decrypted, DATA_SIZE) != 0)
                printk(KERN_ERR PFX "FAIL: input buffer != decrypted buffer\n");
        else
                printk(KERN_ERR PFX "PASS: encryption/decryption verified\n");//Pq usar o argumento de erro do Kernel (KERN_ERR) nessa condição? Ao entrar nesse else não teria ocorrido sucesso?

out_kfree:
        kfree(decrypted);
        kfree(encrypted);
        kfree(input);

out:
        crypto_free_tfm(tfm);
}

/* ====== Module init/exit ====== */

static int __init
init_cryptoapi_demo(void)
{
        cryptoapi_demo();

        return 0;
}

static void __exit
exit_cryptoapi_demo(void)
{
}

module_init(init_cryptoapi_demo);
module_exit(exit_cryptoapi_demo);