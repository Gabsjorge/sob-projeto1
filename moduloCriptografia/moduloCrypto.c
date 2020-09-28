#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/fs.h> 
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
   
#define DEVICE_NAME "moduloCrypto"   
#define CLASS_NAME "moduloCrypto"  
#define BLOCK_SIZE 16 
#define TAM_MAX	256

MODULE_LICENSE("GPL");                                       
MODULE_AUTHOR("Beatriz Oliveira, Gabriela Jorge, José Victor Pires");                                
MODULE_DESCRIPTION("Crypto Device Driver")  
MODULE_VERSION("1.0");                                        

static int majorNumber;                        
static char message[TAM_MAX] = {0};                
static short size_of_message;            
static struct class*  moduloCryptoClass = NULL;    
static struct device* moduloCryptoDevice = NULL;  
static DEFINE_MUTEX(moduloCrypto_mutex);
static char *key_aux;
static char *key = "mensagem12345678"; 
static char *iv = "mensagem12345678";
module_param(key, charp, 0000);		//To allow arguments to be passed to your module, declare the variables that will take the values of the command line 
module_param(iv, charp, 0000);	//arguments as global and then use the module_param() macro, (defined in linux/moduleparam.h) to set the mechanism up

static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
static void moduloCrypto_cifrarEDecifrar(char *dados, int tam, char op);
static int moduloCrypto_hash(char *dados);
void textoParaHexa(char* texto, char* hexa, int tam);
void hexaParaTexto(char* texto, char* hexa);
static void hexdump(unsigned char *buf, unsigned int len);


static struct file_operations fops =
{
    .open = dev_open,
    .read = dev_read,
    .write = dev_write,
    .release = dev_release,
};


static int __init moduloCrypto_init(void) {

    printk(KERN_INFO "moduloCrypto: Initializing the moduloCrypto module\n");

    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
	
    if (majorNumber < 0) {
        printk(KERN_ALERT "moduloCrypto failed to register a major number\n");
        return majorNumber;
    }
    printk(KERN_INFO "moduloCrypto: registered correctly with major number %d\n", majorNumber);

    moduloCryptoClass = class_create(THIS_MODULE, CLASS_NAME);
	
    if (IS_ERR(moduloCryptoClass)) {             
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to register device class\n");
        return PTR_ERR(moduloCryptoClass);       
    }
    printk(KERN_INFO "moduloCrypto: device class registered correctly\n");

    moduloCryptodevice = device_create(moduloCryptoClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
	
    if (IS_ERR(moduloCryptoDevice)) {           
        class_destroy(moduloCryptoClass);        
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(moduloCryptoDevice);
    }
	
	mutex_init(&moduloCrypto_mutex);  //mutex sendo inicializado
	
	printk(KERN_INFO "moduloCrypto: device class created correctly\n");       //Inicializou corretamente
	
    return 0;
}

static void __exit moduloCrypto_exit(void) {
	mutex_destroy(&moduloCrypto_mutex);
    device_destroy(moduloCryptoClass, MKDEV(majorNumber, 0));    
    class_unregister(moduloCryptoClass);                         
    class_destroy(moduloCryptoClass);                            
    unregister_chrdev(majorNumber, DEVICE_NAME);            
    printk(KERN_INFO "moduloCrypto: Device removed!\n");
}


static int dev_open(struct inode *inodep, struct file *filep) {

	if(!mutex_trylock(&moduloCrypto_mutex)) //trava caso o file ja esteja aberto
	{
		printk(KERN_ALERT "moduloCrypto: Device already opened by other user!");
		return -EBUSY;
	}  

	printk(KERN_INFO "moduloCrypto: Device opened!\n");
	return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
    
	int error_count = 0;
    
    error_count = copy_to_user(buffer, message, size_of_message);

    if (error_count = 0) {              
        printk(KERN_INFO "moduloCrypto: Sent %d characters to the user\n", size_of_message);
        return size_of_message;   
    }
    else {
        printk(KERN_INFO "moduloCrypto: Failed to send %d characters to the user\n", error_count);
        return -EFAULT;                
    }
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {   //n esta completa 
    
	int i, retorno;
	char operacao, dados_convertidos[TAM_MAX] = {0}, dados[TAM_MAX] = {0};	
	
	pr_info("moduloCrypto: Received message: %s\n", message);
	
	operacao = message[0];
	
	for(i = 0; i < 16; i++)
	{
		dados[i] = message[i+2];
	}
	
	hexaParaTexto(dados_convertidos, dados);
	
	pr_info("moduloCrypto: Received data: %s\n", dados);
	pr_info("moduloCrypto: Converted data: %s\n", dados_convertidos);	
	

	switch(operacao){
		case 'c': 
			retorno = moduloCrypto_cifrarEDecifrar(dados_convertidos, (len - 2), operacao);  
		break;

		case 'd': 
			retorno = moduloCrypto_cifrarEDecifrar(dados_convertidos, (len - 2), operacao);
		break;

		case 'h':
			moduloCrypto_hash(dados_convertidos);			
		break;

		default:
			pr_info("moduloCrypto: ['%c'] is an invalid operation ...\n", operacao);
			return 0;
		break;
	}
	
	message[size_of_message] = '\0';
	size_of_message = strlen(message); 
	printk(KERN_INFO "moduloCrypto: Received %zu characters from the user\n", len);

	return len;
}

static int dev_release(struct inode *inodep, struct file *filep) {
   
   mutex_unlock(&moduloCrypto_mutex);

   printk(KERN_INFO "moduloCrypto: Device closed!\n");
   
   return 0;
}

static void moduloCrypto_cifrarEDecifrar(char *dados, int tam, char op) //se der problema - pode ser referente ao tamanho da mensagem
{	
	char *iv_aux = NULL;
	char *scratchpad = NULL;
	char *msg = NULL;
	char *dados_dpsOp = NULL;
	struct scatterlist op_sg;   //https://www.kernel.org/doc/Documentation/crypto/api-intro.txt
	struct scatterlist scratchpad_sg; 
	struct skcipher_request *req = NULL; //symmetric key ciphers API - https://kernel.readthedocs.io/en/sphinx-samples/crypto-API.html
	struct crypto_skcipher *skcipher = NULL;
	int ret = -EFAULT, tam_scratchpad, i, blocks;
	
	
	iv_aux = kmalloc(BLOCK_SIZE, GFP_KERNEL);	
	for(i = 0; i < BLOCK_SIZE; i++)
	{
		if(i < strlen(iv);)
		{	
			iv_aux[i] = iv[i];
		}
		else 
		{
			iv_aux[i] = 0;
		}
	}

	/* struct crypto_skcipher * crypto_alloc_skcipher(const char * alg_name, u32 type, u32 mask)
	const char * alg_name - is the cra_name / name or cra_driver_name / driver name of the skcipher cipher
	u32 type - specifies the type of the cipher
	u32 mask - specifies the mask for the cipher	*/
	skcipher = crypto_alloc_skcipher("cbc(aes)", 0, 0); //allocate symmetric key cipher handle
    if (IS_ERR(skcipher)){
		pr_info("moduloCrypto_cifrarEDecifrar: Could not allocate skcipher handle!\n");
    	return PTR_ERR(skcipher);
	}

	/*struct skcipher_request * skcipher_request_alloc(struct crypto_skcipher * tfm, gfp_t gfp)
	struct crypto_skcipher * tfm - cipher handle to be registered with the request
	gfp_t gfp - memory allocation flag that is handed to kmalloc by the API call.
	***Description: Allocate the request data structure that must be used with the skcipher encrypt and decrypt API calls. 
	During the allocation, the provided skcipher handle is registered in the request data structure.	*/
	req = skcipher_request_alloc(skcipher, GFP_KERNEL); 
	if (!req) {
		pr_info("moduloCrypto_cifrarEDecifrar: Could not allocate skcipher request!\n");
		ret = -ENOMEM;
		goto out;
	}
	
	/*int crypto_skcipher_setkey(struct crypto_skcipher * tfm, const u8 * key, unsigned int keylen)
	struct crypto_skcipher * tfm - cipher handle
	const u8 * key - buffer holding the key
	unsigned int keylen - length of the key in bytes	
	***Description: The caller provided key is set for the skcipher referenced by the cipher handle. */
	if (crypto_skcipher_setkey(skcipher, key, BLOCK_SIZE)) { // set key for cipher
		pr_info("moduloCrypto_cifrarEDecifrar: Key could not be set!\n");
		ret = -EAGAIN;
		goto out;
	}
	 
	if(tam % BLOCK_SIZE) //Quantos blocos serao necessarios
	{
		blocks = 1 + (tam / BLOCK_SIZE); //caso n seja divisivel
	}
	else 
	{
		blocks = tam / BLOCK_SIZE; //caso seja divisivel
	}

	tam_scratchpad = blocks * BLOCK_SIZE;	
	scratchpad = kmalloc(tam_scratchpad, GFP_KERNEL); //kmalloc aloca memória
	msg = kmalloc(tam_scratchpad, GFP_KERNEL); 
	//Primeiro argumento: quantos bytes de memória são necessários. 
	//Segundo argumento: tipo de memória que se deseja alocar.
	
	if (!scratchpad || !msg) {
		pr_info("moduloCrypto_cifrarEDecifrar: Could not allocate scratchpad or msg!\n");
		goto out;
	}

	for(i = 0; i < tam_scratchpad;i++) //caso o tamanho da mensagem seja menor que o tamanho do buffer completa o restante do espaço da mensagem com 0.
	{
		if(i < tam) 
		{
			scratchpad[i] = dados[i];
		}
		else 
		{
			scratchpad[i] = 0;
		}
	}

	/*
	void sg_init_one	(	struct scatterlist * 	sg,
							const void * 	buf,
							unsigned int 	buflen 
						)		
	sg_init_one - Initialize a single entry sg list : SG entry : Virtual address for IO : IO length
	*/
	sg_init_one(&scratchpad_sg, scratchpad, tam_scratchpad); 
	sg_init_one(&op_sg, msg, tam_scratchpad); 
	

	/*void skcipher_request_set_crypt(struct skcipher_request * req, struct scatterlist * src, struct scatterlist * dst, unsigned int cryptlen, void * iv)
	struct skcipher_request * req - request handle
	struct scatterlist * src - source scatter / gather list
	struct scatterlist * dst - destination scatter / gather list
	unsigned int cryptlen -number of bytes to process from src
	void * iv - IV for the cipher operation which must comply with the IV size defined by crypto_skcipher_ivsize
	***Description: This function allows setting of the source data and destination data scatter / gather lists.	*/
	skcipher_request_set_crypt(req, &scratchpad_sg, &op_sg, tam_scratchpad,iv_aux); //parametros: requisição, origem, destino, tamanho, iv;

	switch (op) //diferenciando se eh para cifrar ou decifrar
	{
		case 'c': 
			/*int crypto_skcipher_encrypt(struct skcipher_request * req)
			struct skcipher_request * req
			req - reference to the skcipher_request handle that holds all information needed to perform the cipher operation
			*/
			ret = crypto_skcipher_encrypt(req);
			if(ret){
				pr_info("moduloCrypto_cifrarEDecifrar: Failed cryption!\n");
				goto out;
			}
			break;
		case 'd': 
			/*int crypto_skcipher_decrypt(struct skcipher_request * req)
			struct skcipher_request * req
			req - reference to the skcipher_request handle that holds all information needed to perform the cipher operation
			*/
			ret = crypto_skcipher_decrypt(req);
			if(ret){
				pr_info("moduloCrypto_cifrarEDecifrar: Failed decryption!\n");
				goto out;
			}
			break;
	}	

	dados_dpsOp = sg_virt(&op_sg); //sg_virt nesse caso retorna o endereço da scatterlist de destino da funçao skcipher_request_set_crypt()

	textoParaHexa(dados_dpsOp, message, tam_scratchpad);

out:
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	if (scratchpad)
		kfree(scratchpad);
	if (msg)
		kfree(msg);

	return ret;

}

static int moduloCrypto_hash(char *dados)
{
}

void hexaParaTexto(char *texto, char *hexa)
{
	int count = 0, i;
	long num;
	char msg[TAM_MAX] = {0}, aux[3];
                 
    for(i = 0; i < strlen(hexa); i++)
    {
		if(i%2!=0)
		{
			sprintf(aux,"%c%c",hexa[i-1],hexa[i]);
			kstrtol(aux, BLOCK_SIZE, &num);
			msg[count] = (char)num;
			
			count++;   
		}
    } 
    strcpy(texto,msg);
}


void textoParaHexa(char* texto, char* hexa, int tam) 
{
	unsigned char *aux = texto;
	int i = 0;
	while(tam--) 
	{ 
		sprintf(hexa+i, "%02x", *aux); 
		aux++; 
		i+=2; 
	}
	hexa[i] = 0;
}

static void hexdump(unsigned char *buf, unsigned int len) 
{
   while (len--)
		printk("%02x", *buf++);

	printk("\n");
}

module_init(moduloCrypto_init);
module_exit(moduloCrypto_exit);