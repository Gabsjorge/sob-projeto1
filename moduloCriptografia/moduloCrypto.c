#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h> 
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <crypto/hash.h>
   
#define DEVICE_NAME "moduloCrypto"   
#define CLASS_NAME "moduloCrypto"  
#define CRYPTO_BLOCK_SIZE 16 
#define TAM_MAX	256
#define CRYPTO_skcipher_MODE_CBC 0
#define CRYPTO_skcipher_MODE_MASK 0     

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
//static char key_aux[16];
//static char iv_aux[16];
static char key[17];
static char iv[17];
module_param_string(key,key,17,0);		//To allow arguments to be passed to your module, declare the variables that will take the values of the command line 
module_param_string(iv,iv,17,0);  		//arguments as global and then use the module_param() macro, (defined in linux/moduleparam.h) to set the mechanism up

static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
static void moduloCrypto_cifrar(char *dados);
static int moduloCrypto_decifrar(char *dados);
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
    
	int i, len_buffer;
	char operacao, dados_convertidos[TAM_MAX] = {0}, dados[TAM_MAX] = {0};
	
	sprintf(message, "%s(%zu letters)", buffer, len);  
	pr_info("moduloCrypto: Received message: %s\n", message);
	
	operacao = message[0];
	
	for(i = 0; i < 16; i++){
		data[i] = message[i+2];
	}

	message[len-2] = '\0';
	
	hexaParaTexto(dados_convertidos, dados);
	
	pr_info("moduloCrypto: Received data: %s\n", dados);
	pr_info("moduloCrypto: Converted data: %s\n", dados_convertidos);	
	

	switch(operacao){
		case 'c': 
			moduloCrypto_cifrar(dados_convertidos);
		break;

		case 'd': 
			moduloCrypto_decifrar(dados_convertidos);
		break;

		case 'h':
			moduloCrypto_hash(dados_convertidos);			
		break;

		default:
			pr_info("moduloCrypto: ['%c'] is an invalid operation ...\n", operacao);
			return 0;
		break;
	}
	
	size_of_message = strlen(message);                 // store the length of the stored message
	printk(KERN_INFO "moduloCrypto: Received %zu characters from the user\n", len);

	return len;
}

static int dev_release(struct inode *inodep, struct file *filep) {
   
   mutex_unlock(&moduloCrypto_mutex);

   printk(KERN_INFO "moduloCrypto: Device closed!\n");
   
   return 0;
}


static void moduloCrypto_cifrar(char *dados)
{
}

static void moduloCrypto_decifrar(char *dados)
{
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
			kstrtol(aux, CRYPTO_BLOCK_SIZE, &num);
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

static void hexdump(unsigned char *buf, unsigned int len) //O len está recebendo o tamanho da scatterlist
{
   while (len--)
		printk("%02x", *buf++);

	printk("\n");
}

module_init(moduloCrypto_init);
module_exit(moduloCrypto_exit);