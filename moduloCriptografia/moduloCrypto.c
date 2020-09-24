#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
   
#define DEVICE_NAME "moduloCrypto"   
#define CLASS_NAME "moduloCrypto"  
#define CRYPTO_BLOCK_SIZE 16 
#define MAX_MESSAGE	256
#define SHA1_DIG_SIZ 32     

MODULE_LICENSE("GPL");                                       
MODULE_AUTHOR("Beatriz Oliveira, Gabriela Jorge, José Victor Pires");                                
MODULE_DESCRIPTION("Crypto Device Driver")  
MODULE_VERSION("1.0");                                        

static int majorNumber;                        
static char message[MAX_MESSAGE] = {0};                
static short size_of_message;            
static struct class*  moduloCryptoClass = NULL;    
static struct device* moduloCryptoDevice = NULL;  
static char *iv;
static char *key;
static DEFINE_MUTEX(moduloCrypto_mutex);

static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
static void moduloCrypto_cifrar(char *dados);
static int moduloCrypto_decifrar(char *dados);
static int moduloCrypto_hash(char *dados);
void textoParaHexa(char* texto, char* hexa, int tam);
void hexaParaTexto(char* texto, char* hexa);

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
    printk(KERN_INFO "moduloCrypto: device class created correctly\n");       //Inicializou corretamente
	
	mutex_init(&moduloCrypto_mutex);  //mutex sendo inicializado
	
	
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
    
	char operacao, dados_convertidos[MAX_MESSAGE] = {0}, dados[MAX_MESSAGE] = {0};
	
	hexaParaTexto(dados_convertidos, dados);

	switch(operacao){
		case 'c': 
			moduloCrypto_cifrar(dados_convertidos);
		break;

		case 'd': 
			moduloCrypto_decifrar(dados_convertidos);
		break;

		case 'h':
            pr_info("moduloCrypto: Fazendo hash dos dados convertidos");
			moduloCrypto_hash(dados_convertidos);			
		break;

		default:
			pr_info("moduloCrypto: Invalid operation ['%c']...\n", operacao);
			return 0;
		break;
	}

	return;
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
    pr_info("Messagem antes do hash: %s", dados);

    char resp[SHA1_DIG_SIZ]; // variable string that will store hash digest
    struct shash_desc *sdesc;
    int size, ret;

    // Allocating transformation struct to have the synchronous hash => algorithm, type (check /proc/crypto on "sha1"), mask
    struct crypto_shash *tfm;
    tfm = crypto_alloc_shash("sha1",0,0);

    // Failed to allocate hash handler
    if (IS_ERR(tfm)) {
        pr_alert("moduloCrypto: can't allocate hash handler");
        return PTR_ERR(tfm);
    }

    // Getting size for hash transformation struct, and allocation size
    size = sizeof(*sdesc) + crypto_shash_descsize(tfm);
    sdesc = kmalloc(size, GFP_KERNEL);

    // Allocation size for hash digest response
    resp = kmalloc(SHA1_DIG_SIZ);

    // Setting the transformation struct and flags for hash handler
    sdesc->tfm = tfm;
    sdesc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;    

    ret = crypto_shash_digest(sdesc, dados, strlen(dados), resp);
    if (ret) {
        pr_alert("moduloCrypto: failed to process hash");
        return PT_ERR(ret);
    }
    kfree(sdesc);

    pr_info("Messagem após o hash: %s", resp);

    return ret;
}

void hexaParaTexto(char *texto, char *hexa)
{
    
	int count = 0, i;
	long num;
	char msg[MAX_MESSAGE] = {0}, aux[3];
                 
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


module_init(moduloCrypto_init);
module_exit(moduloCrypto_exit);