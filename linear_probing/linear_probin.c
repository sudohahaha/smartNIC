#include <nfp/mem_atomic.h>
#include <pif_plugin.h>
#include <pif_headers.h>
#include <nfp_override.h>
#include <pif_common.h>
#include <std/hash.h>
#include <nfp/me.h>

#define x1 1            //2^0
#define x2 x1, x1       //2^1
#define x4 x2, x2       //2^2
#define x8 x4, x4       //2^3
#define x16 x8, x8      //2^4
#define x32 x16, x16    //2^5
#define x64 x32, x32    //2^6
#define x128 x64, x64   //2^7
#define x256 x128, x128 //2^8

#define STATE_TABLE_SIZE 0xFF 

typedef struct bucket_entry_info {
    uint32_t hit_count; /* for timeouts */
} bucket_entry_info;


typedef struct bucket_entry {
    uint32_t key[2];
    bucket_entry_info bucket_entry_info_value;
}bucket_entry;

__shared __export __addr40 __emem bucket_entry state_hashtable[STATE_TABLE_SIZE + 1]; // 256

volatile __emem __export uint32_t global_semaphores[STATE_TABLE_SIZE + 1] = {x256};

void semaphore_down(volatile __declspec(mem addr40) void * addr) {
    unsigned int addr_hi, addr_lo;
    __declspec(read_write_reg) int xfer;
    SIGNAL_PAIR my_signal_pair;
    addr_hi = ((unsigned long long int)addr >> 8) & 0xff000000;
    addr_lo = (unsigned long long int)addr & 0xffffffff;
    do {
        xfer = 1;
        __asm {
            mem[test_subsat, xfer, addr_hi, <<8, addr_lo, 1],\
            sig_done[my_signal_pair];
            ctx_arb[my_signal_pair]
        }
        sleep(500);
    } while (xfer == 0);
}
void semaphore_up(volatile __declspec(mem addr40) void * addr) {
    unsigned int addr_hi, addr_lo;
    __declspec(read_write_reg) int xfer;
    addr_hi = ((unsigned long long int)addr >> 8) & 0xff000000;
    addr_lo = (unsigned long long int)addr & 0xffffffff;
    __asm {
        mem[incr, --, addr_hi, <<8, addr_lo, 1];
    }
}



int pif_plugin_lookup_state(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) {
    PIF_PLUGIN_ipv4_T *ipv4;
    
    volatile uint32_t hash_value;
    uint32_t  hash_key[2];
    __xread uint32_t hash_key_r[2];
    __addr40 __emem bucket_entry_info *b_info;

    __xwrite bucket_entry_info tmp_b_info;
    __addr40 uint32_t *key_addr;
    __xrw uint32_t key_val_rw[2];

    uint32_t i;

    ipv4 = pif_plugin_hdr_get_ipv4(headers);

    hash_key[0] = ipv4->srcAddr;
    hash_key[1] = ipv4->dstAddr;

    key_val_rw[0] = ipv4->srcAddr;
    key_val_rw[1] = ipv4->dstAddr;


    hash_value = hash_me_crc32((void *) hash_key,sizeof(hash_key), 1);
    hash_value &= (STATE_TABLE_SIZE);   
    

    i = hash_value;
    while( 1 ){

        mem_read_atomic(hash_key_r, state_hashtable[i].key, sizeof(hash_key_r));
        while( hash_key_r[0] != 0 ){
            if (hash_key_r[0] == hash_key[0] && hash_key_r[1] == hash_key[1]){
                __xrw uint32_t count;
                b_info = &state_hashtable[i].bucket_entry_info_value;
                count = 1;
                mem_test_add(&count,(__addr40 void *)&b_info->hit_count, 1 << 2);
                if (count == 0xFFFFFFFF-1) { /* Never incr to 0 or 2^32 */
                    count = 2;
                    mem_add32(&count,(__addr40 void *)&b_info->hit_count, 1 << 2);
                } else if (count == 0xFFFFFFFF) {
                    mem_incr32((__addr40 void *)&b_info->hit_count);
                }
                return PIF_PLUGIN_RETURN_FORWARD;
            }

            i = (i + 1) & STATE_TABLE_SIZE;
            if(i == hash_value){
                //Full
                return PIF_PLUGIN_RETURN_FORWARD;
            }

            mem_read_atomic(hash_key_r, state_hashtable[i].key, sizeof(hash_key_r));
        }

        semaphore_down(&global_semaphores[i]);
        if(hash_key_r[0] == 0){
            b_info = &state_hashtable[i].bucket_entry_info_value;
            key_addr =(__addr40 uint32_t *) state_hashtable[i].key;

            tmp_b_info.hit_count = 1;
            mem_write_atomic(&tmp_b_info, b_info, sizeof(tmp_b_info));
            mem_write_atomic(key_val_rw,(__addr40 void *)key_addr, sizeof(key_val_rw));

        }
        semaphore_up(&global_semaphores[i]);
        
        if (hash_key_r[0] == hash_key[0] && hash_key_r[1] == hash_key[1]){
            return PIF_PLUGIN_RETURN_FORWARD;
        }
    }


}


