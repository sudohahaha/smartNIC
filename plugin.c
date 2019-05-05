#include <nfp/mem_atomic.h>

#include <pif_plugin.h>

//#include <pkt_ops.h>

#include <pif_headers.h>

#include <nfp_override.h>

#include <pif_common.h>

#include <std/hash.h>

#include <nfp/me.h>


#define BUCKET_SIZE 12


#define STATE_TABLE_SIZE 0xF /* 16777200 state table entries available */



typedef struct bucket_entry_info {

    uint32_t hit_count;

} bucket_entry_info;



typedef struct bucket_entry {

    uint32_t key[3]; /* ip1, ip2, ports */

    bucket_entry_info bucket_entry_info_value;

}bucket_entry;





typedef struct bucket_list {

    // uint32_t ctl;

    struct bucket_entry entry[BUCKET_SIZE];

}bucket_list;

typedef struct tracking {
    
    uint32_t heap_arr[BUCKET_SIZE];
    uint32_t heap_size;
    uint32_t key_pointer_index[BUCKET_SIZE];
    
}tracking;

__shared __export __addr40 __emem bucket_list state_hashtable[STATE_TABLE_SIZE + 1];
__shared __export __addr40 __emem tracking heapify[STATE_TABLE_SIZE + 1];
__shared __export __addr40 __emem uint32_t heap_size_check;
//__shared __export __addr40 __emem uint32_t heap_arr_check;
//__shared __export __addr40 __emem uint32_t heap_keypointer_check;
//__shared __export __addr40 __emem uint32_t update_function_check;
int pif_plugin_state_update(EXTRACTED_HEADERS_T *headers,

                        MATCH_DATA_T *match_data)

{



    PIF_PLUGIN_ipv4_T *ipv4;

    PIF_PLUGIN_udp_T *udp;

    volatile uint32_t update_hash_value;

    uint32_t update_hash_key[3];


    __addr40 __emem bucket_entry_info *b_info;

    __xwrite bucket_entry_info tmp_b_info;

    __addr40 uint32_t *key_addr;

    __xrw uint32_t key_val_rw[3];

    __xread uint32_t heap_size_r;
    __xwrite uint32_t key_pointer_index_w;
    __xwrite uint32_t counter;
    __addr40 __emem tracking *heap_info;
    
//    __xwrite uint32_t keypointer_check_w;
//    __xwrite uint32_t heap_size_check_w;

    uint32_t i = 0;

    

    ipv4 = pif_plugin_hdr_get_ipv4(headers);

    udp = pif_plugin_hdr_get_udp(headers);



    /* TODO: Add another field to indicate direction ?*/

    update_hash_key[0] = ipv4->srcAddr;

    update_hash_key[1] = ipv4->dstAddr;

    update_hash_key[2] = (udp->srcPort << 16) | udp->dstPort;



    key_val_rw[0] = ipv4->srcAddr;

    key_val_rw[1] = ipv4->dstAddr;

    key_val_rw[2] = (udp->srcPort << 16) | udp->dstPort;



    update_hash_value = hash_me_crc32((void *)update_hash_key,sizeof(update_hash_key), 1);

    update_hash_value &= (STATE_TABLE_SIZE);

    //get the heap_size
    mem_read_atomic(&heap_size_r, &heapify[update_hash_value].heap_size, sizeof(heap_size_r));
    
    /* If bucket full, drop */
    if (heap_size_r == BUCKET_SIZE)
        return PIF_PLUGIN_RETURN_FORWARD;
    
    key_addr =(__addr40 uint32_t *) state_hashtable[update_hash_value].entry[heap_size_r].key;
    b_info = &state_hashtable[update_hash_value].entry[heap_size_r].bucket_entry_info_value;
    heap_info = &heapify[update_hash_value];
    
    //let the new key pointer index point to the new key memory addr.
    key_pointer_index_w = heap_size_r;
//    keypointer_check_w = heap_size_r;
    mem_write_atomic(&key_pointer_index_w, &heap_info->key_pointer_index[heap_size_r], sizeof(key_pointer_index_w));
    
//    heap_size_check_w = heap_size_r;
//    mem_write_atomic(&heap_size_check_w, (__addr40 void *)&heap_size_check, sizeof(heap_size_check_w));
//    mem_write_atomic(&keypointer_check_w, &heap_keypointer_check, sizeof(keypointer_check_w));
    
    //write the corresponding counter to heap_info
    counter = 1;
    mem_write_atomic(&counter, &heap_info->heap_arr[heap_size_r], sizeof(counter));

    tmp_b_info.hit_count = 1;
    
    mem_write_atomic(&tmp_b_info, b_info, sizeof(tmp_b_info));

    mem_write_atomic(key_val_rw,(__addr40 void *)key_addr, sizeof(key_val_rw));
//    mem_write_atomic(&i,&state_hashtable[update_hash_value].entry[i].test, sizeof(i));

    //increase the heap_size by 1
    mem_incr32(&heapify[update_hash_value].heap_size);
//    mem_incr32(&update_function_check);
    
    
    //heapify

    return PIF_PLUGIN_RETURN_FORWARD;

}


int pif_plugin_lookup_state(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) {



    PIF_PLUGIN_ipv4_T *ipv4;

    PIF_PLUGIN_udp_T *udp;

    volatile uint32_t hash_value;

    uint32_t  hash_key[3];

    __xread uint32_t hash_key_r[3];
    
    __xread uint32_t heap_size_r;
    
//    __xwrite uint32_t heap_arr_check_w;

    __addr40 bucket_entry_info *b_info;

    __addr40 tracking *heap_info;
    
    __xread uint32_t heap_arr_r[BUCKET_SIZE];
    __xread uint32_t key_pointer_index[BUCKET_SIZE];
    
    
    

    uint32_t i;
    uint32_t hash_entry_full; 
    uint32_t flow_entry_found; 


    ipv4 = pif_plugin_hdr_get_ipv4(headers);

    udp = pif_plugin_hdr_get_udp(headers);


    /* TODO: Add another field to indicate direction ?*/

    hash_key[0] = ipv4->srcAddr;

    hash_key[1] = ipv4->dstAddr;

    hash_key[2] = (udp->srcPort << 16) | udp->dstPort;



    //TODO: Change to toeplitz hash:

    //hash_value = hash_toeplitz(&hash_key,sizeof(hash_key),);

    //hash_value = hash_me_crc32((void *)hash_key,sizeof(hash_key), 10);

    hash_value = hash_me_crc32((void *) hash_key,sizeof(hash_key), 1);

    hash_value &= (STATE_TABLE_SIZE);   

    hash_entry_full = 1;
    flow_entry_found= 0;
    
    //read the heap_size
    mem_read_atomic(&heap_size_r, &heapify[hash_value].heap_size, sizeof(heap_size_r));
//    heap_size_check_w = heap_size_r;
//    mem_write_atomic(&heap_size_check_w, (__addr40 void *)&heap_size_check, sizeof(heap_size_check_w));
    if(heap_size_r < BUCKET_SIZE){
        hash_entry_full = 0;
    }
    for (i = 0; i < heap_size_r; i++) {

        mem_read_atomic(hash_key_r, state_hashtable[hash_value].entry[i].key, sizeof(hash_key_r)); /* TODO: Read whole bunch at a time */

        if (hash_key_r[0] == hash_key[0] &&

            hash_key_r[1] == hash_key[1] &&

            hash_key_r[2] == hash_key[2] ) { /* Hit */


            __xrw uint32_t count;

            flow_entry_found = 1;

            b_info = (__addr40 bucket_entry_info *)&state_hashtable[hash_value].entry[i].bucket_entry_info_value;

            heap_info = (__addr40 tracking *)&heapify[hash_value];
            count = 1;

            mem_test_add(&count,(__addr40 void *)&b_info->hit_count, 1 << 2);
            
            //for heap_arr
            mem_test_add(&count,(__addr40 void *)&heap_info->heap_arr[i], 1 << 2);
//            heap_arr_check_w = heap_info->heap_arr[i];
//            mem_write_atomic(&heap_arr_check_w, &heap_arr_check, sizeof(heap_arr_check_w));
            if (count == 0xFFFFFFFF-1) { /* Never incr to 0 or 2^32 */

                count = 2;

                mem_add32(&count,(__addr40 void *)&b_info->hit_count, 1 << 2);
                //for heap_arr
                mem_add32(&count,(__addr40 void *)&heap_info->heap_arr[i], 1 << 2);

            } else if (count == 0xFFFFFFFF) {

                mem_incr32((__addr40 void *)&b_info->hit_count);
                //for heap_arr
                mem_incr32((__addr40 void *)&heap_info->heap_arr[i]);

            }

            break;
//            return PIF_PLUGIN_RETURN_FORWARD;

        }

    }

    if(hash_entry_full == 1 || flow_entry_found == 1){
	return PIF_PLUGIN_RETURN_FORWARD;   
    }


  if (pif_plugin_state_update(headers, match_data) == PIF_PLUGIN_RETURN_DROP) {

        return PIF_PLUGIN_RETURN_DROP;

    }


    return PIF_PLUGIN_RETURN_FORWARD;

}

