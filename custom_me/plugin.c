#include <nfp/mem_atomic.h>

#include <pif_plugin.h>

//#include <pkt_ops.h>

#include <pif_headers.h>

#include <nfp_override.h>

#include <pif_common.h>

#include <std/hash.h>

#include <nfp/me.h>

#include <nfp.h>
#include <stdlib.h>

#include <stdint.h>
#include "plugin.h"
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
int pif_plugin_state_update(EXTRACTED_HEADERS_T *headers,
                            
                            MATCH_DATA_T *match_data)

{
    
    
    PIF_PLUGIN_ipv4_T *ipv4;
    
    PIF_PLUGIN_udp_T *udp;
    
    PIF_PLUGIN_tcp_T *tcp;
    
    volatile uint32_t update_hash_value;
    
    uint32_t update_hash_key[4];
    
    __xwrite uint32_t tmp_b_info;
    
    __xrw uint32_t key_val_rw0;
    __xrw uint32_t key_val_rw1;
    __xrw uint32_t key_val_rw2;
    __xrw uint32_t key_val_rw3;
    __xrw uint64_t time_xfer;
    unsigned long long int time;
    uint32_t low, high;
    
    __xrw uint32_t evict_rw0;
    __xrw uint32_t evict_rw1;
    __xrw uint32_t evict_rw2;
    __xrw uint32_t evict_rw3;
    __xrw uint32_t evict[7];
    __xrw uint32_t evict_val;
    __xrw uint32_t min_index = 0;
    uint32_t evict_hash_32;

    __xread uint32_t hash_key_r0;
    __xread uint32_t hash_key_r1;
    __xread uint32_t hash_key_r2;
    __xread uint32_t hash_key_r3;
    
    uint32_t i = 0;
    __addr40 __emem bucket_list *b_info;
    
    ipv4 = pif_plugin_hdr_get_ipv4(headers);
    udp = pif_plugin_hdr_get_udp(headers);
    tcp = pif_plugin_hdr_get_tcp(headers);
    
    update_hash_key[0] = ipv4->srcAddr;
    update_hash_key[1] = ipv4->dstAddr;
    if(pif_plugin_hdr_tcp_present(headers)){
        update_hash_key[2] = (tcp->srcPort << 16) | tcp->dstPort;
        update_hash_key[3] = 6;
    }else{
        update_hash_key[2] = (udp->srcPort << 16) | udp->dstPort;
        update_hash_key[3] = 17;
    }
    key_val_rw0 = ipv4->srcAddr;

    key_val_rw1 = ipv4->dstAddr;

    if(pif_plugin_hdr_tcp_present(headers)){
        key_val_rw2 = (tcp->srcPort << 16) | tcp->dstPort;
        key_val_rw3 = 6;
    }else{
        key_val_rw2 = (udp->srcPort << 16) | udp->dstPort;
        key_val_rw3 = 17;
    }
    update_hash_value = hash_me_crc32((void *)update_hash_key,sizeof(update_hash_key), 0);
    
    update_hash_value &= (STATE_TABLE_SIZE);
    
    
    semaphore_down(&global_semaphores[update_hash_value]);
    for (i = 0; i < BUCKET_SIZE; i++) {
        mem_read32(&hash_key_r0, &state_hashtable[update_hash_value].entry[i].key0, sizeof(hash_key_r0));
        mem_read32(&hash_key_r1, &state_hashtable[update_hash_value].entry[i].key1, sizeof(hash_key_r1));
        mem_read32(&hash_key_r2, &state_hashtable[update_hash_value].entry[i].key2, sizeof(hash_key_r2));
        mem_read32(&hash_key_r3, &state_hashtable[update_hash_value].entry[i].key3, sizeof(hash_key_r3));
        if (hash_key_r0 == update_hash_key[0] &&
            hash_key_r1 == update_hash_key[1] &&
            hash_key_r2 == update_hash_key[2] &&
            hash_key_r3 == update_hash_key[3]) { /* Hit */
            __xrw uint32_t count;
            b_info = &state_hashtable[update_hash_value];
            count = 1;
            mem_test_add(&count,&b_info->row[i], 1 << 2);
            if (count == 0xFFFFFFFF-1) { /* Never incr to 0 or 2^32 */
                count = 2;
                mem_add32(&count,&b_info->row[i], 1 << 2);
            } else if (count == 0xFFFFFFFF) {
                mem_incr32(&b_info->row[i]);
            }
            break;
        }
        else if (hash_key_r0 == 0) {
            b_info = &state_hashtable[update_hash_value];
            tmp_b_info = 1;
            
            mem_write32(&tmp_b_info, &b_info->row[i], sizeof(tmp_b_info));
            mem_write32(&key_val_rw0,&state_hashtable[update_hash_value].entry[i].key0, sizeof(key_val_rw0));
            mem_write32(&key_val_rw1,&state_hashtable[update_hash_value].entry[i].key1, sizeof(key_val_rw1));
            mem_write32(&key_val_rw2,&state_hashtable[update_hash_value].entry[i].key2, sizeof(key_val_rw2));
            mem_write32(&key_val_rw3,&state_hashtable[update_hash_value].entry[i].key3, sizeof(key_val_rw3));
            break;
        }
    }
    
    if (i == BUCKET_SIZE){
        tmp_b_info = 1;
        mem_read32(&min_index, &hash_table_min_track[update_hash_value], sizeof(min_index));
        mem_read32(&evict_rw0, &state_hashtable[update_hash_value].entry[min_index].key0, sizeof(evict_rw0));
        mem_read32(&evict_rw1, &state_hashtable[update_hash_value].entry[min_index].key1, sizeof(evict_rw1));
        mem_read32(&evict_rw2, &state_hashtable[update_hash_value].entry[min_index].key2, sizeof(evict_rw2));
        mem_read32(&evict_rw3, &state_hashtable[update_hash_value].entry[min_index].key3, sizeof(evict_rw3));
        mem_read32(&evict_val, &state_hashtable[update_hash_value].row[min_index], sizeof(evict_val));
        
        mem_write32(&tmp_b_info, &state_hashtable[update_hash_value].row[min_index], sizeof(tmp_b_info));
        mem_write32(&key_val_rw0,&state_hashtable[update_hash_value].entry[min_index].key0, sizeof(key_val_rw0));
        mem_write32(&key_val_rw1,&state_hashtable[update_hash_value].entry[min_index].key1, sizeof(key_val_rw1));
        mem_write32(&key_val_rw2,&state_hashtable[update_hash_value].entry[min_index].key2, sizeof(key_val_rw2));
        mem_write32(&key_val_rw3,&state_hashtable[update_hash_value].entry[min_index].key3, sizeof(key_val_rw3));
//        mem_incr32(&evict_count);
    }
    semaphore_up(&global_semaphores[update_hash_value]);
    if (i==BUCKET_SIZE){
        time = me_tsc_read();
        low = time & 0xFFFFFFFF;
    //    high = time >> 32 & 0xFFFFFFFF;
        evict_hash_32 = (evict_rw0 + evict_rw1 + evict_rw2 + evict_rw3) & 0xFFFFFFFF;
        evict[0] = evict_rw0;evict[1] = evict_rw1;evict[2] = evict_rw2;evict[3] = evict_rw3;evict[4] = evict_val;
        evict[5] = evict_hash_32;evict[6] = low;
        mem_write_atomic(evict, evict_buffer.record, sizeof(evict));
    }
    
    return PIF_PLUGIN_RETURN_FORWARD;
    
}


int pif_plugin_lookup_state(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) {
    
    
    PIF_PLUGIN_ipv4_T *ipv4;
    
    PIF_PLUGIN_udp_T *udp;
    
    PIF_PLUGIN_tcp_T *tcp;
    
    volatile uint32_t hash_value;
    
    uint32_t  hash_key[4];
    
    __xread uint32_t hash_key_r0;
    __xread uint32_t hash_key_r1;
    __xread uint32_t hash_key_r2;
    __xread uint32_t hash_key_r3;
    
    __addr40 __emem bucket_list *b_info;
    
    uint32_t i;
    __xrw uint32_t count;
    
    ipv4 = pif_plugin_hdr_get_ipv4(headers);
    
    udp = pif_plugin_hdr_get_udp(headers);
    tcp = pif_plugin_hdr_get_tcp(headers);
    
    hash_key[0] = ipv4->srcAddr;
    
    hash_key[1] = ipv4->dstAddr;
    
    if(pif_plugin_hdr_tcp_present(headers)){
        hash_key[2] = (tcp->srcPort << 16) | tcp->dstPort;
        hash_key[3] = 6;
    }else{
        hash_key[2] = (udp->srcPort << 16) | udp->dstPort;
        hash_key[3] = 17;
    }
    
    hash_value = hash_me_crc32((void *) hash_key,sizeof(hash_key), 1);
    
    hash_value &= (STATE_TABLE_SIZE);
    for (i = 0; i < BUCKET_SIZE; i++) {
        mem_read_atomic(&hash_key_r0, &state_hashtable[hash_value].entry[i].key0, sizeof(hash_key_r0));
        mem_read_atomic(&hash_key_r1, &state_hashtable[hash_value].entry[i].key1, sizeof(hash_key_r1));
        mem_read_atomic(&hash_key_r2, &state_hashtable[hash_value].entry[i].key2, sizeof(hash_key_r2));
        mem_read_atomic(&hash_key_r3, &state_hashtable[hash_value].entry[i].key3, sizeof(hash_key_r3));
        
        if (hash_key_r0 == 0) {
            continue;
        }
        
        if (hash_key_r0 == hash_key[0] &&
            hash_key_r1 == hash_key[1] &&
            hash_key_r2 == hash_key[2] &&
            hash_key_r3 == hash_key[3]) { /* Hit */
            
            b_info = &state_hashtable[hash_value];
            
            count = 1;
            
            mem_test_add(&count,&b_info->row[i], 1 << 2);
            
            
            if (count == 0xFFFFFFFF-1) { /* Never incr to 0 or 2^32 */
                
                count = 2;
                
                mem_add32(&count,&b_info->row[i], 1 << 2);
                
            } else if (count == 0xFFFFFFFF) {
                
                mem_incr32(&b_info->row[i]);
                
            }
            
            return PIF_PLUGIN_RETURN_FORWARD;
        }
    }
    
    if (pif_plugin_state_update(headers, match_data) == PIF_PLUGIN_RETURN_DROP) {
        
        return PIF_PLUGIN_RETURN_DROP;
    }
    return PIF_PLUGIN_RETURN_FORWARD;
}

