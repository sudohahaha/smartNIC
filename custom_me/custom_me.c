#include <nfp.h>
#include "plugin.h"
#include <stdint.h>
#include <nfp_chipres.h>
#include <nfp_override.h>
#include <nfp/me.h>
#include <nfp/mem_atomic.h>
#include <stdlib.h>
main()
{
    if(__ctx() == 0) {
        uint32_t i = 0;
        uint32_t j = 0;
        __xrw uint32_t key;
        __xrw uint32_t cur_min_value;
        __xrw uint32_t cur_val;
        __xrw uint32_t cur_min_index;
        while (1){
            for (j = 0; j < STATE_TABLE_SIZE + 1; j ++){
                mem_read_atomic(&cur_min_value, &state_hashtable[j].row[0], sizeof(cur_min_value));
                for (i = 0; i < BUCKET_SIZE; i++) {
                    mem_read_atomic(&cur_val, &state_hashtable[j].row[i], sizeof(cur_val));
                    if(cur_val < cur_min_value && cur_val != 0){
                        cur_min_value = cur_val;
                        cur_min_index = i;
                    }
//                    if(state_hashtable[j].row[i] < cur_min_value && state_hashtable[j].row[i] != 0){
//                        cur_min_value = state_hashtable[j].row[i];
//                        cur_min_index = i;
//                    }
                }
                mem_write_atomic(&cur_min_index, &hash_table_min_track[j], sizeof(cur_min_index));
//                hash_table_min_track[j] = cur_min_index;
            }
            for( j = 0; j < 500; j++){
                    //DO NOTHING
            }
        }
        
        
    }
}

