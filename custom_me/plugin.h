#include <nfp/mem_atomic.h>
//#include <pkt_ops.h>
#include <nfp_override.h>
#include <std/hash.h>
#include <nfp/me.h>
#define VAL_1X 1
#define VAL_2X VAL_1X, VAL_1X
#define VAL_4X VAL_2X, VAL_2X
#define VAL_8X VAL_4X, VAL_4X
#define VAL_16X VAL_8X, VAL_8X
#define VAL_32X VAL_16X, VAL_16X
#define VAL_64X VAL_32X, VAL_32X
#define VAL_128X VAL_64X, VAL_64X
#define VAL_256X VAL_128X, VAL_128X
#define VAL_512X VAL_256X, VAL_256X
#define VAL_1024X VAL_512X, VAL_512X
#define VAL_2048X VAL_1024X, VAL_1024X
#define VAL_4096X VAL_2048X, VAL_2048X
#define VAL_8192X VAL_4096X, VAL_4096X
#define VAL_16384X VAL_8192X, VAL_8192X
#define VAL_32768X VAL_16384X, VAL_16384X
#define VAL_65536X VAL_32768X, VAL_32768X
#define VAL_131072X VAL_65536X, VAL_65536X
#define VAL_262144X VAL_131072X, VAL_131072X
#define VAL_1048576X VAL_262144X, VAL_262144X,VAL_262144X,VAL_262144X
#define VAL_2097152X VAL_1048576X, VAL_1048576X 
#define BUCKET_SIZE 5
#define STATE_TABLE_SIZE 0xFFFF

typedef struct bucket_entry {
    uint32_t key0;
    uint32_t key1;
    uint32_t key2;
    uint32_t key3;
//    uint64_t ts;
}bucket_entry;


typedef struct bucket_list {
    uint32_t row[BUCKET_SIZE];
    struct bucket_entry entry[BUCKET_SIZE];
    
}bucket_list;

typedef struct eviction {
    uint32_t record[7];
    
}eviction;

volatile __emem __export uint32_t global_semaphores[STATE_TABLE_SIZE + 1] = {VAL_65536X};
volatile __emem __export uint32_t evict_semaphores = 1;
__shared __export __addr40 __emem bucket_list state_hashtable[STATE_TABLE_SIZE + 1];
__shared __emem __export uint32_t hash_table_min_track[STATE_TABLE_SIZE + 1];
__shared __export __addr40 __emem eviction evict_buffer;
//__shared __emem __export uint32_t evict_count;
//__shared __emem __export uint32_t k[5];
//__shared __emem __export unsigned long long int ts;

