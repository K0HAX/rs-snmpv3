#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "libsnmpv3_bindings.h"

/*
 * A convenience function to correctly format a single SnmpResult
 *
 * This also demonstrates how to correctly parse an SnmpResult and determine
 * what type of result it is.
*/
int print_type(struct SnmpResult *ptr) {
    enum SnmpType r_type = ptr->result_type;
    switch (r_type)
    {
        case Int:
            printf("Type: Int\n");
            int* int_result = ptr->result;
            printf("[Int] %d\n", *int_result);
            return Int;
            break;
        case String:
            printf("Type: String\n");
            char* result = ptr->result;
            printf("[String] %s\n", result);
            return 0;
            break;
        case ObjectId:
            printf("Type: ObjectId\n");
            return 0;
            break;
        case IpAddress:
            printf("Type: IpAddress\n");
            unsigned int *ip_result = ptr->result;
            printf("[IpAddress]: %u.%u.%u.%u\n", ip_result[0], ip_result[1], ip_result[2], ip_result[3]);
            return 0;
            break;
        case Counter:
            printf("Type: Counter\n");
            unsigned int *counter_result = ptr->result;
            printf("[Counter]: %u\n", *counter_result);
            break;
        case UnsignedInt:
            printf("Type: UnsignedInt\n");
            unsigned int *unsigned_int_result = ptr->result;
            printf("[UnsignedInt]: %u\n", *unsigned_int_result);
            return 0;
            break;
        case TimeTicks:
            printf("Type: TimeTicks\n");
            unsigned long time_ticks_result =(unsigned long) ptr->result;
            printf("[TimeTicks] %lu\n", time_ticks_result);
            return 0;
            break;
        case Opaque:
            printf("Type: Opaque\n");
            unsigned char *opaque_result = ptr->result;
            uintptr_t opaque_length = ptr->length;
            printf("[Opaque] ");
            for (int i = 0; i < opaque_length; i++)
            {
                printf("%.2X", opaque_result[i]);
            }
            printf("\n");
            return 0;
            break;
        case BigCounter:
            printf("Type: BigCounter\n");
            unsigned long long *bigcounter_result = ptr->result;
            printf("[BigCounter] %llu\n", *bigcounter_result);
            return 0;
            break;
        case Unspecified:
            printf("Type: Unspecified\n");
            return 1;
            break;
        case NoSuchObject:
            printf("Type: NoSuchObject\n");
            return 1;
            break;
        case NoSuchInstance:
            printf("Type: NoSuchInstance\n");
            return 1;
            break;
        case EndOfMibView:
            printf("Type: EndOfMibView\n");
            return 1;
            break;
        default:
            printf("Failed finding type!!!!\n");
            return -1;
            break;
    }
    return 1;
}

/*
 * A convenience function to print every `SnmpResult` inside SnmpResults.
*/
int print_all_results(struct SnmpResults results) {
    uintptr_t length = results.length;
    printf("Results Length: %tu\n", length);
    printf("Results Capacity: %tu\n", results.capacity);
    printf("----\n");
    for (uintptr_t i = 0; i < length; i++)
    {
        printf("i = %tu\n", i);
        SnmpResult *this_result = results.results[i];
        if (!this_result) {
            continue;
        }
        printf("Unwrapped result: %p\n", this_result);
        if (print_type(this_result) != 0) {
            printf("Failed to print!\n");
        } else {
            printf("[Host] %s\n", this_result->host);
            printf("[OID] %s\n", this_result->oid);
        }
        printf("----\n");
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc != 5) {
        printf("Usage: %s hostname username [SHA1 Secret] [AES128 Secret]\n", argv[0]);
        exit(-1);
    }
    // Begin memory danger!
    struct AuthParams* auth_params = (struct AuthParams*)malloc(sizeof(struct AuthParams));
    struct PrivParams* priv_params = (struct PrivParams*)malloc(sizeof(struct PrivParams));

    // OidMap
    void* oid_map = new_oid_map();

    // OID 1
    struct OID* oid_sysDescr = (struct OID*)malloc(sizeof(struct OID));
    oid_sysDescr->oid = "1.3.6.1.2.1.1";
    oid_sysDescr->name = "system";
    insert_oid_map(oid_sysDescr, oid_map);

    // Command
    struct Command* walk_cmd = (struct Command*)malloc(sizeof(struct Command));
    Walk_Body* walk_1_body = (struct Walk_Body*)malloc(sizeof(struct Walk_Body));
    walk_cmd->tag = Walk;
    walk_1_body->oid = oid_sysDescr;
    walk_cmd->walk = *walk_1_body;

    // Auth Params
    auth_params->auth_protocol = Sha1Digest;
    auth_params->auth_secret = argv[3];

    // Priv Params
    priv_params->priv_protocol = Aes128;
    priv_params->priv_secret = argv[4];

    struct Params* my_params = (struct Params*)malloc(sizeof(struct Params));
    my_params->user = argv[2];
    my_params->host = argv[1];
    my_params->auth_params = auth_params;
    my_params->priv_params = priv_params;
    my_params->cmd = walk_cmd;

    struct SnmpResults* my_result = run(oid_map, my_params);

    print_all_results(*my_result);

    printf("Freeing my_result!\n");
    free_snmp_results(my_result);
    printf("Freeing oid_map!\n");
    free_oid_map(oid_map);
    printf("Freeing auth_params!\n");
    free(auth_params);
    printf("Freeing priv_params!\n");
    free(priv_params);
    printf("Freeing oid_sysDescr!\n");
    free(oid_sysDescr);
    printf("Freeing walk_cmd!\n");
    free(walk_cmd);
    printf("Freeing walk_1_body!\n");
    free(walk_1_body);
    printf("Freeing my_params!\n");
    free(my_params);
    // End memory danger!
}
