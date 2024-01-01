#include <stdio.h>
#include <stdint.h>
#include "libsnmpv3_bindings.h"

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
    oid_sysDescr->oid = "1.3.6.1.2.1.1.1.0";
    oid_sysDescr->name = "sysDescr.0";
    insert_oid_map(oid_sysDescr, oid_map);

    // Command
    struct Command* get_cmd = (struct Command*)malloc(sizeof(struct Command));
    Get_Body* get_1_body = (struct Get_Body*)malloc(sizeof(struct Get_Body));
    get_cmd->tag = Get;
    get_1_body->oid = oid_sysDescr;
    get_cmd->get = *get_1_body;

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
    my_params->cmd = get_cmd;
    //print_params(my_params);

    struct SnmpResult* my_result = run(oid_map, my_params);

    printf("Host: %s\n\n", my_result->host);
    printf("OID: %s\n\n", my_result->oid);
    printf("sysDescr.0: %s\n\n", my_result->result->string);
    free_snmp_result(my_result);
    free_oid_map(oid_map);
    free(auth_params);
    free(priv_params);
    free(oid_sysDescr);
    free(get_cmd);
    free(get_1_body);
    free(my_params);
    // End memory danger!
}
