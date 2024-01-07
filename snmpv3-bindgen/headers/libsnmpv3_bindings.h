#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

enum AuthTypeArgs {
  Md5Digest,
  Sha1Digest,
  NoAuth,
};
typedef uint8_t AuthTypeArgs;

enum PrivTypeArgs {
  Des,
  Aes128,
  NoPriv,
};
typedef uint8_t PrivTypeArgs;

/**
 * This will allow C programs to read the correct SnmpValue type
 */
typedef enum SnmpType {
  Int,
  String,
  ObjectId,
  IpAddress,
  Counter,
  UnsignedInt,
  TimeTicks,
  Opaque,
  BigCounter,
  Unspecified,
  NoSuchObject,
  NoSuchInstance,
  EndOfMibView,
} SnmpType;

typedef struct OID {
  const char *oid;
  const char *name;
} OID;

/**
 * This enum is a duplicate of `params::Command`, but exported to C
 */
typedef enum Command_Tag {
  Get,
  GetNext,
  Walk,
} Command_Tag;

typedef struct Get_Body {
  const struct OID *oid;
} Get_Body;

typedef struct GetNext_Body {
  const struct OID *oids;
} GetNext_Body;

typedef struct Walk_Body {
  const struct OID *oid;
} Walk_Body;

typedef struct Command {
  Command_Tag tag;
  union {
    Get_Body get;
    GetNext_Body get_next;
    Walk_Body walk;
  };
} Command;

/**
 * The struct that we pass back to C with "real" Auth values.
 */
typedef struct AuthParams {
  AuthTypeArgs auth_protocol;
  const char *auth_secret;
} AuthParams;

/**
 * The struct that we pass back to C with "real" Priv values.
 */
typedef struct PrivParams {
  PrivTypeArgs priv_protocol;
  const char *priv_secret;
} PrivParams;

/**
 * A struct with everything needed to run an SNMPv3 command.
 */
typedef struct Params {
  const char *user;
  const char *host;
  struct AuthParams *auth_params;
  struct PrivParams *priv_params;
  struct Command *cmd;
} Params;

/**
 * A struct to return to C with the results of the SNMPv3 command.
 */
typedef struct SnmpResult {
  char *host;
  char *oid;
  enum SnmpType result_type;
  uintptr_t length;
  void *result;
} SnmpResult;

/**
 * A struct to return to C with an array of results of the SNMPv3 command.
 */
typedef struct SnmpResults {
  uintptr_t length;
  uintptr_t capacity;
  struct SnmpResult **results;
} SnmpResults;

typedef struct ObjectIdentifier {
  uintptr_t length;
  uintptr_t capacity;
  uint64_t *components;
} ObjectIdentifier;

void *new_oid_map(void);

void insert_oid_map(struct OID *oid_ptr, void *ptr);

void print_oid_map(void *ptr);

void free_oid_map(void *ptr);

void print_command(struct Command *ptr);

void print_auth(struct AuthParams *ptr);

void print_priv(struct PrivParams *ptr);

void print_params(struct Params *ptr);

void free_snmp_result(struct SnmpResult *ptr);

void free_snmp_results(struct SnmpResults *ptr);

void free_object_identifier(struct ObjectIdentifier *ptr);

struct SnmpResults *run(void *oid_map_ptr, struct Params *param_ptr);
