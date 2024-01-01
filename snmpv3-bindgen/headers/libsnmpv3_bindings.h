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

typedef struct Vec_u8 Vec_u8;

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
 * This enum is so that C can identify the type of each `SnmpValue`.
 */
typedef enum SnmpValue_Tag {
  Int,
  String,
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
} SnmpValue_Tag;

typedef struct SnmpValue {
  SnmpValue_Tag tag;
  union {
    struct {
      int32_t int_;
    };
    struct {
      char *string;
    };
    struct {
      uint8_t ip_address[4];
    };
    struct {
      uint32_t counter;
    };
    struct {
      uint32_t unsigned_int;
    };
    struct {
      uint32_t time_ticks;
    };
    struct {
      struct Vec_u8 *opaque;
    };
    struct {
      uint64_t big_counter;
    };
  };
} SnmpValue;

/**
 * A struct to return to C with the results of the SNMPv3 command.
 */
typedef struct SnmpResult {
  char *host;
  char *oid;
  struct SnmpValue *result;
} SnmpResult;

void *new_oid_map(void);

void insert_oid_map(struct OID *oid_ptr, void *ptr);

void print_oid_map(void *ptr);

void free_oid_map(void *ptr);

void print_command(struct Command *ptr);

void print_auth(struct AuthParams *ptr);

void print_priv(struct PrivParams *ptr);

void print_params(struct Params *ptr);

void free_snmp_result(struct SnmpResult *ptr);

struct SnmpResult *run(void *oid_map_ptr, struct Params *param_ptr);
