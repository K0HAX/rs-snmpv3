#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * AuthTypeArgs communicates which authentication mechanism will be used
 * for the session.
 *
 * Note: NoAuth is not implemented yet.
 */
enum AuthTypeArgs {
  Md5Digest,
  Sha1Digest,
  NoAuth,
};
typedef uint8_t AuthTypeArgs;

/**
 * PrivTypeArgs communicates which encryption mechanism will be used
 * for the session.
 *
 * Note: NoPriv is not implemented yet.
 */
enum PrivTypeArgs {
  Des,
  Aes128,
  NoPriv,
};
typedef uint8_t PrivTypeArgs;

/**
 * This will allow C programs to read the correct SnmpValue type
 *
 * These values can be used to match SnmpResult->result_type to the correct
 * data type.
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

/**
 * The OID struct contains a dotted decimal, ex: "0.1.2.3" `oid`, and a human readable
 * C string `name`. These are used both for the OidMap, and for telling the library
 * what OIDs to Get or Walk.
 */
typedef struct OID {
  const char *oid;
  const char *name;
} OID;

/**
 * This enum is a duplicate of `params::Command`, but exported to C
 *
 * The command types have different parameters.
 *
 * Get.oid is a single OID.
 *
 * GetNext.oids is a list of OIDs (an OidMap).
 *
 * Walk.oid is a single OID.
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
 * The struct that C sends to the library, for Auth values.
 */
typedef struct AuthParams {
  AuthTypeArgs auth_protocol;
  const char *auth_secret;
} AuthParams;

/**
 * The struct that C sends to the library, for encryption values.
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
 *
 * `host` is the hostname that this result came from.
 *
 * `oid` is the OID that this result came from.
 *
 * `length` and `capacity` are used both to allow C to parse the `result`,
 * and because Rust needs those values to convert a pointer back into
 * certain data types, such as `Vec<T>`.
 *
 * `result_type` is used by C to determine what kind of data was returned.
 */
typedef struct SnmpResult {
  char *host;
  char *oid;
  enum SnmpType result_type;
  uintptr_t length;
  uintptr_t capacity;
  void *result;
} SnmpResult;

/**
 * A struct to return to C with an array of results of the SNMPv3 command.
 *
 * `length` and `capacity` are used both to allow C to parse the `results`,
 * by providing C with the length of the SnmpResult array, and because
 * Rust will need those values to convert the results pointer back into a
 * Vec<*mut SnmpResult> in order to free the results.
 */
typedef struct SnmpResults {
  uintptr_t length;
  uintptr_t capacity;
  struct SnmpResult **results;
} SnmpResults;

/**
 * The ObjectIdentifier struct is just a datatype for SNMP return values
 * of type ObjectId.
 *
 * Components is an array of u64 (uint64_t in C) values, the length of the array
 * is stored in `length`.
 */
typedef struct ObjectIdentifier {
  uintptr_t length;
  uintptr_t capacity;
  uint64_t *components;
} ObjectIdentifier;

/**
 * Ask Rust to allocate and return a pointer to a new OidMap.
 *
 * Returns a void pointer, which is the OidMap.
 *
 * This void pointer can not be dereferenced by C, it is just
 * used as an opaque pointer that can be passed back to Rust later.
 */
void *new_oid_map(void);

/**
 * Ask Rust to push an OID struct onto the OidMap.
 *
 * This has to be a function because the OidMap is an opaque pointer for C,
 * and only Rust can modify it.
 */
void insert_oid_map(struct OID *oid_ptr, void *ptr);

/**
 * A convenience function to print the current value of the
 * OidMap.
 *
 * This does not consume the OidMap.
 */
void print_oid_map(void *ptr);

/**
 * Ask Rust to free the OidMap.
 *
 * C is unable to free the memory used by the OidMap, so this function will
 * perform that task.
 */
void free_oid_map(void *ptr);

/**
 * Convenience function to print the contents of the Command struct.
 */
void print_command(struct Command *ptr);

/**
 * Convenience function to print the contents of the AuthParams struct.
 */
void print_auth(struct AuthParams *ptr);

/**
 * Convenience function to print the contents of the PrivParams struct.
 */
void print_priv(struct PrivParams *ptr);

/**
 * Convenience function to print the contents of the Params struct.
 */
void print_params(struct Params *ptr);

/**
 * Ask Rust to free an SnmpResult.
 *
 * C is not able to properly free SnmpResult, so it must call this function when it would
 * otherwise call free() on the SnmpResult.
 */
void free_snmp_result(struct SnmpResult *ptr);

/**
 * Ask Rust to free a SnmpResults (plural form of the struct)
 *
 * C is not able to properly free SnmpResults, so it must call this function when it would
 * otherwise call free() on the SnmpResults.
 *
 * This function will free all child SnmpResult structs within the SnmpResults as well.
 */
void free_snmp_results(struct SnmpResults *ptr);

/**
 * Ask Rust to free an ObjectIdentifier.
 *
 * This should only be used if the ObjectIdentifier is returned from Rust. If it is created by C
 * by using malloc() then C should free it, not Rust.
 */
void free_object_identifier(struct ObjectIdentifier *ptr);

/**
 * The "do the ting" function.
 *
 * This function takes a *OidMap `oid_map_ptr`, and a *Params as `param_ptr` and
 * returns *SnmpResults.
 *
 * This function does all the heavy lifting, and is probably where optimization work could have
 * the most impact.
 */
struct SnmpResults *run(void *oid_map_ptr, struct Params *param_ptr);
