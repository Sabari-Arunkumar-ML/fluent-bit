#define AVAILABLE 1
#define NOT_AVAILABLE 0
#define RETRIES 2
#define GLOBALRETRIES 100
#define DELAYINSEC 2
#define LOOKUPKEY "agent_key"
#define DEFAULT "Unknown"
#define ACCOUNTYPE_LEN 11
#define ACCOUNTYPE "accountType"
#define DEFAULT_LEN 7
#define PORTKEY "port"

enum siem_parser_status {
    agent_not_available,
    agent_available,
    data_collected,
    unable_to_connect,
    add_default
};
struct siemparser_ctx {
    char *Agent_key;
    char *port;
    int port_key_len;
    int port_key_check;
    int Agent_key_len;
    int lookup_key_check;
    int sock;
    struct flb_filter_instance *ins;
};
