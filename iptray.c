// SPDX-FileCopyrightText: Copyright 2026 Phillip Trudeau-Tavara <pmttavara@protonmail.com>
// SPDX-License-Identifier: 0BSD

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <shellapi.h>

#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Build-time configuration. These are deliberately source constants: edit,
 * rebuild, and restart. ProbeTimeoutMs must remain below ProbeIntervalMs.
 */
#define CFG_PROBE_INTERVAL_MS       300U
#define CFG_PROBE_TIMEOUT_MS        250U
#define CFG_RECOVERY_DELAY_MS     10000U
#define CFG_SUCCESS_QUORUM            2U
#define CFG_FAILURE_QUORUM            2U
#define CFG_UP_ROUNDS                 3U
#define CFG_DOWN_ROUNDS               3U
#define CFG_PREFERRED_PATH             0  /* 0 Ethernet, 1 Wi-Fi */
#define CFG_ALLOW_FAILBACK             1
#define CFG_ENABLE_IPV6                1
#define CFG_ROUTE_PENALTY           5000U
#define CFG_VERBOSE_PROBES              0
#define CFG_STUN_TIMEOUT_MS           800U
#define CFG_STUN_REFRESH_MS         30000U
#define CFG_STUN_HOST       "stun.l.google.com"
#define CFG_STUN_PORT       "19302"
#define CFG_ETHERNET_GUID   "" /* Stable AdapterName GUID, or empty for best Ethernet. */
#define CFG_WIFI_GUID       "" /* Stable AdapterName GUID, or empty for best Wi-Fi. */

static const char *const CFG_IPV4_TARGETS[] = {
    "1.1.1.1", "8.8.8.8", "9.9.9.9"
};
static const char *const CFG_IPV6_TARGETS[] = {
    "2606:4700:4700::1111", "2001:4860:4860::8888", "2620:fe::fe"
};

#define ARRAY_COUNT(a) (sizeof(a) / sizeof((a)[0]))
#define IPTRAY_MAX_TARGETS 5
#define PATH_ETHERNET 0
#define PATH_WIFI 1
#define PATH_COUNT 2

C_ASSERT(ARRAY_COUNT(CFG_IPV4_TARGETS) >= 3);
C_ASSERT(ARRAY_COUNT(CFG_IPV4_TARGETS) <= IPTRAY_MAX_TARGETS);
C_ASSERT(ARRAY_COUNT(CFG_IPV6_TARGETS) >= 3);
C_ASSERT(ARRAY_COUNT(CFG_IPV6_TARGETS) <= IPTRAY_MAX_TARGETS);

typedef enum PathHealth {
    PATH_HEALTH_UNKNOWN = 0,
    PATH_HEALTH_UP,
    PATH_HEALTH_DOWN
} PathHealth;

typedef struct HealthPolicy {
    unsigned success_quorum;
    unsigned failure_quorum;
    unsigned up_rounds;
    unsigned down_rounds;
} HealthPolicy;

typedef struct HealthState {
    PathHealth state;
    unsigned consecutive_success;
    unsigned consecutive_failure;
    ULONGLONG state_since_ms;
    ULONGLONG up_since_ms;
    ULONGLONG failure_streak_since_ms;
} HealthState;

typedef struct HealthChange {
    PathHealth before;
    PathHealth after;
    int changed;
} HealthChange;

typedef struct FailoverDecision {
    int active;
    int preferred;
    int allow_failback;
    ULONGLONG recovery_delay_ms;
} FailoverDecision;

typedef struct TargetList4 {
    IN_ADDR address[IPTRAY_MAX_TARGETS];
    const char *text[IPTRAY_MAX_TARGETS];
    unsigned count;
} TargetList4;

typedef struct TargetList6 {
    IN6_ADDR address[IPTRAY_MAX_TARGETS];
    const char *text[IPTRAY_MAX_TARGETS];
    unsigned count;
} TargetList6;

typedef struct AppConfig {
    DWORD probe_interval_ms;
    DWORD probe_timeout_ms;
    DWORD recovery_delay_ms;
    DWORD stun_timeout_ms;
    DWORD stun_refresh_ms;
    DWORD route_penalty;
    int preferred;
    int allow_failback;
    int enable_ipv6;
    int verbose_probes;
    HealthPolicy health;
    TargetList4 targets4;
    TargetList6 targets6;
    const char *ethernet_guid;
    const char *wifi_guid;
    const char *stun_host;
    const char *stun_port;
} AppConfig;

static AppConfig config_make(void) {
    AppConfig config;
    ZeroMemory(&config, sizeof(config));
    config.probe_interval_ms = CFG_PROBE_INTERVAL_MS;
    config.probe_timeout_ms = CFG_PROBE_TIMEOUT_MS;
    config.recovery_delay_ms = CFG_RECOVERY_DELAY_MS;
    config.stun_timeout_ms = CFG_STUN_TIMEOUT_MS;
    config.stun_refresh_ms = CFG_STUN_REFRESH_MS;
    config.route_penalty = CFG_ROUTE_PENALTY;
    config.preferred = CFG_PREFERRED_PATH == PATH_WIFI ? PATH_WIFI : PATH_ETHERNET;
    config.allow_failback = CFG_ALLOW_FAILBACK;
    config.enable_ipv6 = CFG_ENABLE_IPV6;
    config.verbose_probes = CFG_VERBOSE_PROBES;
    config.health.success_quorum = CFG_SUCCESS_QUORUM;
    config.health.failure_quorum = CFG_FAILURE_QUORUM;
    config.health.up_rounds = CFG_UP_ROUNDS;
    config.health.down_rounds = CFG_DOWN_ROUNDS;
    config.ethernet_guid = CFG_ETHERNET_GUID;
    config.wifi_guid = CFG_WIFI_GUID;
    config.stun_host = CFG_STUN_HOST;
    config.stun_port = CFG_STUN_PORT;
    config.targets4.count = (unsigned)ARRAY_COUNT(CFG_IPV4_TARGETS);
    config.targets6.count = (unsigned)ARRAY_COUNT(CFG_IPV6_TARGETS);
    for (unsigned i = 0; i < config.targets4.count; ++i) {
        config.targets4.text[i] = CFG_IPV4_TARGETS[i];
        InetPtonA(AF_INET, CFG_IPV4_TARGETS[i], &config.targets4.address[i]);
    }
    for (unsigned i = 0; i < config.targets6.count; ++i) {
        config.targets6.text[i] = CFG_IPV6_TARGETS[i];
        InetPtonA(AF_INET6, CFG_IPV6_TARGETS[i], &config.targets6.address[i]);
    }
    return config;
}

static int config_valid(AppConfig config) {
    if (config.probe_timeout_ms >= config.probe_interval_ms ||
        config.health.success_quorum > ARRAY_COUNT(CFG_IPV4_TARGETS) ||
        config.health.failure_quorum > ARRAY_COUNT(CFG_IPV4_TARGETS)) return 0;
    for (unsigned i = 0; i < config.targets4.count; ++i)
        if (config.targets4.address[i].S_un.S_addr == 0) return 0;
    for (unsigned i = 0; i < config.targets6.count; ++i)
        if (IN6_IS_ADDR_UNSPECIFIED(&config.targets6.address[i])) return 0;
    return 1;
}

static HealthChange make_health_change(PathHealth before, PathHealth after) {
    HealthChange change = {before, after, before != after};
    return change;
}

static HealthState health_make(ULONGLONG now) {
    HealthState health;
    ZeroMemory(&health, sizeof(health));
    health.state = PATH_HEALTH_UNKNOWN;
    health.state_since_ms = now;
    return health;
}

static HealthState health_force_down(HealthState health, ULONGLONG now) {
    PathHealth before = health.state;
    health.state = PATH_HEALTH_DOWN;
    health.consecutive_success = 0;
    health.consecutive_failure = 0;
    if (before != PATH_HEALTH_DOWN) health.failure_streak_since_ms = now;
    health.up_since_ms = 0;
    if (before != PATH_HEALTH_DOWN) health.state_since_ms = now;
    return health;
}

static HealthState health_advance(HealthState health, HealthPolicy policy,
                                  unsigned successes, unsigned attempts,
                                  int physically_up, ULONGLONG now) {
    unsigned failures = attempts >= successes ? attempts - successes : 0;
    if (!physically_up) return health_force_down(health, now);
    if (successes >= policy.success_quorum) {
        ++health.consecutive_success;
        health.consecutive_failure = 0;
        health.failure_streak_since_ms = 0;
        if (health.consecutive_success >= policy.up_rounds &&
            health.state != PATH_HEALTH_UP) {
            health.state = PATH_HEALTH_UP;
            health.state_since_ms = now;
            health.up_since_ms = now;
        }
    } else if (failures >= policy.failure_quorum) {
        ++health.consecutive_failure;
        health.consecutive_success = 0;
        if (health.consecutive_failure == 1) health.failure_streak_since_ms = now;
        if (health.consecutive_failure >= policy.down_rounds &&
            health.state != PATH_HEALTH_DOWN) {
            health.state = PATH_HEALTH_DOWN;
            health.state_since_ms = now;
            health.up_since_ms = 0;
        }
    } else {
        health.consecutive_success = 0;
        health.consecutive_failure = 0;
        health.failure_streak_since_ms = 0;
    }
    return health;
}

static FailoverDecision decision_make(int preferred, int failback,
                                      ULONGLONG recovery_delay) {
    FailoverDecision decision = {-1, preferred, failback, recovery_delay};
    return decision;
}

static FailoverDecision decision_advance(FailoverDecision decision,
                                         HealthState first, HealthState second,
                                         int usable_first, int usable_second,
                                         ULONGLONG now) {
    HealthState health[2] = {first, second};
    int usable[2] = {usable_first, usable_second};
    int old = decision.active;
    if (old < 0 || old >= PATH_COUNT) {
        int preferred = decision.preferred;
        int alternate = 1 - preferred;
        if (usable[preferred] && health[preferred].state == PATH_HEALTH_UP)
            decision.active = preferred;
        else if (usable[alternate] && health[alternate].state == PATH_HEALTH_UP)
            decision.active = alternate;
        return decision;
    }
    if (!usable[old]) {
        int alternate = 1 - old;
        /* Physical/link/address loss: move immediately to any usable alternate. */
        decision.active = usable[alternate] ? alternate : -1;
        return decision;
    }
    if (health[old].state == PATH_HEALTH_DOWN) {
        int alternate = 1 - old;
        /* Upstream loss: require the alternate's probes to be confirmed healthy. */
        decision.active = usable[alternate] && health[alternate].state == PATH_HEALTH_UP
            ? alternate : -1;
        return decision;
    }
    if (old != decision.preferred && decision.allow_failback) {
        int preferred = decision.preferred == PATH_WIFI ? PATH_WIFI : PATH_ETHERNET;
        if (usable[preferred] && health[preferred].state == PATH_HEALTH_UP &&
            health[preferred].up_since_ms != 0 &&
            now - health[preferred].up_since_ms >= decision.recovery_delay_ms)
            decision.active = preferred;
    }
    return decision;
}

static const char *health_name(PathHealth health) {
    if (health == PATH_HEALTH_UP) return "UP";
    if (health == PATH_HEALTH_DOWN) return "DOWN";
    return "UNKNOWN";
}

static const char *path_name(int path) {
    return path == PATH_WIFI ? "Wi-Fi" : "Ethernet";
}

static HANDLE g_log = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_log_lock;
static int g_log_ready;

static int log_open(const wchar_t *path) {
    WIN32_FILE_ATTRIBUTE_DATA data;
    wchar_t backup[MAX_PATH];
    InitializeCriticalSection(&g_log_lock);
    g_log_ready = 1;
    if (GetFileAttributesExW(path, GetFileExInfoStandard, &data) &&
        (data.nFileSizeHigh != 0 || data.nFileSizeLow >= 2U * 1024U * 1024U)) {
        _snwprintf_s(backup, MAX_PATH, _TRUNCATE, L"%s.1", path);
        DeleteFileW(backup);
        MoveFileExW(path, backup, MOVEFILE_REPLACE_EXISTING);
    }
    g_log = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    return g_log != INVALID_HANDLE_VALUE;
}

static void log_close(void) {
    if (g_log != INVALID_HANDLE_VALUE) CloseHandle(g_log);
    g_log = INVALID_HANDLE_VALUE;
    if (g_log_ready) DeleteCriticalSection(&g_log_lock);
    g_log_ready = 0;
}

static void log_write(const char *level, const char *format, ...) {
    SYSTEMTIME now;
    char message[1536];
    char line[1792];
    va_list arguments;
    int length;
    DWORD written;
    va_start(arguments, format);
    _vsnprintf_s(message, sizeof(message), _TRUNCATE, format, arguments);
    va_end(arguments);
    GetLocalTime(&now);
    length = _snprintf_s(line, sizeof(line), _TRUNCATE,
        "%04u-%02u-%02uT%02u:%02u:%02u.%03u %s %s\r\n",
        now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
        now.wMilliseconds, level, message);
    if (length < 0) length = (int)strlen(line);
    OutputDebugStringA(line);
    if (!g_log_ready || g_log == INVALID_HANDLE_VALUE) return;
    EnterCriticalSection(&g_log_lock);
    WriteFile(g_log, line, (DWORD)length, &written, NULL);
    LeaveCriticalSection(&g_log_lock);
}

#define LOG_INFO(...) log_write("INFO", __VA_ARGS__)
#define LOG_WARN(...) log_write("WARN", __VA_ARGS__)
#define LOG_ERROR(...) log_write("ERROR", __VA_ARGS__)

typedef struct AdapterInfo {
    int present;
    int physical_up;
    int ipv4_ready;
    int ipv6_ready;
    int weak_host_send4;
    int weak_host_send6;
    int has_gateway4;
    int has_gateway6;
    int hardware_interface;
    NET_LUID luid;
    NET_IFINDEX if_index4;
    NET_IFINDEX if_index6;
    ULONG if_metric4;
    ULONG if_metric6;
    IF_OPER_STATUS oper_status;
    IN_ADDR source4;
    SOCKADDR_IN6 source6;
    char source4_text[INET_ADDRSTRLEN];
    char source6_text[INET6_ADDRSTRLEN];
    char adapter_guid[128];
    char friendly_name[256];
} AdapterInfo;

typedef struct AdapterSet {
    AdapterInfo path[PATH_COUNT];
    ULONGLONG generation;
} AdapterSet;

typedef struct NetworkNotifications {
    HANDLE interface_handle;
    HANDLE address_handle;
    HANDLE route_handle;
} NetworkNotifications;

static int guid_matches(const char *configured, const char *adapter_name) {
    const char *a = configured;
    const char *b = adapter_name;
    size_t a_length;
    size_t b_length;
    if (!configured[0]) return 1;
    if (*a == '{') ++a;
    if (*b == '{') ++b;
    a_length = strlen(a);
    b_length = strlen(b);
    if (a_length && a[a_length - 1] == '}') --a_length;
    if (b_length && b[b_length - 1] == '}') --b_length;
    return a_length == b_length && _strnicmp(a, b, a_length) == 0;
}

static int useful_ipv4(const SOCKADDR_IN *address) {
    ULONG host = ntohl(address->sin_addr.S_un.S_addr);
    return host != 0 && (host >> 24) != 127 && (host >> 16) != 0xA9FE;
}

static int useful_ipv6(const SOCKADDR_IN6 *address) {
    const IN6_ADDR *a = &address->sin6_addr;
    return !IN6_IS_ADDR_UNSPECIFIED(a) && !IN6_IS_ADDR_LOOPBACK(a) &&
           !IN6_IS_ADDR_LINKLOCAL(a) && !IN6_IS_ADDR_MULTICAST(a);
}

static void fill_ip_interface(AdapterInfo *adapter, ADDRESS_FAMILY family) {
    MIB_IPINTERFACE_ROW row;
    ZeroMemory(&row, sizeof(row));
    InitializeIpInterfaceEntry(&row);
    row.Family = family;
    row.InterfaceLuid = adapter->luid;
    if (GetIpInterfaceEntry(&row) != NO_ERROR) return;
    if (family == AF_INET) {
        adapter->if_metric4 = row.Metric;
        adapter->if_index4 = row.InterfaceIndex;
        adapter->weak_host_send4 = row.WeakHostSend != FALSE;
    } else {
        adapter->if_metric6 = row.Metric;
        adapter->if_index6 = row.InterfaceIndex;
        adapter->weak_host_send6 = row.WeakHostSend != FALSE;
    }
}

static void fill_adapter(const IP_ADAPTER_ADDRESSES *source, AdapterInfo *adapter) {
    const IP_ADAPTER_UNICAST_ADDRESS *unicast;
    const IP_ADAPTER_GATEWAY_ADDRESS_LH *gateway;
    ZeroMemory(adapter, sizeof(*adapter));
    adapter->present = 1;
    adapter->luid = source->Luid;
    adapter->if_index4 = source->IfIndex;
    adapter->if_index6 = source->Ipv6IfIndex;
    adapter->oper_status = source->OperStatus;
    adapter->physical_up = source->OperStatus == IfOperStatusUp;
    {
        MIB_IF_ROW2 interface_row;
        ZeroMemory(&interface_row, sizeof(interface_row));
        interface_row.InterfaceLuid = source->Luid;
        if (GetIfEntry2(&interface_row) == NO_ERROR)
            adapter->hardware_interface =
                interface_row.InterfaceAndOperStatusFlags.HardwareInterface != 0;
    }
    if (source->AdapterName)
        strncpy_s(adapter->adapter_guid, sizeof(adapter->adapter_guid),
                  source->AdapterName, _TRUNCATE);
    if (source->FriendlyName)
        WideCharToMultiByte(CP_UTF8, 0, source->FriendlyName, -1,
                            adapter->friendly_name, (int)sizeof(adapter->friendly_name),
                            NULL, NULL);
    if (!adapter->friendly_name[0])
        strncpy_s(adapter->friendly_name, sizeof(adapter->friendly_name),
                  adapter->adapter_guid, _TRUNCATE);
    for (unicast = source->FirstUnicastAddress; unicast; unicast = unicast->Next) {
        if (unicast->DadState != IpDadStatePreferred &&
            unicast->DadState != IpDadStateDeprecated) continue;
        if (unicast->Address.lpSockaddr->sa_family == AF_INET && !adapter->ipv4_ready) {
            const SOCKADDR_IN *a4 = (const SOCKADDR_IN *)unicast->Address.lpSockaddr;
            if (useful_ipv4(a4)) {
                adapter->source4 = a4->sin_addr;
                InetNtopA(AF_INET, &adapter->source4, adapter->source4_text,
                          (DWORD)sizeof(adapter->source4_text));
                adapter->ipv4_ready = 1;
            }
        } else if (unicast->Address.lpSockaddr->sa_family == AF_INET6 &&
                   !adapter->ipv6_ready) {
            const SOCKADDR_IN6 *a6 = (const SOCKADDR_IN6 *)unicast->Address.lpSockaddr;
            if (useful_ipv6(a6)) {
                adapter->source6 = *a6;
                InetNtopA(AF_INET6, &adapter->source6.sin6_addr, adapter->source6_text,
                          (DWORD)sizeof(adapter->source6_text));
                adapter->ipv6_ready = 1;
            }
        }
    }
    for (gateway = source->FirstGatewayAddress; gateway; gateway = gateway->Next) {
        if (gateway->Address.lpSockaddr->sa_family == AF_INET) adapter->has_gateway4 = 1;
        if (gateway->Address.lpSockaddr->sa_family == AF_INET6) adapter->has_gateway6 = 1;
    }
    fill_ip_interface(adapter, AF_INET);
    fill_ip_interface(adapter, AF_INET6);
}

static ULONG adapter_score(const AdapterInfo *adapter) {
    ULONG score = adapter->if_metric4;
    if (!adapter->physical_up) score += 1000000U;
    if (!adapter->ipv4_ready) score += 500000U;
    return score;
}

static DWORD discover_adapters(const AppConfig *config, AdapterSet *set) {
    ULONG size = 16384;
    ULONG result;
    IP_ADAPTER_ADDRESSES *addresses = NULL;
    AdapterInfo best[PATH_COUNT];
    ULONG scores[PATH_COUNT] = {0xFFFFFFFFUL, 0xFFFFFFFFUL};
    ZeroMemory(best, sizeof(best));
    for (;;) {
        addresses = (IP_ADAPTER_ADDRESSES *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
        if (!addresses) return ERROR_NOT_ENOUGH_MEMORY;
        result = GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST |
            GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            NULL, addresses, &size);
        if (result != ERROR_BUFFER_OVERFLOW) break;
        HeapFree(GetProcessHeap(), 0, addresses);
        addresses = NULL;
    }
    if (result != NO_ERROR) {
        if (addresses) HeapFree(GetProcessHeap(), 0, addresses);
        return result;
    }
    for (IP_ADAPTER_ADDRESSES *item = addresses; item; item = item->Next) {
        int path = -1;
        AdapterInfo candidate;
        ULONG score;
        const char *configured;
        if (item->IfType == IF_TYPE_ETHERNET_CSMACD) path = PATH_ETHERNET;
        else if (item->IfType == IF_TYPE_IEEE80211) path = PATH_WIFI;
        if (path < 0) continue;
        configured = path == PATH_ETHERNET ? config->ethernet_guid : config->wifi_guid;
        if (!guid_matches(configured, item->AdapterName ? item->AdapterName : "")) continue;
        fill_adapter(item, &candidate);
        /* An unpinned host-only virtual NIC is not an Internet failover path. */
        if (!configured[0] && (!candidate.hardware_interface ||
            (!candidate.has_gateway4 && !candidate.has_gateway6))) continue;
        score = adapter_score(&candidate);
        if (score < scores[path]) {
            best[path] = candidate;
            scores[path] = score;
        }
    }
    HeapFree(GetProcessHeap(), 0, addresses);
    set->path[0] = best[0];
    set->path[1] = best[1];
    ++set->generation;
    return NO_ERROR;
}

static void make_destination(ADDRESS_FAMILY family, const void *target,
                             SOCKADDR_INET *destination) {
    ZeroMemory(destination, sizeof(*destination));
    destination->si_family = family;
    if (family == AF_INET) destination->Ipv4.sin_addr = *(const IN_ADDR *)target;
    else destination->Ipv6.sin6_addr = *(const IN6_ADDR *)target;
}

static DWORD best_route_for_adapter(const AdapterInfo *adapter, ADDRESS_FAMILY family,
                                    const void *target, MIB_IPFORWARD_ROW2 *route,
                                    SOCKADDR_INET *best_source) {
    SOCKADDR_INET source;
    SOCKADDR_INET destination;
    ZeroMemory(&source, sizeof(source));
    source.si_family = family;
    if (family == AF_INET) source.Ipv4.sin_addr = adapter->source4;
    else source.Ipv6 = adapter->source6;
    make_destination(family, target, &destination);
    return GetBestRoute2((NET_LUID *)&adapter->luid, 0, &source, &destination,
                         0, route, best_source);
}

static DWORD best_system_route(ADDRESS_FAMILY family, const void *target,
                               MIB_IPFORWARD_ROW2 *route,
                               SOCKADDR_INET *best_source) {
    SOCKADDR_INET destination;
    make_destination(family, target, &destination);
    return GetBestRoute2(NULL, 0, NULL, &destination, 0, route, best_source);
}

static VOID CALLBACK interface_changed(PVOID context, PMIB_IPINTERFACE_ROW row,
                                       MIB_NOTIFICATION_TYPE type) {
    (void)row; (void)type; SetEvent((HANDLE)context);
}
static VOID CALLBACK address_changed(PVOID context, PMIB_UNICASTIPADDRESS_ROW row,
                                     MIB_NOTIFICATION_TYPE type) {
    (void)row; (void)type; SetEvent((HANDLE)context);
}
static VOID CALLBACK route_changed(PVOID context, PMIB_IPFORWARD_ROW2 row,
                                   MIB_NOTIFICATION_TYPE type) {
    (void)row; (void)type; SetEvent((HANDLE)context);
}

static DWORD notifications_start(NetworkNotifications *notifications, HANDLE event) {
    DWORD result;
    ZeroMemory(notifications, sizeof(*notifications));
    result = NotifyIpInterfaceChange(AF_UNSPEC, interface_changed, event, FALSE,
                                     &notifications->interface_handle);
    if (result != NO_ERROR) return result;
    result = NotifyUnicastIpAddressChange(AF_UNSPEC, address_changed, event, FALSE,
                                          &notifications->address_handle);
    if (result != NO_ERROR) goto fail;
    result = NotifyRouteChange2(AF_UNSPEC, route_changed, event, FALSE,
                                &notifications->route_handle);
    if (result == NO_ERROR) return NO_ERROR;
    CancelMibChangeNotify2(notifications->address_handle);
fail:
    CancelMibChangeNotify2(notifications->interface_handle);
    ZeroMemory(notifications, sizeof(*notifications));
    return result;
}

static void notifications_stop(NetworkNotifications *notifications) {
    if (notifications->route_handle) CancelMibChangeNotify2(notifications->route_handle);
    if (notifications->address_handle) CancelMibChangeNotify2(notifications->address_handle);
    if (notifications->interface_handle) CancelMibChangeNotify2(notifications->interface_handle);
    ZeroMemory(notifications, sizeof(*notifications));
}

typedef struct ProbeResult {
    int attempted;
    int success;
    DWORD rtt_ms;
    DWORD ip_status;
    DWORD api_error;
    NET_LUID route_luid;
} ProbeResult;

typedef struct ProbeRound {
    ProbeResult ipv4[PATH_COUNT][IPTRAY_MAX_TARGETS];
    ProbeResult ipv6[PATH_COUNT][IPTRAY_MAX_TARGETS];
    unsigned success4[PATH_COUNT];
    unsigned success6[PATH_COUNT];
} ProbeRound;

#define PROBE_PAYLOAD_SIZE 32
#define PROBE_REPLY_SIZE 512
#define PROBE_SLOT_COUNT (PATH_COUNT * IPTRAY_MAX_TARGETS * 2)

typedef struct ProbeSlot {
    HANDLE icmp;
    HANDLE event;
    ADDRESS_FAMILY family;
    unsigned path;
    unsigned target;
    unsigned char payload[PROBE_PAYLOAD_SIZE];
    unsigned char reply[PROBE_REPLY_SIZE];
    ProbeResult *result;
} ProbeSlot;

typedef struct ProbeEngine {
    ProbeSlot slots[PROBE_SLOT_COUNT];
} ProbeEngine;

static ProbeEngine *probe_create(void) {
    ProbeEngine *engine = (ProbeEngine *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                                   sizeof(*engine));
    if (!engine) return NULL;
    ZeroMemory(engine, sizeof(*engine)); /* Also makes ownership obvious to /analyze. */
    for (unsigned i = 0; i < PROBE_SLOT_COUNT; ++i) {
        ProbeSlot *slot = &engine->slots[i];
        slot->family = i < PATH_COUNT * IPTRAY_MAX_TARGETS ? AF_INET : AF_INET6;
        slot->icmp = slot->family == AF_INET ? IcmpCreateFile() : Icmp6CreateFile();
        slot->event = CreateEventW(NULL, TRUE, FALSE, NULL);
        memset(slot->payload, 'p', sizeof(slot->payload));
        if (slot->icmp == INVALID_HANDLE_VALUE || !slot->event) {
            for (unsigned j = 0; j <= i; ++j) {
                if (engine->slots[j].icmp && engine->slots[j].icmp != INVALID_HANDLE_VALUE)
                    IcmpCloseHandle(engine->slots[j].icmp);
                if (engine->slots[j].event) CloseHandle(engine->slots[j].event);
            }
            HeapFree(GetProcessHeap(), 0, engine);
            return NULL;
        }
    }
    return engine;
}

static void probe_destroy(ProbeEngine *engine) {
    if (!engine) return;
    for (unsigned i = 0; i < PROBE_SLOT_COUNT; ++i) {
        /* probe_create zeroes the whole allocation before acquiring handles. */
#pragma warning(suppress: 6001)
        if (engine->slots[i].icmp && engine->slots[i].icmp != INVALID_HANDLE_VALUE)
            IcmpCloseHandle(engine->slots[i].icmp);
#pragma warning(suppress: 6001)
        if (engine->slots[i].event) CloseHandle(engine->slots[i].event);
    }
    HeapFree(GetProcessHeap(), 0, engine);
}

static int probe_route_valid(const AdapterInfo *adapter, ADDRESS_FAMILY family,
                             const void *target, ProbeResult *result) {
    MIB_IPFORWARD_ROW2 route;
    SOCKADDR_INET source;
    DWORD status = best_route_for_adapter(adapter, family, target, &route, &source);
    if (status != NO_ERROR) { result->api_error = status; return 0; }
    result->route_luid = route.InterfaceLuid;
    if (route.InterfaceLuid.Value != adapter->luid.Value) {
        result->api_error = ERROR_NETWORK_UNREACHABLE;
        return 0;
    }
    if ((family == AF_INET && adapter->weak_host_send4) ||
        (family == AF_INET6 && adapter->weak_host_send6)) {
        result->api_error = ERROR_NOT_SUPPORTED;
        return 0;
    }
    return 1;
}

static void probe_start4(ProbeSlot *slot, const AdapterInfo *adapter,
                         const IN_ADDR *target, DWORD timeout, ProbeResult *result) {
    DWORD replies;
    ZeroMemory(result, sizeof(*result));
    result->ip_status = IP_REQ_TIMED_OUT;
    slot->result = result;
    ResetEvent(slot->event);
    ZeroMemory(slot->reply, sizeof(slot->reply));
    if (!adapter->present || !adapter->physical_up || !adapter->ipv4_ready) {
        result->api_error = !adapter->present ? ERROR_NOT_FOUND : ERROR_NETWORK_UNREACHABLE;
        SetEvent(slot->event);
        return;
    }
    if (!probe_route_valid(adapter, AF_INET, target, result)) {
        SetEvent(slot->event);
        return;
    }
    result->attempted = 1;
    replies = IcmpSendEcho2Ex(slot->icmp, slot->event, NULL, NULL,
                              adapter->source4.S_un.S_addr, target->S_un.S_addr,
                              slot->payload, (WORD)sizeof(slot->payload), NULL,
                              slot->reply, sizeof(slot->reply), timeout);
    if (replies == 0 && GetLastError() != ERROR_IO_PENDING) {
        result->api_error = GetLastError();
        SetEvent(slot->event);
    } else if (replies != 0) SetEvent(slot->event);
}

static void probe_start6(ProbeSlot *slot, const AdapterInfo *adapter,
                         const IN6_ADDR *target, DWORD timeout, ProbeResult *result) {
    SOCKADDR_IN6 source;
    SOCKADDR_IN6 destination;
    DWORD replies;
    ZeroMemory(result, sizeof(*result));
    result->ip_status = IP_REQ_TIMED_OUT;
    slot->result = result;
    ResetEvent(slot->event);
    ZeroMemory(slot->reply, sizeof(slot->reply));
    if (!adapter->present || !adapter->physical_up || !adapter->ipv6_ready) {
        result->api_error = !adapter->present ? ERROR_NOT_FOUND : ERROR_NETWORK_UNREACHABLE;
        SetEvent(slot->event);
        return;
    }
    if (!probe_route_valid(adapter, AF_INET6, target, result)) {
        SetEvent(slot->event);
        return;
    }
    source = adapter->source6;
    destination = source;
    destination.sin6_addr = *target;
    destination.sin6_port = 0;
    result->attempted = 1;
    replies = Icmp6SendEcho2(slot->icmp, slot->event, NULL, NULL,
                             &source, &destination,
                             slot->payload, (WORD)sizeof(slot->payload), NULL,
                             slot->reply, sizeof(slot->reply), timeout);
    if (replies == 0 && GetLastError() != ERROR_IO_PENDING) {
        result->api_error = GetLastError();
        SetEvent(slot->event);
    } else if (replies != 0) SetEvent(slot->event);
}

static void probe_finish(ProbeSlot *slot) {
    ProbeResult *result = slot->result;
    if (!result || !result->attempted) return;
    if (slot->family == AF_INET) {
        if (IcmpParseReplies(slot->reply, sizeof(slot->reply)) != 0) {
            PICMP_ECHO_REPLY reply = (PICMP_ECHO_REPLY)slot->reply;
            result->ip_status = reply->Status;
            result->rtt_ms = reply->RoundTripTime;
            result->success = reply->Status == IP_SUCCESS;
        } else if (GetLastError() != IP_REQ_TIMED_OUT) result->api_error = GetLastError();
    } else {
        if (Icmp6ParseReplies(slot->reply, sizeof(slot->reply)) != 0) {
            PICMPV6_ECHO_REPLY reply = (PICMPV6_ECHO_REPLY)slot->reply;
            result->ip_status = reply->Status;
            result->rtt_ms = reply->RoundTripTime;
            result->success = reply->Status == IP_SUCCESS;
        } else if (GetLastError() != IP_REQ_TIMED_OUT) result->api_error = GetLastError();
    }
}

static DWORD probe_round(ProbeEngine *engine, const AppConfig *config,
                         const AdapterSet *adapters, ProbeRound *round) {
    HANDLE events[PROBE_SLOT_COUNT];
    ProbeSlot *launched[PROBE_SLOT_COUNT];
    DWORD used = 0;
    DWORD wait_status;
    ZeroMemory(round, sizeof(*round));
    for (unsigned family_index = 0; family_index < 2; ++family_index) {
        ADDRESS_FAMILY family = family_index == 0 ? AF_INET : AF_INET6;
        unsigned count = family == AF_INET ? config->targets4.count : config->targets6.count;
        if (family == AF_INET6 && !config->enable_ipv6) continue;
        for (unsigned path = 0; path < PATH_COUNT; ++path) {
            for (unsigned target = 0; target < count; ++target) {
                unsigned index = family_index * PATH_COUNT * IPTRAY_MAX_TARGETS +
                                 path * IPTRAY_MAX_TARGETS + target;
                ProbeSlot *slot = &engine->slots[index];
                slot->family = family;
                slot->path = path;
                slot->target = target;
                if (family == AF_INET)
                    probe_start4(slot, &adapters->path[path], &config->targets4.address[target],
                                 config->probe_timeout_ms, &round->ipv4[path][target]);
                else
                    probe_start6(slot, &adapters->path[path], &config->targets6.address[target],
                                 config->probe_timeout_ms, &round->ipv6[path][target]);
                events[used] = slot->event;
                launched[used++] = slot;
            }
        }
    }
    /* ICMP signals its event for a reply, not for silence. At the API timeout,
       every silent request is complete even though its event remains clear. */
    wait_status = WaitForMultipleObjects(used, events, TRUE,
                                         config->probe_timeout_ms + 10U);
    for (DWORD i = 0; i < used; ++i) {
        ProbeSlot *slot = launched[i];
        probe_finish(slot);
        if (slot->result && slot->result->success) {
            if (slot->family == AF_INET) ++round->success4[slot->path];
            else ++round->success6[slot->path];
        }
        slot->result = NULL;
    }
    return wait_status == WAIT_FAILED ? GetLastError() : NO_ERROR;
}

static DWORD probe_verify(ProbeEngine *engine, ADDRESS_FAMILY family,
                          const AppConfig *config, const AdapterInfo *adapter,
                          ProbeResult *result) {
    unsigned index = family == AF_INET ? 0 : PATH_COUNT * IPTRAY_MAX_TARGETS;
    ProbeSlot *slot = &engine->slots[index];
    DWORD wait_status;
    slot->family = family;
    if (family == AF_INET)
        probe_start4(slot, adapter, &config->targets4.address[0],
                     config->probe_timeout_ms, result);
    else
        probe_start6(slot, adapter, &config->targets6.address[0],
                     config->probe_timeout_ms, result);
    wait_status = WaitForSingleObject(slot->event, config->probe_timeout_ms + 10U);
    probe_finish(slot);
    slot->result = NULL;
    return wait_status == WAIT_FAILED ? GetLastError() : NO_ERROR;
}

#define IPTRAY_ROUTE_MAGIC 0x52545049UL
#define IPTRAY_ROUTE_VERSION 1UL
#define ROUTE_COMMAND_APPLY 1UL
#define ROUTE_COMMAND_RESTORE 2UL
#define ROUTE_COMMAND_STOP 3UL

typedef struct RouteRequest {
    DWORD magic;
    DWORD version;
    DWORD command;
    ADDRESS_FAMILY family;
    NET_LUID active_luid;
    NET_LUID standby_luid;
    DWORD penalty;
} RouteRequest;

typedef struct RouteResponse {
    DWORD magic;
    DWORD version;
    DWORD status;
    DWORD changed;
    DWORD saved;
    DWORD recovery_status;
    DWORD active_interface_metric;
    DWORD active_route_metric;
    DWORD active_effective_metric;
    DWORD standby_interface_metric;
    DWORD standby_route_metric;
    DWORD standby_effective_metric;
} RouteResponse;

#define MAX_SAVED_ROUTES 32
#define JOURNAL_MAGIC 0x4A545049UL

typedef struct SavedRoute {
    ADDRESS_FAMILY family;
    NET_LUID luid;
    SOCKADDR_INET next_hop;
    ULONG metric;
} SavedRoute;

typedef struct RouteJournal {
    DWORD magic;
    DWORD version;
    DWORD count;
    SavedRoute route[MAX_SAVED_ROUTES];
} RouteJournal;

typedef struct HelperState {
    RouteJournal journal;
    wchar_t journal_path[MAX_PATH];
    DWORD recovery_status;
} HelperState;

static int same_next_hop(const SOCKADDR_INET *a, const SOCKADDR_INET *b,
                         ADDRESS_FAMILY family) {
    if (family == AF_INET)
        return a->Ipv4.sin_addr.S_un.S_addr == b->Ipv4.sin_addr.S_un.S_addr;
    return memcmp(&a->Ipv6.sin6_addr, &b->Ipv6.sin6_addr, sizeof(IN6_ADDR)) == 0 &&
           a->Ipv6.sin6_scope_id == b->Ipv6.sin6_scope_id;
}

static int default_route(const MIB_IPFORWARD_ROW2 *row, ADDRESS_FAMILY family) {
    return row->DestinationPrefix.Prefix.si_family == family &&
           row->DestinationPrefix.PrefixLength == 0;
}

static int saved_route_index(const HelperState *state, const MIB_IPFORWARD_ROW2 *row) {
    for (DWORD i = 0; i < state->journal.count; ++i) {
        const SavedRoute *saved = &state->journal.route[i];
        if (saved->family == row->DestinationPrefix.Prefix.si_family &&
            saved->luid.Value == row->InterfaceLuid.Value &&
            same_next_hop(&saved->next_hop, &row->NextHop, saved->family)) return (int)i;
    }
    return -1;
}

static DWORD journal_write(const HelperState *state) {
    wchar_t temporary[MAX_PATH];
    HANDLE file;
    DWORD written;
    DWORD bytes = FIELD_OFFSET(RouteJournal, route) +
                  state->journal.count * (DWORD)sizeof(SavedRoute);
    _snwprintf_s(temporary, MAX_PATH, _TRUNCATE, L"%s.tmp", state->journal_path);
    file = CreateFileW(temporary, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return GetLastError();
    if (!WriteFile(file, &state->journal, bytes, &written, NULL) || written != bytes ||
        !FlushFileBuffers(file)) {
        DWORD error = GetLastError();
        CloseHandle(file);
        DeleteFileW(temporary);
        return error;
    }
    CloseHandle(file);
    if (!MoveFileExW(temporary, state->journal_path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DWORD error = GetLastError();
        DeleteFileW(temporary);
        return error;
    }
    return NO_ERROR;
}

static DWORD save_route(HelperState *state, const MIB_IPFORWARD_ROW2 *row) {
    SavedRoute *saved;
    DWORD status;
    if (saved_route_index(state, row) >= 0) return NO_ERROR;
    if (state->journal.count >= MAX_SAVED_ROUTES) return ERROR_BUFFER_OVERFLOW;
    saved = &state->journal.route[state->journal.count++];
    ZeroMemory(saved, sizeof(*saved));
    saved->family = row->DestinationPrefix.Prefix.si_family;
    saved->luid = row->InterfaceLuid;
    saved->next_hop = row->NextHop;
    saved->metric = row->Metric;
    status = journal_write(state);
    if (status != NO_ERROR) --state->journal.count;
    return status;
}

static DWORD helper_restore(HelperState *state) {
    PMIB_IPFORWARD_TABLE2 table = NULL;
    DWORD first_error = GetIpForwardTable2(AF_UNSPEC, &table);
    if (first_error != NO_ERROR) return first_error;
    first_error = NO_ERROR;
    for (DWORD i = 0; i < state->journal.count; ++i) {
        const SavedRoute *saved = &state->journal.route[i];
        for (ULONG j = 0; j < table->NumEntries; ++j) {
            MIB_IPFORWARD_ROW2 row = table->Table[j];
            if (default_route(&row, saved->family) &&
                row.InterfaceLuid.Value == saved->luid.Value &&
                same_next_hop(&row.NextHop, &saved->next_hop, saved->family)) {
                if (row.Metric != saved->metric) {
                    DWORD status;
                    row.Metric = saved->metric;
                    status = SetIpForwardEntry2(&row);
                    if (status != NO_ERROR && first_error == NO_ERROR) first_error = status;
                }
                break;
            }
        }
    }
    FreeMibTable(table);
    if (first_error == NO_ERROR) {
        DeleteFileW(state->journal_path);
        state->journal.count = 0;
    }
    return first_error;
}

static DWORD helper_recover(HelperState *state) {
    HANDLE file = CreateFileW(state->journal_path, GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD read;
    DWORD expected;
    if (file == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND ? NO_ERROR : GetLastError();
    ZeroMemory(&state->journal, sizeof(state->journal));
    if (!ReadFile(file, &state->journal, sizeof(state->journal), &read, NULL)) {
        DWORD error = GetLastError();
        CloseHandle(file);
        return error;
    }
    CloseHandle(file);
    expected = FIELD_OFFSET(RouteJournal, route) +
               state->journal.count * (DWORD)sizeof(SavedRoute);
    if (state->journal.magic != JOURNAL_MAGIC ||
        state->journal.version != IPTRAY_ROUTE_VERSION ||
        state->journal.count > MAX_SAVED_ROUTES || read != expected)
        return ERROR_INVALID_DATA;
    return helper_restore(state);
}

static DWORD get_interface_metric(ADDRESS_FAMILY family, NET_LUID luid, ULONG *metric) {
    MIB_IPINTERFACE_ROW row;
    DWORD status;
    ZeroMemory(&row, sizeof(row));
    InitializeIpInterfaceEntry(&row);
    row.Family = family;
    row.InterfaceLuid = luid;
    status = GetIpInterfaceEntry(&row);
    if (status == NO_ERROR) *metric = row.Metric;
    return status;
}

static DWORD helper_apply(HelperState *state, const RouteRequest *request,
                          RouteResponse *response) {
    PMIB_IPFORWARD_TABLE2 table = NULL;
    ULONG active_if;
    ULONG standby_if = 0;
    ULONG active_route = 1;
    ULONG standby_route;
    ULONGLONG desired;
    DWORD first_error = get_interface_metric(request->family, request->active_luid, &active_if);
    if (first_error != NO_ERROR) return first_error;
    if (request->standby_luid.Value != 0)
        get_interface_metric(request->family, request->standby_luid, &standby_if);
    desired = (ULONGLONG)active_if + active_route + request->penalty;
    standby_route = desired > standby_if ? (ULONG)(desired - standby_if) : 1;
    if (standby_route == 0) standby_route = 1;
    first_error = GetIpForwardTable2(request->family, &table);
    if (first_error != NO_ERROR) return first_error;
    first_error = NO_ERROR;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        MIB_IPFORWARD_ROW2 row = table->Table[i];
        ULONG wanted;
        DWORD status;
        if (!default_route(&row, request->family)) continue;
        if (row.InterfaceLuid.Value == request->active_luid.Value) wanted = active_route;
        else if (request->standby_luid.Value != 0 &&
                 row.InterfaceLuid.Value == request->standby_luid.Value) wanted = standby_route;
        else continue;
        status = save_route(state, &row);
        if (status != NO_ERROR) {
            if (first_error == NO_ERROR) first_error = status;
            continue;
        }
        if (row.Metric != wanted) {
            row.Metric = wanted;
            status = SetIpForwardEntry2(&row);
            if (status == NO_ERROR) ++response->changed;
            else if (first_error == NO_ERROR) first_error = status;
        }
    }
    FreeMibTable(table);
    response->saved = state->journal.count;
    response->active_interface_metric = active_if;
    response->active_route_metric = active_route;
    response->active_effective_metric = active_if + active_route;
    response->standby_interface_metric = standby_if;
    response->standby_route_metric = standby_route;
    response->standby_effective_metric = standby_if + standby_route;
    return first_error;
}

static int helper_serve(HANDLE pipe, HelperState *state) {
    for (;;) {
        RouteRequest request;
        RouteResponse response;
        DWORD read;
        DWORD written;
        if (!ReadFile(pipe, &request, sizeof(request), &read, NULL) ||
            read != sizeof(request)) break;
        ZeroMemory(&response, sizeof(response));
        response.magic = IPTRAY_ROUTE_MAGIC;
        response.version = IPTRAY_ROUTE_VERSION;
        response.recovery_status = state->recovery_status;
        if (request.magic != IPTRAY_ROUTE_MAGIC || request.version != IPTRAY_ROUTE_VERSION)
            response.status = ERROR_INVALID_DATA;
        else if (request.command == ROUTE_COMMAND_APPLY &&
                 (request.family == AF_INET || request.family == AF_INET6))
            response.status = helper_apply(state, &request, &response);
        else if (request.command == ROUTE_COMMAND_RESTORE ||
                 request.command == ROUTE_COMMAND_STOP)
            response.status = helper_restore(state);
        else response.status = ERROR_INVALID_FUNCTION;
        if (!WriteFile(pipe, &response, sizeof(response), &written, NULL) ||
            written != sizeof(response)) break;
        if (request.command == ROUTE_COMMAND_RESTORE ||
            request.command == ROUTE_COMMAND_STOP) return 0;
    }
    helper_restore(state);
    return 0;
}

static int route_helper_main(int argc, wchar_t **argv) {
    HelperState state;
    HANDLE tray_process;
    HANDLE pipe;
    DWORD tray_pid;
    if (argc != 5 || wcscmp(argv[1], L"--route-helper") != 0)
        return ERROR_INVALID_PARAMETER;
    tray_pid = wcstoul(argv[3], NULL, 10);
    tray_process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                               FALSE, tray_pid);
    if (!tray_process) return (int)GetLastError();
    ZeroMemory(&state, sizeof(state));
    state.journal.magic = JOURNAL_MAGIC;
    state.journal.version = IPTRAY_ROUTE_VERSION;
    wcsncpy_s(state.journal_path, MAX_PATH, argv[4], _TRUNCATE);
    state.recovery_status = helper_recover(&state);
    state.journal.magic = JOURNAL_MAGIC;
    state.journal.version = IPTRAY_ROUTE_VERSION;
    pipe = CreateFileW(argv[2], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                       SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
    if (pipe == INVALID_HANDLE_VALUE) {
        CloseHandle(tray_process);
        return (int)GetLastError();
    }
    {
        DWORD mode = PIPE_READMODE_MESSAGE;
        SetNamedPipeHandleState(pipe, &mode, NULL, NULL);
    }
    if (WaitForSingleObject(tray_process, 0) == WAIT_TIMEOUT) helper_serve(pipe, &state);
    CloseHandle(pipe);
    CloseHandle(tray_process);
    return 0;
}

typedef struct RouteClient {
    HANDLE pipe;
    HANDLE helper_process;
    DWORD helper_pid;
} RouteClient;

static int route_client_available(const RouteClient *client) {
    return client->pipe && client->pipe != INVALID_HANDLE_VALUE;
}

static DWORD route_transact(RouteClient *client, const RouteRequest *request,
                            RouteResponse *response) {
    DWORD bytes;
    if (!route_client_available(client)) return ERROR_INVALID_HANDLE;
    if (!WriteFile(client->pipe, request, sizeof(*request), &bytes, NULL) ||
        bytes != sizeof(*request)) return GetLastError();
    if (!ReadFile(client->pipe, response, sizeof(*response), &bytes, NULL) ||
        bytes != sizeof(*response)) return GetLastError();
    if (response->magic != IPTRAY_ROUTE_MAGIC || response->version != IPTRAY_ROUTE_VERSION)
        return ERROR_INVALID_DATA;
    return response->status;
}

static DWORD route_client_stop(RouteClient *client, int stop_command) {
    DWORD result = NO_ERROR;
    if (route_client_available(client)) {
        RouteRequest request;
        RouteResponse response;
        ZeroMemory(&request, sizeof(request));
        request.magic = IPTRAY_ROUTE_MAGIC;
        request.version = IPTRAY_ROUTE_VERSION;
        request.command = stop_command ? ROUTE_COMMAND_STOP : ROUTE_COMMAND_RESTORE;
        result = route_transact(client, &request, &response);
        DisconnectNamedPipe(client->pipe);
        CloseHandle(client->pipe);
        client->pipe = INVALID_HANDLE_VALUE;
    }
    if (client->helper_process) {
        WaitForSingleObject(client->helper_process, 3000U);
        CloseHandle(client->helper_process);
        client->helper_process = NULL;
    }
    return result;
}

static DWORD route_client_start(RouteClient *client, const wchar_t *executable,
                                const wchar_t *journal_path) {
    SHELLEXECUTEINFOW execute;
    wchar_t pipe_name[128];
    wchar_t parameters[MAX_PATH * 2 + 160];
    DWORD error = ERROR_TIMEOUT;
    ULONG client_pid;
    int connected = 0;
    ZeroMemory(client, sizeof(*client));
    client->pipe = INVALID_HANDLE_VALUE;
    _snwprintf_s(pipe_name, ARRAY_COUNT(pipe_name), _TRUNCATE,
                 L"\\\\.\\pipe\\IPtray-%lu-%llu", GetCurrentProcessId(), GetTickCount64());
    client->pipe = CreateNamedPipeW(pipe_name,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, sizeof(RouteResponse), sizeof(RouteRequest), 15000, NULL);
    if (client->pipe == INVALID_HANDLE_VALUE) return GetLastError();
    _snwprintf_s(parameters, ARRAY_COUNT(parameters), _TRUNCATE,
                 L"--route-helper \"%s\" %lu \"%s\"",
                 pipe_name, GetCurrentProcessId(), journal_path);
    ZeroMemory(&execute, sizeof(execute));
    execute.cbSize = sizeof(execute);
    execute.fMask = SEE_MASK_NOCLOSEPROCESS;
    execute.lpVerb = L"runas";
    execute.lpFile = executable;
    execute.lpParameters = parameters;
    execute.nShow = SW_HIDE;
    if (!ShellExecuteExW(&execute)) {
        error = GetLastError();
        CloseHandle(client->pipe);
        client->pipe = INVALID_HANDLE_VALUE;
        return error;
    }
    client->helper_process = execute.hProcess;
    client->helper_pid = GetProcessId(execute.hProcess);
    {
        ULONGLONG deadline = GetTickCount64() + 15000U;
        while (GetTickCount64() < deadline) {
            if (ConnectNamedPipe(client->pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
                connected = 1;
                break;
            }
            error = GetLastError();
            if (error != ERROR_PIPE_LISTENING && error != ERROR_NO_DATA) break;
            if (WaitForSingleObject(client->helper_process, 20U) == WAIT_OBJECT_0) {
                error = ERROR_PROCESS_ABORTED;
                break;
            }
        }
    }
    if (!connected) {
        route_client_stop(client, 0);
        return error;
    }
    {
        DWORD mode = PIPE_READMODE_MESSAGE | PIPE_WAIT;
        if (!SetNamedPipeHandleState(client->pipe, &mode, NULL, NULL)) {
            error = GetLastError();
            route_client_stop(client, 0);
            return error;
        }
    }
    if (!GetNamedPipeClientProcessId(client->pipe, &client_pid) ||
        client_pid != client->helper_pid) {
        route_client_stop(client, 0);
        return ERROR_ACCESS_DENIED;
    }
    return NO_ERROR;
}

static DWORD route_client_apply(RouteClient *client, ADDRESS_FAMILY family,
                                NET_LUID active, NET_LUID standby, DWORD penalty,
                                RouteResponse *response) {
    RouteRequest request;
    ZeroMemory(&request, sizeof(request));
    ZeroMemory(response, sizeof(*response));
    request.magic = IPTRAY_ROUTE_MAGIC;
    request.version = IPTRAY_ROUTE_VERSION;
    request.command = ROUTE_COMMAND_APPLY;
    request.family = family;
    request.active_luid = active;
    request.standby_luid = standby;
    request.penalty = penalty;
    return route_transact(client, &request, response);
}

typedef struct ControllerStatus {
    int active4;
    int active6;
    int route_control;
    int route_verified4;
    int route_verified6;
    int ipv6_managed;
    PathHealth health4[2];
    PathHealth health6[2];
    int present[2];
    int physical_up[2];
    IN_ADDR active_source4;
    char adapter_name[2][96];
} ControllerStatus;

typedef void (*ControllerCallback)(const ControllerStatus *, void *);

typedef struct ControllerParams {
    const AppConfig *config;
    HANDLE stop_event;
    HANDLE refresh_event;
    const wchar_t *executable_path;
    const wchar_t *journal_path;
    ControllerCallback callback;
    void *callback_context;
} ControllerParams;

typedef struct Controller {
    const ControllerParams *params;
    AdapterSet adapters;
    NET_LUID known_luid[2];
    HealthState health4[2];
    HealthState health6[2];
    FailoverDecision decision4;
    FailoverDecision decision6;
    NetworkNotifications notifications;
    ProbeEngine *probes;
    RouteClient routes;
    ControllerStatus status;
    ULONGLONG round_number;
    int force_route_apply;
} Controller;

static int adapter_usable(const AdapterInfo *adapter, ADDRESS_FAMILY family,
                          const AppConfig *config) {
    MIB_IPFORWARD_ROW2 route;
    SOCKADDR_INET source;
    DWORD status;
    if (!adapter->present || !adapter->physical_up) return 0;
    if (family == AF_INET) {
        if (!adapter->ipv4_ready || adapter->weak_host_send4) return 0;
        status = best_route_for_adapter(adapter, family, &config->targets4.address[0],
                                        &route, &source);
    } else {
        if (!adapter->ipv6_ready || adapter->weak_host_send6) return 0;
        status = best_route_for_adapter(adapter, family, &config->targets6.address[0],
                                        &route, &source);
    }
    return status == NO_ERROR && route.InterfaceLuid.Value == adapter->luid.Value;
}

static void controller_publish(Controller *controller) {
    for (int path = 0; path < PATH_COUNT; ++path) {
        const AdapterInfo *adapter = &controller->adapters.path[path];
        controller->status.health4[path] = controller->health4[path].state;
        controller->status.health6[path] = controller->health6[path].state;
        controller->status.present[path] = adapter->present;
        controller->status.physical_up[path] = adapter->physical_up;
        strncpy_s(controller->status.adapter_name[path],
                  sizeof(controller->status.adapter_name[path]),
                  adapter->friendly_name, _TRUNCATE);
    }
    controller->status.active4 = controller->decision4.active;
    controller->status.active6 = controller->decision6.active;
    controller->status.route_control = route_client_available(&controller->routes);
    controller->status.ipv6_managed = controller->params->config->enable_ipv6 &&
        adapter_usable(&controller->adapters.path[0], AF_INET6, controller->params->config) &&
        adapter_usable(&controller->adapters.path[1], AF_INET6, controller->params->config);
    ZeroMemory(&controller->status.active_source4, sizeof(IN_ADDR));
    if (controller->decision4.active >= 0)
        controller->status.active_source4 =
            controller->adapters.path[controller->decision4.active].source4;
    controller->params->callback(&controller->status, controller->params->callback_context);
}

static void log_adapter(int path, const AdapterInfo *adapter) {
    if (!adapter->present) { LOG_WARN("adapter path=%s absent", path_name(path)); return; }
    LOG_INFO("adapter path=%s name=\"%s\" guid=%s luid=%llu hardware=%d oper=%u "
             "source4=%s gateway4=%d metric4=%lu weak4=%d source6=%s "
             "gateway6=%d metric6=%lu weak6=%d",
             path_name(path), adapter->friendly_name, adapter->adapter_guid,
             adapter->luid.Value, adapter->hardware_interface, (unsigned)adapter->oper_status,
             adapter->source4_text[0] ? adapter->source4_text : "none",
             adapter->has_gateway4, adapter->if_metric4, adapter->weak_host_send4,
             adapter->source6_text[0] ? adapter->source6_text : "none",
             adapter->has_gateway6, adapter->if_metric6, adapter->weak_host_send6);
    if (adapter->weak_host_send4 || adapter->weak_host_send6)
        LOG_ERROR("adapter path=%s weak-host send enabled; affected bound probes rejected",
                  path_name(path));
}

static int adapter_changed(const AdapterInfo *a, const AdapterInfo *b) {
    if (a->present != b->present || a->physical_up != b->physical_up ||
        a->luid.Value != b->luid.Value || a->ipv4_ready != b->ipv4_ready ||
        a->ipv6_ready != b->ipv6_ready) return 1;
    if (a->ipv4_ready && a->source4.S_un.S_addr != b->source4.S_un.S_addr) return 1;
    return a->ipv6_ready && memcmp(&a->source6, &b->source6, sizeof(a->source6)) != 0;
}

static void controller_refresh(Controller *controller, ULONGLONG now) {
    AdapterSet fresh;
    DWORD result;
    int initial = controller->adapters.generation == 0;
    ZeroMemory(&fresh, sizeof(fresh));
    fresh.generation = controller->adapters.generation;
    result = discover_adapters(controller->params->config, &fresh);
    if (result != NO_ERROR) { LOG_ERROR("GetAdaptersAddresses failed code=%lu", result); return; }
    for (int path = 0; path < PATH_COUNT; ++path) {
        AdapterInfo *old = &controller->adapters.path[path];
        AdapterInfo *current = &fresh.path[path];
        if (current->present) controller->known_luid[path] = current->luid;
        if (adapter_changed(old, current)) {
            LOG_INFO("adapter change path=%s generation=%llu", path_name(path), fresh.generation);
            log_adapter(path, current);
            if (!current->present || !current->physical_up) {
                PathHealth before4 = controller->health4[path].state;
                PathHealth before6 = controller->health6[path].state;
                HealthChange c4;
                HealthChange c6;
                controller->health4[path] = health_force_down(controller->health4[path], now);
                controller->health6[path] = health_force_down(controller->health6[path], now);
                c4 = make_health_change(before4, controller->health4[path].state);
                c6 = make_health_change(before6, controller->health6[path].state);
                if (c4.changed) LOG_WARN("state family=IPv4 path=%s %s->DOWN physical",
                                         path_name(path), health_name(c4.before));
                if (c6.changed) LOG_WARN("state family=IPv6 path=%s %s->DOWN physical",
                                         path_name(path), health_name(c6.before));
            } else if (old->luid.Value != current->luid.Value ||
                       old->source4.S_un.S_addr != current->source4.S_un.S_addr ||
                       memcmp(&old->source6, &current->source6, sizeof(old->source6)) != 0) {
                controller->health4[path] = health_make(now);
                controller->health6[path] = health_make(now);
                LOG_INFO("health reset path=%s after adapter/address change", path_name(path));
            }
        } else if (initial) {
            log_adapter(path, current);
        }
        if (!current->present) {
            controller->health4[path] = health_force_down(controller->health4[path], now);
            controller->health6[path] = health_force_down(controller->health6[path], now);
        }
    }
    controller->adapters = fresh;
    controller->force_route_apply = 1;
}

static int controller_record_health(Controller *controller, ADDRESS_FAMILY family,
                                    const ProbeRound *round, ULONGLONG now) {
    const AppConfig *config = controller->params->config;
    unsigned attempts = family == AF_INET ? config->targets4.count : config->targets6.count;
    int important = 0;
    for (int path = 0; path < PATH_COUNT; ++path) {
        HealthState *health = family == AF_INET ? &controller->health4[path]
                                                : &controller->health6[path];
        unsigned successes = family == AF_INET ? round->success4[path]
                                                : round->success6[path];
        unsigned failure_streak_before = health->consecutive_failure;
        int physical = controller->adapters.path[path].present &&
                       controller->adapters.path[path].physical_up;
        PathHealth before = health->state;
        HealthChange change;
        *health = health_advance(*health, config->health, successes, attempts,
                                 physical, now);
        change = make_health_change(before, health->state);
        if (health->consecutive_failure == 1 && failure_streak_before == 0) important = 1;
        if (change.changed) {
            important = 1;
            LOG_WARN("state family=%s path=%s %s->%s successes=%u/%u "
                     "success_streak=%u failure_streak=%u",
                     family == AF_INET ? "IPv4" : "IPv6", path_name(path),
                     health_name(change.before), health_name(change.after), successes,
                     attempts, health->consecutive_success, health->consecutive_failure);
        }
    }
    return important;
}

static void controller_log_probes(Controller *controller, ADDRESS_FAMILY family,
                                  const ProbeRound *round, int important) {
    const AppConfig *config = controller->params->config;
    unsigned count = family == AF_INET ? config->targets4.count : config->targets6.count;
    for (int path = 0; path < PATH_COUNT; ++path) {
        const AdapterInfo *adapter = &controller->adapters.path[path];
        for (unsigned target = 0; target < count; ++target) {
            const ProbeResult *result = family == AF_INET ? &round->ipv4[path][target]
                                                          : &round->ipv6[path][target];
            if (!config->verbose_probes && !important &&
                controller->round_number % 100 != 1) continue;
            LOG_INFO("probe family=%s path=%s luid=%llu source=%s target=%s result=%s "
                     "rtt_ms=%lu status=%lu api_error=%lu route_luid=%llu",
                     family == AF_INET ? "IPv4" : "IPv6", path_name(path),
                     adapter->luid.Value,
                     family == AF_INET ? (adapter->source4_text[0] ? adapter->source4_text : "none")
                                       : (adapter->source6_text[0] ? adapter->source6_text : "none"),
                     family == AF_INET ? config->targets4.text[target]
                                       : config->targets6.text[target],
                     result->success ? "reply" : "timeout/failure", result->rtt_ms,
                     result->ip_status, result->api_error, result->route_luid.Value);
        }
    }
}

static NET_LUID controller_standby_luid(const Controller *controller, int active) {
    NET_LUID luid;
    ZeroMemory(&luid, sizeof(luid));
    if (active >= 0 && active < PATH_COUNT) luid = controller->known_luid[1 - active];
    return luid;
}

static int controller_verify(Controller *controller, ADDRESS_FAMILY family,
                             int active, ULONGLONG started) {
    const AppConfig *config = controller->params->config;
    MIB_IPFORWARD_ROW2 best;
    SOCKADDR_INET source;
    ProbeResult probe;
    DWORD route_status = family == AF_INET
        ? best_system_route(family, &config->targets4.address[0], &best, &source)
        : best_system_route(family, &config->targets6.address[0], &best, &source);
    DWORD probe_status;
    if (route_status != NO_ERROR ||
        best.InterfaceLuid.Value != controller->adapters.path[active].luid.Value) {
        LOG_ERROR("route verification family=%s path=%s failed code=%lu best_luid=%llu "
                  "expected_luid=%llu", family == AF_INET ? "IPv4" : "IPv6",
                  path_name(active), route_status,
                  route_status == NO_ERROR ? best.InterfaceLuid.Value : 0,
                  controller->adapters.path[active].luid.Value);
        return 0;
    }
    probe_status = probe_verify(controller->probes, family, config,
                                &controller->adapters.path[active], &probe);
    if (probe_status != NO_ERROR || !probe.success) {
        LOG_ERROR("post-switch probe family=%s path=%s source=%s target=%s code=%lu "
                  "status=%lu api_error=%lu elapsed_ms=%llu",
                  family == AF_INET ? "IPv4" : "IPv6", path_name(active),
                  family == AF_INET ? controller->adapters.path[active].source4_text
                                    : controller->adapters.path[active].source6_text,
                  family == AF_INET ? config->targets4.text[0] : config->targets6.text[0],
                  probe_status, probe.ip_status, probe.api_error, GetTickCount64() - started);
        return 0;
    }
    LOG_INFO("route verified family=%s active=%s luid=%llu source=%s target=%s "
             "rtt_ms=%lu failover_duration_ms=%llu",
             family == AF_INET ? "IPv4" : "IPv6", path_name(active),
             controller->adapters.path[active].luid.Value,
             family == AF_INET ? controller->adapters.path[active].source4_text
                               : controller->adapters.path[active].source6_text,
             family == AF_INET ? config->targets4.text[0] : config->targets6.text[0],
             probe.rtt_ms, GetTickCount64() - started);
    return 1;
}

static void controller_apply(Controller *controller, ADDRESS_FAMILY family,
                             int old_active, int new_active, ULONGLONG now,
                             ULONGLONG failure_started) {
    RouteResponse response;
    DWORD status;
    int *verified = family == AF_INET ? &controller->status.route_verified4
                                      : &controller->status.route_verified6;
    if (new_active < 0) {
        *verified = 0;
        if (old_active >= 0) LOG_WARN("no healthy route family=%s old=%s",
                                      family == AF_INET ? "IPv4" : "IPv6",
                                      path_name(old_active));
        return;
    }
    if (!route_client_available(&controller->routes)) {
        *verified = 0;
        if (new_active != old_active)
            LOG_ERROR("route switch unavailable family=%s requested=%s",
                      family == AF_INET ? "IPv4" : "IPv6", path_name(new_active));
        return;
    }
    status = route_client_apply(&controller->routes, family,
                                controller->adapters.path[new_active].luid,
                                controller_standby_luid(controller, new_active),
                                controller->params->config->route_penalty, &response);
    if (status != NO_ERROR) {
        *verified = 0;
        LOG_ERROR("route helper failed family=%s active=%s code=%lu changed=%lu "
                  "saved=%lu recovery_code=%lu",
                  family == AF_INET ? "IPv4" : "IPv6", path_name(new_active), status,
                  response.changed, response.saved, response.recovery_status);
        return;
    }
    /* Route/address notifications include our own SetIpForwardEntry2 calls.
       A no-op reapply proves the policy is still present; do not probe/log it twice. */
    if (response.changed == 0 && new_active == old_active && *verified) return;
    LOG_INFO("route change family=%s old=%s new=%s changed=%lu saved=%lu "
             "active_metric=%lu+%lu=%lu standby_metric=%lu+%lu=%lu",
             family == AF_INET ? "IPv4" : "IPv6",
             old_active >= 0 ? path_name(old_active) : "none", path_name(new_active),
             response.changed, response.saved, response.active_interface_metric,
             response.active_route_metric, response.active_effective_metric,
             response.standby_interface_metric, response.standby_route_metric,
             response.standby_effective_metric);
    *verified = controller_verify(controller, family, new_active,
                                  failure_started ? failure_started : now);
}

static void controller_decide(Controller *controller, ADDRESS_FAMILY family,
                              ULONGLONG now) {
    HealthState *health = family == AF_INET ? controller->health4 : controller->health6;
    FailoverDecision *decision = family == AF_INET ? &controller->decision4
                                                    : &controller->decision6;
    int usable[2];
    int old_active = decision->active;
    int new_active;
    ULONGLONG failure_started = 0;
    for (int path = 0; path < PATH_COUNT; ++path)
        usable[path] = adapter_usable(&controller->adapters.path[path], family,
                                      controller->params->config);
    *decision = decision_advance(*decision, health[0], health[1],
                                 usable[0], usable[1], now);
    new_active = decision->active;
    if (old_active >= 0 && health[old_active].state == PATH_HEALTH_DOWN)
        failure_started = health[old_active].failure_streak_since_ms;
    if (new_active != old_active || controller->force_route_apply)
        controller_apply(controller, family, old_active, new_active, now, failure_started);
}

static DWORD WINAPI controller_thread(void *parameter) {
    const ControllerParams *params = (const ControllerParams *)parameter;
    Controller controller;
    HANDLE events[2] = {params->stop_event, params->refresh_event};
    ULONGLONG next_round;
    DWORD status;
    ZeroMemory(&controller, sizeof(controller));
    controller.params = params;
    controller.routes.pipe = INVALID_HANDLE_VALUE;
    controller.status.active4 = -1;
    controller.status.active6 = -1;
    for (int path = 0; path < PATH_COUNT; ++path) {
        controller.health4[path] = health_make(GetTickCount64());
        controller.health6[path] = health_make(GetTickCount64());
    }
    controller.decision4 = decision_make(params->config->preferred,
                                         params->config->allow_failback,
                                         params->config->recovery_delay_ms);
    controller.decision6 = decision_make(params->config->preferred,
                                         params->config->allow_failback,
                                         params->config->recovery_delay_ms);
    controller.probes = probe_create();
    if (!controller.probes) {
        LOG_ERROR("probe engine initialization failed code=%lu", GetLastError());
        controller_publish(&controller);
        return 1;
    }
    status = notifications_start(&controller.notifications, params->refresh_event);
    if (status != NO_ERROR) LOG_ERROR("network notification registration failed code=%lu", status);
    controller_refresh(&controller, GetTickCount64());
    status = route_client_start(&controller.routes, params->executable_path,
                                params->journal_path);
    if (status != NO_ERROR)
        LOG_ERROR("elevated route helper unavailable code=%lu; monitoring continues", status);
    else LOG_INFO("elevated route helper connected pid=%lu", controller.routes.helper_pid);
    controller_publish(&controller);
    next_round = GetTickCount64();
    while (WaitForSingleObject(params->stop_event, 0) != WAIT_OBJECT_0) {
        ULONGLONG now = GetTickCount64();
        DWORD wait_ms = now < next_round ? (DWORD)(next_round - now) : 0;
        DWORD wait_result = WaitForMultipleObjects(2, events, FALSE, wait_ms);
        if (wait_result == WAIT_OBJECT_0) break;
        if (wait_result == WAIT_OBJECT_0 + 1) {
            ResetEvent(params->refresh_event);
            controller_refresh(&controller, GetTickCount64());
            controller_decide(&controller, AF_INET, GetTickCount64());
            if (params->config->enable_ipv6)
                controller_decide(&controller, AF_INET6, GetTickCount64());
            controller.force_route_apply = 0;
            controller_publish(&controller);
            continue;
        }
        if (wait_result == WAIT_FAILED) {
            LOG_ERROR("controller wait failed code=%lu", GetLastError());
            break;
        }
        {
            ProbeRound round;
            int important4;
            int important6 = 0;
            ULONGLONG round_started = GetTickCount64();
            status = probe_round(controller.probes, params->config,
                                 &controller.adapters, &round);
            ++controller.round_number;
            if (status != NO_ERROR) LOG_ERROR("probe round completion failed code=%lu", status);
            important4 = controller_record_health(&controller, AF_INET, &round,
                                                  round_started);
            if (params->config->enable_ipv6)
                important6 = controller_record_health(&controller, AF_INET6, &round,
                                                      round_started);
            controller_log_probes(&controller, AF_INET, &round, important4);
            if (params->config->enable_ipv6)
                controller_log_probes(&controller, AF_INET6, &round, important6);
        }
        controller_decide(&controller, AF_INET, GetTickCount64());
        if (params->config->enable_ipv6)
            controller_decide(&controller, AF_INET6, GetTickCount64());
        controller.force_route_apply = 0;
        controller_publish(&controller);
        next_round += params->config->probe_interval_ms;
        if (next_round < GetTickCount64()) next_round = GetTickCount64();
    }
    notifications_stop(&controller.notifications);
    if (route_client_available(&controller.routes)) {
        status = route_client_stop(&controller.routes, 1);
        if (status == NO_ERROR) LOG_INFO("original route metrics restored on shutdown");
        else LOG_ERROR("route restore on shutdown failed code=%lu", status);
    }
    probe_destroy(controller.probes);
    return 0;
}

#define WM_TRAY (WM_APP + 1)
#define WM_STATUS_CHANGED (WM_APP + 2)
#define ID_EXIT 1
#define ID_STATUS 2
#define SHUTDOWN_TIMER 1

#define ICON_FONT L"Segoe UI"
#define ICON_TEXT_BLEED 2

static const GUID g_guids[4] = {
    {0x7a9e1c40, 0x2b6d, 0x4f81, {0xa3, 0x55, 0x10, 0x07, 0x12, 0x00, 0x00, 0x00}},
    {0x7a9e1c40, 0x2b6d, 0x4f81, {0xa3, 0x55, 0x10, 0x07, 0x12, 0x00, 0x00, 0x01}},
    {0x7a9e1c40, 0x2b6d, 0x4f81, {0xa3, 0x55, 0x10, 0x07, 0x12, 0x00, 0x00, 0x02}},
    {0x7a9e1c40, 0x2b6d, 0x4f81, {0xa3, 0x55, 0x10, 0x07, 0x12, 0x00, 0x00, 0x03}}
};

typedef struct SharedStatus {
    ControllerStatus controller;
    ULONG public_ip;
} SharedStatus;

static AppConfig g_config;
static ControllerParams g_controller_params;
static SharedStatus g_status;
static CRITICAL_SECTION g_status_lock;
static HANDLE g_stop_event;
static HANDLE g_refresh_event;
static HANDLE g_stun_event;
static HANDLE g_controller_thread;
static HANDLE g_stun_thread;
static HANDLE g_instance_mutex;
static HWND g_window;
static UINT g_taskbar_created;
static int g_shutting_down;
static int g_added;
static int g_use_guid = 1;
static HICON g_icons[4];
static int g_last_online;
static ULONG g_last_ip;
static char g_last_tip[128];

static HFONT make_fitting_font(HDC dc, int width, int height) {
    for (int size = height; size >= 4; --size) {
        SIZE extent = {0};
        TEXTMETRICW metrics = {0};
        HFONT probe = CreateFontW(-size, 0, 0, 0, FW_REGULAR, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  ANTIALIASED_QUALITY, DEFAULT_PITCH | FF_DONTCARE, ICON_FONT);
        HGDIOBJ old;
        if (!probe) continue;
        old = SelectObject(dc, probe);
        GetTextExtentPoint32W(dc, L"999", 3, &extent);
        GetTextMetricsW(dc, &metrics);
        SelectObject(dc, old);
        DeleteObject(probe);
        if (extent.cx > 0 && extent.cx <= width && extent.cy <= height) {
            int target = width + ICON_TEXT_BLEED;
            int average = (metrics.tmAveCharWidth * target + extent.cx / 2) / extent.cx;
            return CreateFontW(-size, average, 0, 0, FW_REGULAR, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               ANTIALIASED_QUALITY, DEFAULT_PITCH | FF_DONTCARE, ICON_FONT);
        }
    }
    return CreateFontW(-4, 0, 0, 0, FW_REGULAR, FALSE, FALSE, FALSE,
                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       ANTIALIASED_QUALITY, DEFAULT_PITCH | FF_DONTCARE, ICON_FONT);
}

static HICON make_icon(const wchar_t *text, int online) {
    int width = GetSystemMetrics(SM_CXSMICON);
    int height = GetSystemMetrics(SM_CYSMICON);
    BITMAPINFO bitmap_info;
    HDC screen;
    HDC dc;
    HBITMAP color;
    HBITMAP mask;
    void *pixels = NULL;
    HGDIOBJ old_bitmap;
    HGDIOBJ old_font;
    HFONT font;
    RECT rectangle;
    ICONINFO icon_info;
    HICON icon;
    if (width <= 0) width = 16;
    if (height <= 0) height = 16;
    ZeroMemory(&bitmap_info, sizeof(bitmap_info));
    bitmap_info.bmiHeader.biSize = sizeof(bitmap_info.bmiHeader);
    bitmap_info.bmiHeader.biWidth = width;
    bitmap_info.bmiHeader.biHeight = -height;
    bitmap_info.bmiHeader.biPlanes = 1;
    bitmap_info.bmiHeader.biBitCount = 32;
    bitmap_info.bmiHeader.biCompression = BI_RGB;
    screen = GetDC(NULL);
    if (!screen) return NULL;
    color = CreateDIBSection(screen, &bitmap_info, DIB_RGB_COLORS, &pixels, NULL, 0);
    dc = CreateCompatibleDC(screen);
    ReleaseDC(NULL, screen);
    if (!color || !dc) {
        if (dc) DeleteDC(dc);
        if (color) DeleteObject(color);
        return NULL;
    }
    old_bitmap = SelectObject(dc, color);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(255, 255, 255));
    font = make_fitting_font(dc, width, height);
    old_font = SelectObject(dc, font);
    SetRect(&rectangle, 0, 0, width, height);
    DrawTextW(dc, text, -1, &rectangle,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOCLIP);
    SelectObject(dc, old_font);
    if (font) DeleteObject(font);
    GdiFlush();
    mask = CreateBitmap(width, height, 1, 1, NULL);
    if (!mask) {
        SelectObject(dc, old_bitmap);
        DeleteDC(dc);
        DeleteObject(color);
        return NULL;
    }
    {
        HDC mask_dc = CreateCompatibleDC(NULL);
        if (mask_dc) {
            HGDIOBJ old_mask = SelectObject(mask_dc, mask);
            SetBkColor(dc, RGB(0, 0, 0));
            BitBlt(mask_dc, 0, 0, width, height, dc, 0, 0, SRCCOPY);
            SelectObject(mask_dc, old_mask);
            DeleteDC(mask_dc);
        }
    }
    {
        uint32_t foreground = online ? RGB(0, 255, 0) : RGB(255, 0, 0);
        uint32_t red = GetRValue(foreground);
        uint32_t green = GetGValue(foreground);
        uint32_t blue = GetBValue(foreground);
        uint32_t *pixel = (uint32_t *)pixels;
        for (int i = 0; i < width * height; ++i) {
            uint32_t alpha = pixel[i] & 0xFF;
            pixel[i] = (alpha << 24) | ((red * alpha / 255) << 16) |
                       ((green * alpha / 255) << 8) | (blue * alpha / 255);
        }
    }
    SelectObject(dc, old_bitmap);
    DeleteDC(dc);
    ZeroMemory(&icon_info, sizeof(icon_info));
    icon_info.fIcon = TRUE;
    icon_info.hbmColor = color;
    icon_info.hbmMask = mask;
    icon = CreateIconIndirect(&icon_info);
    DeleteObject(color);
    DeleteObject(mask);
    return icon;
}

static int status_online(const SharedStatus *status) {
    int active = status->controller.active4;
    return active >= 0 && active < 2 &&
           status->controller.health4[active] == PATH_HEALTH_UP;
}

static void build_tooltip(const SharedStatus *status, char *tip, size_t tip_size) {
    unsigned char *ip = (unsigned char *)&status->public_ip;
    const ControllerStatus *c = &status->controller;
    const char *active4 = c->active4 >= 0 ? path_name(c->active4) : "none";
    const char *route4 = !c->route_control ? "unmanaged" :
                         c->route_verified4 ? "verified" : "unverified";
    char ipv6[32];
    if (!g_config.enable_ipv6) strcpy_s(ipv6, sizeof(ipv6), "disabled");
    else if (!c->ipv6_managed) strcpy_s(ipv6, sizeof(ipv6), "not dual-path");
    else _snprintf_s(ipv6, sizeof(ipv6), _TRUNCATE, "%s %s",
                     c->active6 >= 0 ? path_name(c->active6) : "none",
                     c->route_verified6 ? "verified" : "unverified");
    _snprintf_s(tip, tip_size, _TRUNCATE,
                "%u.%u.%u.%u | IPv4 %s %s | Eth %s, Wi-Fi %s | IPv6 %s",
                ip[0], ip[1], ip[2], ip[3], active4, route4,
                health_name(c->health4[0]), health_name(c->health4[1]), ipv6);
}

static void update_tray(HWND window) {
    SharedStatus status;
    char tip[128];
    int online;
    int first = !g_added;
    EnterCriticalSection(&g_status_lock);
    status = g_status;
    LeaveCriticalSection(&g_status_lock);
    online = status_online(&status);
    build_tooltip(&status, tip, sizeof(tip));
    for (int k = 0; k < 4; ++k) {
        int i = first ? 3 - k : k;
        int octet = (status.public_ip >> (8 * i)) & 0xFF;
        wchar_t text[8];
        HICON icon;
        NOTIFYICONDATAA data;
        _snwprintf_s(text, _countof(text), _TRUNCATE, L"%d", octet);
        icon = make_icon(text, online);
        if (!icon) {
            LOG_ERROR("tray icon rendering failed slot=%d code=%lu", i, GetLastError());
            continue;
        }
        ZeroMemory(&data, sizeof(data));
        data.cbSize = sizeof(data);
        data.hWnd = window;
        data.uID = (UINT)i;
        data.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
        data.uCallbackMessage = WM_TRAY;
        data.hIcon = icon;
        strncpy_s(data.szTip, sizeof(data.szTip), tip, _TRUNCATE);
        if (g_use_guid) {
            data.uFlags |= NIF_GUID;
            data.guidItem = g_guids[i];
        }
        if (first) {
            if (g_use_guid) {
                NOTIFYICONDATAA old;
                ZeroMemory(&old, sizeof(old));
                old.cbSize = sizeof(old);
                old.hWnd = window;
                old.uFlags = NIF_GUID;
                old.guidItem = g_guids[i];
                Shell_NotifyIconA(NIM_DELETE, &old);
            }
            if (!Shell_NotifyIconA(NIM_ADD, &data) && g_use_guid) {
                g_use_guid = 0;
                data.uFlags &= ~NIF_GUID;
                if (!Shell_NotifyIconA(NIM_ADD, &data)) {
                    LOG_ERROR("Shell_NotifyIcon(NIM_ADD) failed slot=%d code=%lu",
                              i, GetLastError());
                }
            }
        } else if (!Shell_NotifyIconA(NIM_MODIFY, &data)) {
            LOG_ERROR("Shell_NotifyIcon(NIM_MODIFY) failed slot=%d code=%lu",
                      i, GetLastError());
        }
        if (g_icons[i]) DestroyIcon(g_icons[i]);
        g_icons[i] = icon;
    }
    g_added = 1;
    g_last_online = online;
    g_last_ip = status.public_ip;
    strncpy_s(g_last_tip, sizeof(g_last_tip), tip, _TRUNCATE);
}

static void remove_tray(HWND window) {
    for (int i = 0; i < 4; ++i) {
        NOTIFYICONDATAA data;
        ZeroMemory(&data, sizeof(data));
        data.cbSize = sizeof(data);
        data.hWnd = window;
        data.uID = (UINT)i;
        if (g_use_guid) {
            data.uFlags = NIF_GUID;
            data.guidItem = g_guids[i];
        }
        Shell_NotifyIconA(NIM_DELETE, &data);
        if (g_icons[i]) DestroyIcon(g_icons[i]);
        g_icons[i] = NULL;
    }
    g_added = 0;
}

static void controller_status_changed(const ControllerStatus *status, void *context) {
    HWND window = (HWND)context;
    EnterCriticalSection(&g_status_lock);
    if (g_status.controller.active4 != status->active4 ||
        g_status.controller.active_source4.S_un.S_addr != status->active_source4.S_un.S_addr) {
        SetEvent(g_stun_event);
    }
    g_status.controller = *status;
    LeaveCriticalSection(&g_status_lock);
    PostMessageW(window, WM_STATUS_CHANGED, 0, 0);
}

static ULONG get_public_ipv4(IN_ADDR source) {
    static volatile LONG transaction_counter;
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo *address;
    SOCKET socket_handle = INVALID_SOCKET;
    ULONG result = 0;
    unsigned char request[20] = {0};
    unsigned char response[512];
    int timeout = (int)g_config.stun_timeout_ms;
    LONG transaction = InterlockedIncrement(&transaction_counter);
    int dns_status;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    dns_status = getaddrinfo(g_config.stun_host, g_config.stun_port, &hints, &addresses);
    if (dns_status != 0) {
        LOG_WARN("STUN DNS resolution failed host=%s code=%d",
                 g_config.stun_host, dns_status);
        return 0;
    }
    for (address = addresses; address; address = address->ai_next) {
        SOCKADDR_IN local;
        socket_handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socket_handle == INVALID_SOCKET) continue;
        ZeroMemory(&local, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_addr = source;
        if (bind(socket_handle, (SOCKADDR *)&local, sizeof(local)) == 0) break;
        closesocket(socket_handle);
        socket_handle = INVALID_SOCKET;
    }
    if (socket_handle == INVALID_SOCKET || !address) {
        LOG_WARN("STUN source bind failed source=%lu code=%d",
                 ntohl(source.S_un.S_addr), WSAGetLastError());
        freeaddrinfo(addresses);
        return 0;
    }
    if (setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO,
                   (const char *)&timeout, sizeof(timeout)) != 0 ||
        setsockopt(socket_handle, SOL_SOCKET, SO_SNDTIMEO,
                   (const char *)&timeout, sizeof(timeout)) != 0) {
        LOG_WARN("STUN socket timeout setup failed code=%d", WSAGetLastError());
        closesocket(socket_handle);
        freeaddrinfo(addresses);
        return 0;
    }
    request[0] = 0x00; request[1] = 0x01;
    request[4] = 0x21; request[5] = 0x12; request[6] = 0xA4; request[7] = 0x42;
    {
        ULONGLONG tick = GetTickCount64();
        memcpy(request + 8, &tick, sizeof(tick));
        memcpy(request + 16, &transaction, sizeof(transaction));
    }
    if (sendto(socket_handle, (const char *)request, sizeof(request), 0,
               address->ai_addr, (int)address->ai_addrlen) == sizeof(request)) {
        int length = recvfrom(socket_handle, (char *)response, sizeof(response), 0, NULL, NULL);
        if (length >= 20 && response[0] == 0x01 && response[1] == 0x01 &&
            memcmp(response + 4, request + 4, 16) == 0) {
            int message_length = (response[2] << 8) | response[3];
            int end = 20 + message_length < length ? 20 + message_length : length;
            for (int offset = 20; offset + 4 <= end;) {
                int type = (response[offset] << 8) | response[offset + 1];
                int attribute_length = (response[offset + 2] << 8) | response[offset + 3];
                int value = offset + 4;
                if (value + attribute_length > end) break;
                if (type == 0x0020 && attribute_length >= 8 && response[value + 1] == 1) {
                    unsigned char *out = (unsigned char *)&result;
                    out[0] = response[value + 4] ^ 0x21;
                    out[1] = response[value + 5] ^ 0x12;
                    out[2] = response[value + 6] ^ 0xA4;
                    out[3] = response[value + 7] ^ 0x42;
                    break;
                }
                if (type == 0x0001 && attribute_length >= 8 &&
                    response[value + 1] == 1 && result == 0) {
                    memcpy(&result, response + value + 4, sizeof(result));
                }
                offset = value + ((attribute_length + 3) & ~3);
            }
        }
    } else {
        LOG_WARN("STUN send failed source=%lu code=%d",
                 ntohl(source.S_un.S_addr), WSAGetLastError());
    }
    if (result == 0) LOG_WARN("STUN response timeout/invalid source=%lu code=%d",
                              ntohl(source.S_un.S_addr), WSAGetLastError());
    closesocket(socket_handle);
    freeaddrinfo(addresses);
    return result;
}

static DWORD WINAPI stun_thread(void *unused) {
    HANDLE events[2] = {g_stop_event, g_stun_event};
    IN_ADDR last_source;
    ULONGLONG last_check = 0;
    (void)unused;
    ZeroMemory(&last_source, sizeof(last_source));
    for (;;) {
        SharedStatus snapshot;
        DWORD wait_ms = g_config.stun_refresh_ms;
        DWORD wait_result = WaitForMultipleObjects(2, events, FALSE, wait_ms);
        if (wait_result == WAIT_OBJECT_0) break;
        ResetEvent(g_stun_event);
        EnterCriticalSection(&g_status_lock);
        snapshot = g_status;
        LeaveCriticalSection(&g_status_lock);
        if (!status_online(&snapshot) || snapshot.controller.active_source4.S_un.S_addr == 0) {
            continue;
        }
        if (snapshot.controller.active_source4.S_un.S_addr != last_source.S_un.S_addr ||
            GetTickCount64() - last_check >= g_config.stun_refresh_ms ||
            wait_result == WAIT_OBJECT_0 + 1) {
            ULONG public_ip = get_public_ipv4(snapshot.controller.active_source4);
            last_check = GetTickCount64();
            last_source = snapshot.controller.active_source4;
            if (public_ip) {
                EnterCriticalSection(&g_status_lock);
                g_status.public_ip = public_ip;
                LeaveCriticalSection(&g_status_lock);
                PostMessageW(g_window, WM_STATUS_CHANGED, 0, 0);
            }
        }
    }
    return 0;
}

static void show_context_menu(HWND window) {
    POINT point;
    HMENU menu = CreatePopupMenu();
    wchar_t status[160];
    if (!menu) return;
    MultiByteToWideChar(CP_UTF8, 0, g_last_tip, -1, status, _countof(status));
    AppendMenuW(menu, MF_STRING | MF_GRAYED, ID_STATUS, status);
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(menu, MF_STRING, ID_EXIT, L"Exit IPtray");
    GetCursorPos(&point);
    SetForegroundWindow(window);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, point.x, point.y, 0, window, NULL);
    DestroyMenu(menu);
}

static void begin_shutdown(HWND window) {
    if (g_shutting_down) return;
    g_shutting_down = 1;
    LOG_INFO("shutdown requested");
    SetEvent(g_stop_event);
    SetEvent(g_stun_event);
    remove_tray(window);
    SetTimer(window, SHUTDOWN_TIMER, 50, NULL);
}

static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == g_taskbar_created) {
        g_added = 0;
        update_tray(window);
        return 0;
    }
    switch (message) {
        case WM_STATUS_CHANGED:
            if (!g_shutting_down) update_tray(window);
            return 0;
        case WM_TRAY: {
            UINT event = LOWORD(lparam);
            if (event == WM_RBUTTONUP || event == WM_CONTEXTMENU || event == WM_LBUTTONUP) {
                show_context_menu(window);
            }
            return 0;
        }
        case WM_COMMAND:
            if (LOWORD(wparam) == ID_EXIT) begin_shutdown(window);
            return 0;
        case WM_CLOSE:
            begin_shutdown(window);
            return 0;
        case WM_POWERBROADCAST:
            if (wparam == PBT_APMRESUMEAUTOMATIC || wparam == PBT_APMRESUMESUSPEND) {
                LOG_INFO("power resume notification; refreshing adapters/routes");
                SetEvent(g_refresh_event);
                SetEvent(g_stun_event);
            }
            return TRUE;
        case WM_TIMER:
            if (wparam == SHUTDOWN_TIMER &&
                WaitForSingleObject(g_controller_thread, 0) == WAIT_OBJECT_0 &&
                WaitForSingleObject(g_stun_thread, 0) == WAIT_OBJECT_0) {
                KillTimer(window, SHUTDOWN_TIMER);
                DestroyWindow(window);
            }
            return 0;
        case WM_DESTROY:
            remove_tray(window);
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(window, message, wparam, lparam);
    }
}

typedef struct RuntimePaths {
    int valid;
    wchar_t executable[MAX_PATH];
    wchar_t log_file[MAX_PATH];
    wchar_t journal[MAX_PATH];
} RuntimePaths;

static RuntimePaths paths_make(void) {
    RuntimePaths paths;
    wchar_t local[MAX_PATH];
    ZeroMemory(&paths, sizeof(paths));
    if (!GetModuleFileNameW(NULL, paths.executable, MAX_PATH)) return paths;
    if (!GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH)) return paths;
    _snwprintf_s(paths.log_file, MAX_PATH, _TRUNCATE, L"%s\\IPtray", local);
    if (!CreateDirectoryW(paths.log_file, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        return paths;
    _snwprintf_s(paths.journal, MAX_PATH, _TRUNCATE, L"%s\\route-state.bin",
                 paths.log_file);
    wcsncat_s(paths.log_file, MAX_PATH, L"\\iptray.log", _TRUNCATE);
    paths.valid = 1;
    return paths;
}

static int self_test(void) {
    HealthPolicy policy = {2, 2, 3, 3};
    HealthState ethernet = health_make(0);
    HealthState wifi = health_make(0);
    FailoverDecision decision = decision_make(PATH_ETHERNET, 1, 10000);
    ULONGLONG outage_start = 900;
    int failed = 0;
#define TEST(expression) do { if (!(expression)) { \
    ++failed; OutputDebugStringA("IPtray self-test failed: " #expression "\n"); \
} } while (0)
    ethernet = health_advance(ethernet, policy, 2, 3, 1, 300);
    ethernet = health_advance(ethernet, policy, 3, 3, 1, 600);
    ethernet = health_advance(ethernet, policy, 2, 3, 1, 900);
    wifi = health_advance(wifi, policy, 3, 3, 1, 300);
    wifi = health_advance(wifi, policy, 3, 3, 1, 600);
    wifi = health_advance(wifi, policy, 3, 3, 1, 900);
    TEST(ethernet.state == PATH_HEALTH_UP);
    decision = decision_advance(decision, ethernet, wifi, 1, 1, 900);
    TEST(decision.active == PATH_ETHERNET);
    ethernet = health_advance(ethernet, policy, 0, 3, 1, 1120);
    ethernet = health_advance(ethernet, policy, 1, 3, 1, 1420);
    TEST(ethernet.state == PATH_HEALTH_UP);
    ethernet = health_advance(ethernet, policy, 0, 3, 1, 1720);
    TEST(ethernet.state == PATH_HEALTH_DOWN);
    TEST(1720 - ethernet.failure_streak_since_ms == 600);
    TEST(1720 - outage_start < 1200); /* Default detection budget. */
    decision = decision_advance(decision, ethernet, wifi, 1, 1, 1720);
    TEST(decision.active == PATH_WIFI);
    ethernet = health_force_down(ethernet, 1800);
    ethernet = health_advance(ethernet, policy, 3, 3, 1, 2100);
    ethernet = health_advance(ethernet, policy, 3, 3, 1, 2400);
    ethernet = health_advance(ethernet, policy, 3, 3, 1, 2700);
    decision = decision_advance(decision, ethernet, wifi, 1, 1, 12000);
    TEST(decision.active == PATH_WIFI);
    decision = decision_advance(decision, ethernet, wifi, 1, 1, 12700);
    TEST(decision.active == PATH_ETHERNET);
    ethernet = health_force_down(ethernet, 13000);
    decision = decision_advance(decision, ethernet, wifi, 0, 1, 13000);
    TEST(decision.active == PATH_WIFI); /* Physical-down bypasses probe thresholds. */
    {
        HealthState absent = health_force_down(health_make(0), 0);
        FailoverDecision startup = decision_make(PATH_ETHERNET, 1, 10000);
        startup = decision_advance(startup, absent, wifi, 0, 1, 1000);
        TEST(startup.active == PATH_WIFI); /* Ethernet absent at startup. */
        startup = decision_make(PATH_WIFI, 1, 10000);
        startup = decision_advance(startup, ethernet, absent, 1, 0, 1000);
        TEST(startup.active == -1); /* Ethernet is down at this point too. */
        ethernet = health_make(0);
        ethernet = health_advance(ethernet, policy, 3, 3, 1, 300);
        ethernet = health_advance(ethernet, policy, 3, 3, 1, 600);
        ethernet = health_advance(ethernet, policy, 3, 3, 1, 900);
        startup = decision_advance(startup, ethernet, absent, 1, 0, 1000);
        TEST(startup.active == PATH_ETHERNET); /* Wi-Fi absent at startup. */
    }
    {
        HealthState noisy = ethernet;
        noisy = health_advance(noisy, policy, 0, 3, 1, 14000);
        noisy = health_advance(noisy, policy, 3, 3, 1, 14300);
        noisy = health_advance(noisy, policy, 0, 3, 1, 14600);
        noisy = health_advance(noisy, policy, 3, 3, 1, 14900);
        TEST(noisy.state == PATH_HEALTH_UP); /* Alternating loss cannot flap. */
    }
    {
        FailoverDecision sticky = decision_make(PATH_ETHERNET, 0, 0);
        sticky.active = PATH_WIFI;
        sticky = decision_advance(sticky, ethernet, wifi, 1, 1, 99999);
        TEST(sticky.active == PATH_WIFI); /* Optional failback disabled. */
    }
#undef TEST
    OutputDebugStringA(failed ? "IPtray self-test: FAIL\n" : "IPtray self-test: PASS\n");
    return failed ? 1 : 0;
}

static int inspect_mode(void) {
    WSADATA winsock;
    RuntimePaths paths = paths_make();
    AppConfig config = config_make();
    AdapterSet adapters;
    ProbeEngine *engine;
    ProbeRound round;
    DWORD status;
    if (!paths.valid || !config_valid(config)) return 1;
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) return 1;
    log_open(paths.log_file);
    LOG_INFO("inspect mode start; no route changes will be made");
    ZeroMemory(&adapters, sizeof(adapters));
    status = discover_adapters(&config, &adapters);
    if (status != NO_ERROR) {
        LOG_ERROR("inspect GetAdaptersAddresses failed code=%lu", status);
        log_close();
        WSACleanup();
        return 1;
    }
    log_adapter(PATH_ETHERNET, &adapters.path[PATH_ETHERNET]);
    log_adapter(PATH_WIFI, &adapters.path[PATH_WIFI]);
    engine = probe_create();
    if (!engine) {
        LOG_ERROR("inspect probe engine creation failed code=%lu", GetLastError());
        log_close();
        WSACleanup();
        return 1;
    }
    status = probe_round(engine, &config, &adapters, &round);
    for (int family_index = 0; family_index < 2; ++family_index) {
        ADDRESS_FAMILY family = family_index == 0 ? AF_INET : AF_INET6;
        unsigned count = family == AF_INET ? config.targets4.count : config.targets6.count;
        for (int path = 0; path < PATH_COUNT; ++path) {
            AdapterInfo adapter = adapters.path[path];
            for (unsigned target = 0; target < count; ++target) {
                ProbeResult result = family == AF_INET ? round.ipv4[path][target]
                                                       : round.ipv6[path][target];
                LOG_INFO("inspect probe family=%s path=%s luid=%llu source=%s target=%s "
                         "result=%s rtt_ms=%lu status=%lu api_error=%lu route_luid=%llu",
                         family == AF_INET ? "IPv4" : "IPv6", path_name(path),
                         adapter.luid.Value,
                         family == AF_INET ? (adapter.source4_text[0] ? adapter.source4_text : "none")
                                           : (adapter.source6_text[0] ? adapter.source6_text : "none"),
                         family == AF_INET ? config.targets4.text[target]
                                           : config.targets6.text[target],
                         result.success ? "reply" : "timeout/failure", result.rtt_ms,
                         result.ip_status, result.api_error, result.route_luid.Value);
            }
        }
    }
    LOG_INFO("inspect mode end code=%lu", status);
    probe_destroy(engine);
    log_close();
    WSACleanup();
    return status == NO_ERROR ? 0 : 1;
}

int WINAPI wWinMain(_In_ HINSTANCE instance, _In_opt_ HINSTANCE previous,
                    _In_ PWSTR command_line, _In_ int show) {
    WNDCLASSW window_class;
    WSADATA winsock;
    MSG message;
    RuntimePaths paths;
    wchar_t **arguments;
    int argument_count;
    DWORD error;
    int exit_code = 0;
    (void)previous;
    (void)command_line;
    (void)show;
    arguments = CommandLineToArgvW(GetCommandLineW(), &argument_count);
    if (arguments && argument_count > 1 && wcscmp(arguments[1], L"--route-helper") == 0) {
        int result = route_helper_main(argument_count, arguments);
        LocalFree(arguments);
        return result;
    }
    if (arguments && argument_count == 2 && wcscmp(arguments[1], L"--self-test") == 0) {
        int result = self_test();
        LocalFree(arguments);
        return result;
    }
    if (arguments && argument_count == 2 && wcscmp(arguments[1], L"--inspect") == 0) {
        int result = inspect_mode();
        LocalFree(arguments);
        return result;
    }
    if (arguments) LocalFree(arguments);
    g_instance_mutex = CreateMutexW(NULL, TRUE, L"Local\\IPtray-7a9e1c40-2b6d-4f81-a355");
    if (!g_instance_mutex || GetLastError() == ERROR_ALREADY_EXISTS) return 0;
    paths = paths_make();
    if (!paths.valid) return 1;
    log_open(paths.log_file);
    g_config = config_make();
    if (!config_valid(g_config)) {
        LOG_ERROR("invalid build-time configuration");
        log_close();
        return 1;
    }
    LOG_INFO("IPtray starting mode=tray interval_ms=%lu timeout_ms=%lu targets4=%u "
             "thresholds=success:%u/%u failure:%u/%u recovery_ms=%lu preferred=%s",
             g_config.probe_interval_ms, g_config.probe_timeout_ms,
             g_config.targets4.count, g_config.health.success_quorum,
             g_config.health.up_rounds, g_config.health.failure_quorum,
             g_config.health.down_rounds, g_config.recovery_delay_ms,
             path_name(g_config.preferred));
    error = WSAStartup(MAKEWORD(2, 2), &winsock);
    if (error != 0) {
        LOG_ERROR("WSAStartup failed code=%lu", error);
        log_close();
        return 1;
    }
    SetProcessDPIAware();
    InitializeCriticalSection(&g_status_lock);
    ZeroMemory(&g_status, sizeof(g_status));
    g_status.controller.active4 = -1;
    g_status.controller.active6 = -1;
    for (int i = 0; i < 2; ++i) {
        g_status.controller.health4[i] = PATH_HEALTH_UNKNOWN;
        g_status.controller.health6[i] = PATH_HEALTH_UNKNOWN;
    }
    g_stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_refresh_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_stun_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_stop_event || !g_refresh_event || !g_stun_event) {
        LOG_ERROR("CreateEvent failed code=%lu", GetLastError());
        exit_code = 1;
        goto cleanup;
    }
    g_taskbar_created = RegisterWindowMessageW(L"TaskbarCreated");
    ZeroMemory(&window_class, sizeof(window_class));
    window_class.lpfnWndProc = window_proc;
    window_class.hInstance = instance;
    window_class.lpszClassName = L"iptray_wndclass_v2";
    if (!RegisterClassW(&window_class)) {
        LOG_ERROR("RegisterClass failed code=%lu", GetLastError());
        exit_code = 1;
        goto cleanup;
    }
    g_window = CreateWindowExW(0, window_class.lpszClassName, L"IPtray",
                               WS_OVERLAPPED, 0, 0, 0, 0, NULL, NULL, instance, NULL);
    if (!g_window) {
        LOG_ERROR("CreateWindow failed code=%lu", GetLastError());
        exit_code = 1;
        goto cleanup;
    }
    g_controller_params.config = &g_config;
    g_controller_params.stop_event = g_stop_event;
    g_controller_params.refresh_event = g_refresh_event;
    g_controller_params.executable_path = paths.executable;
    g_controller_params.journal_path = paths.journal;
    g_controller_params.callback = controller_status_changed;
    g_controller_params.callback_context = g_window;
    g_stun_thread = CreateThread(NULL, 0, stun_thread, NULL, 0, NULL);
    g_controller_thread = CreateThread(NULL, 0, controller_thread,
                                       &g_controller_params, 0, NULL);
    if (!g_stun_thread || !g_controller_thread) {
        LOG_ERROR("CreateThread failed code=%lu", GetLastError());
        SetEvent(g_stop_event);
        exit_code = 1;
        goto cleanup;
    }
    while (GetMessageW(&message, NULL, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

cleanup:
    if (g_stop_event) SetEvent(g_stop_event);
    if (g_stun_event) SetEvent(g_stun_event);
    if (g_controller_thread) {
        WaitForSingleObject(g_controller_thread, INFINITE);
        CloseHandle(g_controller_thread);
    }
    if (g_stun_thread) {
        WaitForSingleObject(g_stun_thread, INFINITE);
        CloseHandle(g_stun_thread);
    }
    if (g_refresh_event) CloseHandle(g_refresh_event);
    if (g_stun_event) CloseHandle(g_stun_event);
    if (g_stop_event) CloseHandle(g_stop_event);
    DeleteCriticalSection(&g_status_lock);
    WSACleanup();
    if (g_instance_mutex) CloseHandle(g_instance_mutex);
    LOG_INFO("IPtray stopped exit_code=%d", exit_code);
    log_close();
    return exit_code;
}
