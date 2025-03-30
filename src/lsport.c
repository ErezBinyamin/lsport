#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <pwd.h>

#define MAX_PATH 256
#define MAX_LINE 1024
#define MAX_CONNS 1024
#define MAX_FDS 128

#define ANSI_YELLOW "\x1b[33m"
#define ANSI_RESET "\x1b[0m"
#define DEBUG_PRINT(fmt, ...) \
    fprintf(stderr, ANSI_YELLOW "[DEBUG] %s:%d:%s(): " fmt ANSI_RESET "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)

int show_protocol = 0, show_destination = 0, show_state = 0, show_user = 0, show_fds = 0;
int show_all_ports = 0;
char *output_columns = NULL;

// Define a struct to store unique connection identifiers and their FD entries
typedef struct {
    char local_addr[128];
    int local_port;
    char remote_addr[128];
    int remote_port;
    int fd_entries[MAX_FDS];
    int fd_count;
} Connection;
Connection seen_connections[MAX_CONNS];
int conn_count = 0;

void parse_proc_net(const char *protocol, const char *file);
void get_process_info(int inode, char *proc_name, int *pid, char *user);
void hex_to_ip(const char *hex, char *ip);
int cmp_str(const void *a, const void *b);
int find_connection_index(const char *local_addr, int local_port, const char *remote_addr, int remote_port);
void usage();

void usage() {
    printf("Usage: \n"
           " lsport [options]\n"
           "\n"
           "List information about open network ports\n"
           "\n"
           "Options:\n"
           "  -h, --help              this help message\n"
           "  -v, --version           version information\n"
           "  -A, -e                  all ports (default is only users ports)\n"
           "  -O, --output-all        output all columns\n"
           "  -o, --output <list>     specified output columns\n"
           "\n"
           "Available output columns:\n"
           "          PID  Process Identifier(ID)\n"
           "          CMD  Process name\n"
           "        LPORT  Port on local machine\n"
           "         NODE  Traffic type ie: tcp or udp\n"
           "          DST  Destination IP address and remote port (DSTIP and RPORT)\n"
           "        STATE  Connection state/status\n"
           "         USER  Username of user who owns the process\n"
           "          FDs  List of file descriptors pointing to this open port\n"
           "\n"
           );
}  

int main(int argc, char* argv[]) {
    static struct option long_options[] = {
        {"help",       no_argument,       NULL, 'h'},
        {"version",    no_argument,       NULL, 'v'},
        {"A",          no_argument,       NULL, 'A'},
        {"e",          no_argument,       NULL, 'e'},
        {"output-all", no_argument,       NULL, 'O'},
        {"output",     required_argument, NULL, 'o'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "hvAeOo:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                usage();
                return 0;
            case 'v':
                printf("lsport version 1.0\n");
                return 0;
            case 'A':
            case 'e':
                show_all_ports = 1;
                break;
            case 'O':
                show_protocol = 1;
                show_destination = 1;
                show_state = 1;
                show_user = 1;
                show_fds = 1;
                break;
            case 'o':
                output_columns = optarg;
                break;
            default:
                usage();
                return 1;
        }
    }
    if (NULL != output_columns){
        char *column;
        column = strtok(output_columns, ",");
        while (column != NULL) {
            if (strcmp(column, "PID") == 0) { /* show_pid = 1;*/ opt=0;}
            else if (strcmp(column, "CMD") == 0) { /* show_cmd = 1;*/ opt=0;}
            else if (strcmp(column, "LPORT") == 0) { /* show_lport = 1;*/ opt=0;}
            else if (strcmp(column, "NODE") == 0) { show_protocol = 1; }
            else if (strcmp(column, "DST") == 0) { show_destination = 1; }
            else if (strcmp(column, "STATE") == 0) { show_state = 1; }
            else if (strcmp(column, "USER") == 0) { show_user = 1; }
            else if (strcmp(column, "FDs") == 0) { show_fds = 1; }
            else{
                fprintf(stderr, "Error: Invalid output column: %s\n\n", column);
                usage();
                return 1;
            }
            column = strtok(NULL, ",");
        }
    }

    printf("%-8s %-20s %-12s", "PID", "CMD", "LPORT");
    if (show_protocol) printf(" %-10s", "NODE");
    if (show_destination) printf(" %-15s", "DSTIP");
    if (show_destination) printf(" %-10s", "RPORT");
    if (show_state) printf(" %-15s", "STATE");
    if (show_user) printf(" %-19s", "USER");
    if (show_fds) printf(" %-10s", "FDs");
    printf("\n");

    DIR *dir = opendir("/proc/net");
    if (!dir) {
        perror("opendir");
        return 1;
    }
    
    struct dirent *entry;
    // Only analyze certain files in /proc/net/... (All these files have the same table header)
    const char *good_files[] = {
        "icmp", "icmp6", "raw", "raw6", "tcp", "tcp6", "udp", "udp6", "udplite", "udplite6"
    };
    const size_t good_count = sizeof(good_files) / sizeof(good_files[0]);
    while ((entry = readdir(dir))) {
        if (! bsearch(entry->d_name, good_files, good_count, sizeof(char *), cmp_str)) continue;
        if (entry->d_type == DT_REG) {
            char filepath[MAX_PATH];
            snprintf(filepath, sizeof(filepath), "/proc/net/%s", entry->d_name);
            if (access(filepath, R_OK) != 0) {
                fprintf(stderr, "Permission denied: %s (errno: %d)\n", filepath, errno);
                continue;
            }
            parse_proc_net(entry->d_name, filepath);
        }
    }
    
    closedir(dir);
    return 0;
}

void parse_proc_net(const char *protocol, const char *file) {
    FILE *fp = fopen(file, "r");
    if (!fp) {
        perror("fopen");
        return;
    }
    
    // Skip the first line (header)
    char line[MAX_LINE];
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        int local_port=0, remote_port=0, state=0, uid=0, inode=0;
        char local_addr[128]={0}, remote_addr[128]={0}, remote_ip[INET_ADDRSTRLEN]={0};
        
        sscanf(line, "%*d: %64[0-9A-Fa-f]:%x %64[0-9A-Fa-f]:%x %d %*x:%*x %*x:%*x %*x %d %*d %d", 
               local_addr, &local_port, remote_addr, &remote_port, &state, &uid, &inode);
       
        hex_to_ip(remote_addr, remote_ip);

        // Check if this connection already exists
        int conn_index = find_connection_index(local_addr, local_port, remote_ip, remote_port);
        if (conn_index == -1) {
            // New connection, create and add it to the seen_connections array
            Connection new_conn = {0};
            strncpy(new_conn.local_addr, local_addr, sizeof(new_conn.local_addr));
            new_conn.local_port = local_port;
            strncpy(new_conn.remote_addr, remote_ip, sizeof(new_conn.remote_addr));
            new_conn.remote_port = remote_port;
            seen_connections[conn_count++] = new_conn;
            conn_index = conn_count - 1;
        }
        // Add the current FD entry to the connection's FD list
        seen_connections[conn_index].fd_entries[seen_connections[conn_index].fd_count++] = inode;
        
        char proc_name[256] = "?";
        int pid = 0;
        char user[256] = "UID: ";
        snprintf(user, sizeof(user), "UID: %d", uid);
        get_process_info(inode, proc_name, &pid, user);
        if (0 == ( pid + local_port + remote_port + strlen(remote_addr))) {
            DEBUG_PRINT("Probably a problem");
            continue;
        }
        if (0==inode) {
            if (0==pid) {
                strcpy(proc_name, "Kernel Swapper/Idle");
            }
            else {
                strcpy(proc_name, "?Anomally?");
                strcpy(user, "?Anomally?");
            }
        }
        if (0==uid) strcpy(user, "root");
        uid_t current_uid = geteuid();
        if (0==show_all_ports && current_uid != uid) continue;

        char *state_str;
        switch (state) {
            case 1: state_str = "ESTABLISHED"; break;
            case 2: state_str = "SYN_SENT"; break;
            case 3: state_str = "SYN_RECV"; break;
            case 4: state_str = "FIN_WAIT1"; break;
            case 5: state_str = "FIN_WAIT2"; break;
            case 6: state_str = "TIME_WAIT"; break;
            case 7: state_str = "CLOSE"; break;
            case 8: state_str = "CLOSE_WAIT"; break;
            case 9: state_str = "LAST_ACK"; break;
            case 10: state_str = "LISTEN"; break;
            case 11: state_str = "CLOSING"; break;
            default: state_str = "UNKNOWN";
        }
        
        if((0!=current_uid) && 0==pid && (strcmp(proc_name, "?") == 0) ){
            printf("%-8s %-20s %-12d", "?", proc_name, local_port);
        }
        else {
            printf("%-8d %-20s %-12d", pid, proc_name, local_port);
        }
        if (show_protocol) printf(" %-10s", protocol);
        if (show_destination) printf(" %-15s", remote_ip);
        if (show_destination) printf(" %-10d", remote_port);
        if (show_state) printf(" %-15s", state_str);
        if (show_user) printf(" %-20s", user);
        if (show_fds) {
            printf("[");
            for (int i = 0; i < seen_connections[conn_index].fd_count; i++) {
                if (i > 0) printf(", ");
                printf("%d", seen_connections[conn_index].fd_entries[i]);
            }
            printf("]\n");
        }
        else{ printf("\n"); }
    }
    fclose(fp);
}

void get_process_info(int inode, char *proc_name, int *pid, char* user) {
    struct dirent *entry;
    DIR *dp = opendir("/proc");
    if (!dp) return;
    
    while ((entry = readdir(dp))) {
        if (!isdigit(entry->d_name[0])) continue;
        
        char fd_path[MAX_PATH];
        int max_len = sizeof(fd_path) - strlen("/proc/") - strlen("/fd") - 1;
        snprintf(fd_path, sizeof(fd_path), "/proc/%.*s/fd", max_len, entry->d_name);
        
        DIR *fd_dir = opendir(fd_path);
        if (!fd_dir) continue;
        
        struct dirent *fd_entry;
        while ((fd_entry = readdir(fd_dir))) {
            if (fd_entry->d_type != DT_LNK) continue;
            
            char link_path[MAX_PATH], target[MAX_PATH];

            snprintf(link_path, sizeof(link_path), "%s/%s", fd_path, fd_entry->d_name);
            ssize_t len = readlink(link_path, target, sizeof(target) - 1);
            
            if (len != -1) {
                target[len] = '\0';
                if (strstr(target, "socket:[")) {
                    int sock_inode;
                    sscanf(target, "socket:[%d]", &sock_inode);
                    if (sock_inode == inode) {
                        *pid = atoi(entry->d_name);
                        snprintf(proc_name, 256, "/proc/%d/comm", *pid);
                        FILE *comm_fp = fopen(proc_name, "r");
                        if (comm_fp) {
                            if (fgets(proc_name, 256, comm_fp) == NULL) {
                                fclose(comm_fp);
                                return;
                            }
                            proc_name[strcspn(proc_name, "\n")] = 0;
                            fclose(comm_fp);
                        } else {
                            strcpy(proc_name, "Unknown");
                        }

                        char status_path[MAX_PATH];
                        snprintf(status_path, sizeof(status_path), "/proc/%d/status", *pid);
                        FILE *status_fp = fopen(status_path, "r");
                        if (status_fp) {
                            char buf[MAX_LINE];
                            while (fgets(buf, sizeof(buf), status_fp)) {
                                if (strncmp(buf, "Uid:", 4) == 0) {
                                    int proc_uid;
                                    sscanf(buf, "Uid:\t%d", &proc_uid);
                                    struct passwd *pw = getpwuid(proc_uid);
                                    if (pw) {
                                        strcpy(user, pw->pw_name);
                                    }
                                    break;
                                }
                            }
                            fclose(status_fp);
                        }

                        closedir(fd_dir);
                        closedir(dp);
                        return;
                    }
                }
            }
        }
        closedir(fd_dir);
    }
    closedir(dp);
}

// Function to find the index of an existing connection in the seen_connections array
int find_connection_index(const char *local_addr, int local_port, const char *remote_addr, int remote_port) {
    for (int i = 0; i < conn_count; i++) {
        if (strcmp(seen_connections[i].local_addr, local_addr) == 0 &&
            seen_connections[i].local_port == local_port &&
            strcmp(seen_connections[i].remote_addr, remote_addr) == 0 &&
            seen_connections[i].remote_port == remote_port) {
            return i;  // Found the connection
        }
    }
    return -1;  // Connection not found
}

void hex_to_ip(const char *hex, char *ip) {
    unsigned int bytes[4];
    sscanf(hex, "%2X%2X%2X%2X", &bytes[3], &bytes[2], &bytes[1], &bytes[0]);
    snprintf(ip, INET_ADDRSTRLEN, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

int cmp_str(const void *a, const void *b) {
    return strcmp((const char *)a, *(const char **)b);
}
