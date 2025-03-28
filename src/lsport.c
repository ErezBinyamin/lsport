#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
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

void parse_proc_net(const char *protocol, const char *file, int *unknown_count);
void get_process_info(int inode, char *proc_name, int *pid, char *user);
void hex_to_ip(const char *hex, char *ip);
int find_connection_index(const char *local_addr, int local_port, const char *remote_addr, int remote_port);

int main() {
    printf("%-20s %-10s %-10s %-10s %-20s %-10s %-15s %-10s %-20s\n", "Process Name", "PID", "Local Port", "Protocol", "Destination", "Dest Port", "State", "User", "FD Entries");
    printf("----------------------------------------------------------------------------------------------------------------------\n");
     
    DIR *dir = opendir("/proc/net");
    if (!dir) {
        perror("opendir");
        return 1;
    }
    
    struct dirent *entry;
    int unknown_count = 0;
    while ((entry = readdir(dir))) {
        if (entry->d_type == DT_REG) {
            char filepath[MAX_PATH];
            snprintf(filepath, sizeof(filepath), "/proc/net/%s", entry->d_name);
            parse_proc_net(entry->d_name, filepath, &unknown_count);
        }
    }
    
    closedir(dir);
    printf("Unknown connections: %d\n", unknown_count);
    return 0;
}

void parse_proc_net(const char *protocol, const char *file, int *unknown_count) {
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
        
        char proc_name[256] = "Unknown";
        int pid = 0;
        char user[256] = "Unknown";
        get_process_info(inode, proc_name, &pid, user);
        if (0 == ( pid + local_port + remote_port + strlen(remote_addr))) {
            (*unknown_count)++;
            continue;
        }
        if (0==(inode + pid)) {
            strcpy(proc_name, "Kproc");
            strcpy(user, "Kernel");
        }

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
        
        printf("%-20s %-10d %-10d %-10s %-20s %-10d %-15s %-10s", proc_name, pid, local_port, protocol, remote_ip, remote_port, state_str, user);
        printf("[");
        for (int i = 0; i < seen_connections[conn_index].fd_count; i++) {
            if (i > 0) printf(", ");
            printf("%d", seen_connections[conn_index].fd_entries[i]);
        }
        printf("]\n");
    }
    fclose(fp);
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

void hex_to_ip(const char *hex, char *ip) {
    unsigned int bytes[4];
    sscanf(hex, "%2X%2X%2X%2X", &bytes[3], &bytes[2], &bytes[1], &bytes[0]);
    snprintf(ip, INET_ADDRSTRLEN, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}
