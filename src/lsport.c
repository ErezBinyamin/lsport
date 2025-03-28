#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>
#include <arpa/inet.h>

#define MAX_PATH 256
#define MAX_LINE 1024

void parse_proc_net(const char *protocol, const char *file, int *unknown_count);
void get_process_info(int inode, char *proc_name, int *pid);
void hex_to_ip(const char *hex, char *ip);

int main() {
    printf("%-20s %-10s %-10s %-10s %-20s %-10s %-15s %-10s\n", "Process Name", "PID", "Local Port", "Protocol", "Destination", "Dest Port", "State", "User");
    printf("----------------------------------------------------------------------------------------------------------\n");
    
    DIR *dir = opendir("/proc/net");
    if (!dir) {
        perror("opendir");
        return 1;
    }
    
    struct dirent *entry;
    int unknown_count = 0, local_count = 0;
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
    
    char line[MAX_LINE];
    fgets(line, sizeof(line), fp); // Skip the first line (header)
    
    while (fgets(line, sizeof(line), fp)) {
        int local_port=0, remote_port=0, state=0, uid=0, inode=0;
        char local_addr[128]={0}, remote_addr[128]={0}, remote_ip[INET_ADDRSTRLEN]={0};
        
        sscanf(line, "%*d: %64[0-9A-Fa-f]:%x %64[0-9A-Fa-f]:%x %d %*x:%*x %*x:%*x %*x %d %*d %d", 
               local_addr, &local_port, remote_addr, &remote_port, &state, &uid, &inode);
       
        hex_to_ip(remote_addr, remote_ip);
        
        char proc_name[256] = "Unknown";
        int pid = 0;
        get_process_info(inode, proc_name, &pid);
        //if (0 == (pid + local_port + remote_port + remote_ip)) {
        if (0 == (pid + local_port + remote_port )) {
            (*unknown_count)++;
            continue;
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
        
        //printf("%-20s %-10d %-10d %-10s %-20s %-10d\n", proc_name, pid, local_port, protocol, remote_ip, remote_port);
        printf("%-20s %-10d %-10d %-10s %-20s %-10d %-15s\n", proc_name, pid, local_port, protocol, remote_ip, remote_port, state_str);
        //printf("%-20s %-10d %-10d %-10s %-20s %-10d %-15s %-10s\n", proc_name, pid, local_port, protocol, remote_ip, remote_port, state_str, user);
    }
    
    fclose(fp);
}

void get_process_info(int inode, char *proc_name, int *pid) {
    struct dirent *entry;
    DIR *dp = opendir("/proc");
    if (!dp) return;
    
    while ((entry = readdir(dp))) {
        if (!isdigit(entry->d_name[0])) continue;
        
        char fd_path[MAX_PATH];
        snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd", entry->d_name);
        
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
                            fgets(proc_name, 256, comm_fp);
                            proc_name[strcspn(proc_name, "\n")] = 0;
                            fclose(comm_fp);
                        } else {
                            strcpy(proc_name, "Unknown");
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
