#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <pcap.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <pthread.h>
#include <unistd.h>

#define PROMISCUOUS 1
#define TIMEOUT_MS 10000
#define MAX_LINE_LEN 1024
#define DEV_NAME_LEN 64
#define INTERVAL 1 // 多少秒统计一次数据
#define MAX_PATH 4096

//定义文件流和日志文件名
FILE *networks_log,*process_log,*cpu_log;

//定义启动时间
time_t start_time;


void open_log_files(){
networks_log = fopen("networks_log.txt","w");
process_log = fopen("process_log.txt","w");
cpu_log = fopen("cpu_log.txt","w");

if(networks_log == NULL || process_log == NULL || cpu_log == NULL){
	perror("fopen failed");
	exit(1);
	}
}

void close_log_files(){
	fclose(networks_log);
	fclose(process_log);
	fclose(cpu_log);
}

char* whitelist[] = {"init", "sshd", "bash"};

void print_cpu_usage() {
 time_t current_time = time(NULL);
    struct tm *local_time = localtime(&current_time);

   
   
    FILE *fp = popen("ps -eo %cpu,pid,user,args --sort=-%cpu | head", "r");
    if (fp == NULL) {
        perror("popen failed");
        exit(1);
    }

    char buffer[1024];
    printf("CPU利用率最高的进程或程序：\n");
      fprintf(cpu_log, "%04d-%02d-%02d %02d:%02d:%02d - CPU利用率最高的进程或程序：\n",
            local_time->tm_year + 1900, local_time->tm_mon + 1, local_time->tm_mday,
            local_time->tm_hour, local_time->tm_min, local_time->tm_sec);

   
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        printf("%s", buffer);
       fprintf(cpu_log,"%s", buffer);
    }
    pclose(fp);
}

int get_process_name(const char* pid, char* name) {
    char path[MAX_PATH];
    FILE *fp;
    sprintf(path, "/proc/%s/cmdline", pid);
    fp = fopen(path, "r");
    if (fp) {
        if (fgets(name, MAX_PATH, fp) != NULL) {
            fclose(fp);
            return 0;
        }
        fclose(fp);
    }
    return -1;
}
void print_cpu_load() {
 time_t current_time = time(NULL);
    struct tm *local_time = localtime(&current_time);
    FILE *fp = fopen("/proc/loadavg", "r");
    if (fp == NULL) {
        perror("fopen failed");
        exit(1);
    }

    char buffer[1024];
    fgets(buffer, sizeof(buffer), fp);
    fclose(fp);

    double load_avg_1, load_avg_5, load_avg_15;
    sscanf(buffer, "%lf %lf %lf", &load_avg_1, &load_avg_5, &load_avg_15);

    printf("1分钟内的平均负载: %.2f\n", load_avg_1);
    printf("5分钟内的平均负载: %.2f\n", load_avg_5);
    printf("15分钟内的平均负载: %.2f\n", load_avg_15);
    fprintf(cpu_log,"%04d-%02d-%02d %02d:%02d:%02d - 1分钟内的平均负载: %.2f\n",  local_time->tm_year + 1900, local_time->tm_mon + 1, local_time->tm_mday,
            local_time->tm_hour, local_time->tm_min, local_time->tm_sec,load_avg_1);
     fprintf(cpu_log,"%04d-%02d-%02d %02d:%02d:%02d - 5分钟内的平均负载: %.2f\n",  local_time->tm_year + 1900, local_time->tm_mon + 1, local_time->tm_mday,
            local_time->tm_hour, local_time->tm_min, local_time->tm_sec,load_avg_5);
}

void print_memory_usage() {
	 time_t current_time = time(NULL);
    struct tm *local_time = localtime(&current_time);
    
    FILE *fp = fopen("/proc/meminfo", "r");
    if (fp == NULL) {
        perror("fopen failed");
        exit(1);
    }

    char buffer[1024];
    unsigned long total_mem = 0, free_mem = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        if (sscanf(buffer, "MemTotal: %lu kB", &total_mem) == 1) {
            printf("总内存：%lu kB\n", total_mem);
             fprintf(cpu_log,"%04d-%02d-%02d %02d:%02d:%02d - 总内存：%lu kB\n",local_time->tm_year + 1900, local_time->tm_mon + 1, local_time->tm_mday,
            local_time->tm_hour, local_time->tm_min, local_time->tm_sec,total_mem);
        } else if (sscanf(buffer, "MemFree: %lu kB", &free_mem) == 1) {
            printf("空闲内存：%lu kB\n", free_mem);
            fprintf(cpu_log,"%04d-%02d-%02d %02d:%02d:%02d - 空闲内存：%lu kB\n",local_time->tm_year + 1900, local_time->tm_mon + 1, local_time->tm_mday,
            local_time->tm_hour, local_time->tm_min, local_time->tm_sec,free_mem);
            break;  // 已获取到总内存和空闲内存，退出循环
        }
    }

    fclose(fp);

    double memory_usage = ((double)(total_mem - free_mem) / total_mem) * 100.0;

    printf("内存利用率: %.2f%%\n", memory_usage);
    fprintf(cpu_log,"%04d-%02d-%02d %02d:%02d:%02d - 内存利用率: %.2f%%\n",local_time->tm_year + 1900, local_time->tm_mon + 1, local_time->tm_mday,
            local_time->tm_hour, local_time->tm_min, local_time->tm_sec,memory_usage);
    
}

void monitor_cpu() {
  struct tm *local_time;
    unsigned long prev_user_jiffies = 0;
    unsigned long prev_nice_jiffies = 0;
    unsigned long prev_system_jiffies = 0;
    unsigned long prev_idle_jiffies = 0;
   
    while (1) {
    time_t current_time = time(NULL);
    struct tm *local_time = localtime(&current_time);
        FILE *fp = fopen("/proc/stat", "r");
        
        char buffer[256];
        if (fp != NULL) {
            fgets(buffer, sizeof(buffer), fp); // 读取总的 CPU 利用情况
            sscanf(buffer, "cpu %lu %lu %lu %lu", &prev_user_jiffies, &prev_nice_jiffies, &prev_system_jiffies, &prev_idle_jiffies);
            fclose(fp);

            sleep(INTERVAL);

            fp = fopen("/proc/stat", "r");
            if (fp != NULL) {
                unsigned long user_jiffies, nice_jiffies, system_jiffies, idle_jiffies;
                fgets(buffer, sizeof(buffer), fp);
                sscanf(buffer, "cpu %lu %lu %lu %lu", &user_jiffies, &nice_jiffies, &system_jiffies, &idle_jiffies);
                fclose(fp);

                unsigned long total_delta = (user_jiffies + nice_jiffies + system_jiffies + idle_jiffies) - (prev_user_jiffies + prev_nice_jiffies + prev_system_jiffies + prev_idle_jiffies);
                unsigned long idle_delta = idle_jiffies - prev_idle_jiffies;

                double cpu_usage = ((double)(total_delta - idle_delta) / total_delta) * 100.0;

                printf("当前CPU利用率：%.2f%%\n", cpu_usage);
                fprintf(cpu_log,"%04d-%02d-%02d %02d:%02d:%02d - 当前CPU利用率：%.2f%%\n",local_time->tm_year + 1900, local_time->tm_mon + 1, local_time->tm_mday,
            local_time->tm_hour, local_time->tm_min, local_time->tm_sec,cpu_usage);

                prev_user_jiffies = user_jiffies;
                prev_nice_jiffies = nice_jiffies;
                prev_system_jiffies = system_jiffies;
                prev_idle_jiffies = idle_jiffies;
            }
        }

        print_cpu_load();  // 打印CPU负载
        print_memory_usage(); //打印内存利用率

        sleep(INTERVAL); // 等待一段时间后再次统计
    }
}
void monitor_process() {
 struct tm *local_time;
    while (1) {
        int whitelist_count = sizeof(whitelist) / sizeof(whitelist[0]);
        int blacklist_count = 0;
        time_t current_time = time(NULL);
    struct tm *local_time = localtime(&current_time);

        struct dirent *entry;
        DIR *dp = opendir("/proc");

        if (dp == NULL) {
            perror("opendir");
            return;
        }
printf("->----------------------进程检测中------------------\n");
 fprintf(process_log,"%04d-%02d-%02d %02d:%02d:%02d - Whitelist processes:\n",local_time->tm_year + 1900, local_time->tm_mon + 1, local_time->tm_mday,
            local_time->tm_hour, local_time->tm_min, local_time->tm_sec);
        printf("Whitelist processes:\n");
        for (int i = 0; i < whitelist_count; i++) {
            printf("%s\n", whitelist[i]);
            fprintf(process_log,"%s\n", whitelist[i]);
        }

        while ((entry = readdir(dp))) {
            if (atoi(entry->d_name) != 0) {
                char process_name[MAX_PATH];
                if (get_process_name(entry->d_name, process_name) == 0) {
                    int in_whitelist = 0;
                    for (int i = 0; i < whitelist_count; i++) {
                        if (strcmp(process_name, whitelist[i]) == 0) {
                            in_whitelist = 1;
                            break;
                        }
                    }
                    if (!in_whitelist) {
                        blacklist_count++;
                         fprintf(process_log,"%04d-%02d-%02d %02d:%02d:%02d - Blacklisted process: %s\n", local_time->tm_year + 1900, local_time->tm_mon + 1, local_time->tm_mday,
            local_time->tm_hour, local_time->tm_min, local_time->tm_sec,process_name);
                        printf("Blacklisted process: %s\n", process_name);
                    }
                }
            }
        }

        closedir(dp);

        printf("Whitelist count: %d\n", whitelist_count);
        printf("Blacklist count: %d\n", blacklist_count);
         fprintf(process_log,"%04d-%02d-%02d %02d:%02d:%02d - Whitelist count: %d\n",local_time->tm_year + 1900, local_time->tm_mon + 1, local_time->tm_mday,
            local_time->tm_hour, local_time->tm_min, local_time->tm_sec, whitelist_count);
fprintf(process_log,"%04d-%02d-%02d %02d:%02d:%02d - Blacklist count: %d\n\n", local_time->tm_year + 1900, local_time->tm_mon + 1, local_time->tm_mday,
            local_time->tm_hour, local_time->tm_min, local_time->tm_sec,blacklist_count);
        print_cpu_usage(); // 打印CPU利用率最高的进程或程序

        sleep(INTERVAL); // 等待一段时间后再次统计
    }
}

// 定义网络接口结构体
struct net_dev {
    char name[DEV_NAME_LEN];
    unsigned long long in_bytes;
    unsigned long long out_bytes;
    unsigned long long in_packets;
    unsigned long long out_packets;
    unsigned long long in_icmp;
    unsigned long long out_icmp;
    unsigned long long in_udp;
    unsigned long long out_udp;
    unsigned long long in_tcp;
    unsigned long long out_tcp;
};
// 读取 /proc/net/dev 文件获取网络接口数据
int read_net_dev(struct net_dev *dev_list) {
    FILE *fp;
    char line[MAX_LINE_LEN];
    int i = 0;

    fp = fopen("/proc/net/dev", "r");
    if (fp == NULL) {
        perror("fopen");
        fclose(fp);
        return 0;
    }

    while (fgets(line, MAX_LINE_LEN, fp) != NULL) {
        char *p = strchr(line, ':');
        if (p != NULL) {
            struct net_dev *dev = &dev_list[i++];
            *p = '\0';

            // 获取接口名称
            strncpy(dev->name, line, DEV_NAME_LEN);

            // 解析接口数据
            sscanf(p + 1, "%llu %*u %*u %*u %*u %*u %*u %*u %llu %*u %*u %*u %*u %*u %*u %*u %llu %*u %*u %*u %llu %*u %*u %*u %llu %*u %*u %*u",
                &dev->in_bytes, &dev->out_bytes, &dev->in_packets, &dev->out_packets, &dev->in_icmp, &dev->out_icmp,
                &dev->in_udp, &dev->out_udp, &dev->in_tcp, &dev->out_tcp);
        }
    }

    fclose(fp);
    return i;
}

void *network_monitor(void *arg) {
    struct net_dev old_dev_list[128], new_dev_list[128];
    //int interval = 1; // 统计时间间隔，单位为分钟

    while (1) {
        // 获取新的网络接口数据
        int num_devs = read_net_dev(new_dev_list);

        // 计算流量和包数量
        for (int i = 0; i < num_devs; i++) {
            struct net_dev *old_dev = &old_dev_list[i];
            struct net_dev *new_dev = &new_dev_list[i];

            unsigned long long in_bytes = new_dev->in_bytes - old_dev->in_bytes;
            unsigned long long out_bytes = new_dev->out_bytes - old_dev->out_bytes;

            // 计算带宽利用率
            double bw_utilization = (double)(in_bytes + out_bytes) * 8 / INTERVAL / 1000000;
printf("->----------------流量检测中---------------------\n");
            printf("[%s] Incoming Traffic: %llu bytes, Outgoing Traffic: %llu bytes, Total Traffic: %llu bytes, Bandwidth Utilization: %.2f Mbps\n",
                   new_dev->name, in_bytes, out_bytes, in_bytes + out_bytes, bw_utilization);
                 fprintf(networks_log,"[%s] Incoming Traffic: %llu bytes, Outgoing Traffic: %llu bytes, Total Traffic: %llu bytes, Bandwidth Utilization: %.2f Mbps\n",
                   new_dev->name, in_bytes, out_bytes, in_bytes + out_bytes, bw_utilization);
        }

        memcpy(old_dev_list, new_dev_list, sizeof(new_dev_list));
        sleep(INTERVAL);
    }

    pthread_exit(NULL);
}

time_t last_packet_print_time = 0;
time_t last_stat_time = 0;
int tcp_count = 0, udp_count = 0, icmp_count = 0, http_count = 0, other_count = 0;
void packet_handler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet) {
    struct ip *ip_hdr;
    struct tcphdr *tcp_hdr;
    struct udphdr *udp_hdr;
    unsigned short ip_hdr_len, tcp_hdr_len, udp_hdr_len, sport, dport;
FILE *networks_log=(FILE *)user;
    // 解析IP头部
    ip_hdr = (struct ip *)(packet + sizeof(struct ethhdr));
    ip_hdr_len = ip_hdr->ip_hl * 4;

    // 根据协议类型进行处理
    switch (ip_hdr->ip_p) {
        case IPPROTO_TCP:
            // 解析TCP头部
            tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_hdr_len);
            tcp_hdr_len = tcp_hdr->th_off * 4;

            // 统计TCP包数量
            tcp_count++;

            // 获取源端口和目标端口
            sport = ntohs(tcp_hdr->th_sport);
            dport = ntohs(tcp_hdr->th_dport);

            // 输出TCP包信息
            printf("TCP packet: Source Port=%u, Destination Port=%u\n", sport, dport);
             fprintf(networks_log,"TCP packet: Source Port=%u, Destination Port=%u\n", sport, dport);
              fflush(networks_log);
            break;
        case IPPROTO_UDP:
            // 解析UDP头部
            udp_hdr = (struct udphdr *)(packet + sizeof(struct ethhdr) + ip_hdr_len);
            udp_hdr_len = sizeof(struct udphdr);

            // 统计UDP包数量
            udp_count++;

            // 获取源端口和目标端口
            sport = ntohs(udp_hdr->uh_sport);
            dport = ntohs(udp_hdr->uh_dport);

            // 输出UDP包信息
            printf("UDP packet: Source Port=%u, Destination Port=%u\n", sport, dport);
            fprintf(networks_log,"UDP packet: Source Port=%u, Destination Port=%u\n", sport, dport);
             fflush(networks_log);
            break;
        case IPPROTO_ICMP:
            // 统计ICMP包数量
            icmp_count++;

            // 输出ICMP包信息
            printf("ICMP packet\n");
            fprintf(networks_log,"ICMP packet\n");
             fflush(networks_log);
            break;
        default:
            // 统计其他类型协议包数量
            other_count++;

            // 输出其他类型协议包信息
            printf("Other protocol packet (Protocol=%u)\n", ip_hdr->ip_p);
          fprintf(networks_log,"Other protocol packet (Protocol=%u)\n", ip_hdr->ip_p);  
           fflush(networks_log); 
    }
    // 判断是否为HTTP请求或响应
    if (strstr((char *)(packet + sizeof(struct ethhdr) + ip_hdr_len + tcp_hdr_len), "HTTP/1.") != NULL) {
        http_count++;
    }

    // 获取当前时间
    time_t current_time = time(NULL);

    // 每秒输出一次协议包信息
    
    if (current_time - last_packet_print_time >= 1) {
        last_packet_print_time = current_time;
        
        print_statistics(networks_log,tcp_count, udp_count, icmp_count, http_count, other_count);
        
        
    }

    // 每隔50秒统计一次信息
        if (current_time - last_packet_print_time >= INTERVAL) {
        last_packet_print_time = current_time;
        printf("%d seconds statistics:\n",INTERVAL);
        print_statistics(networks_log,tcp_count, udp_count, icmp_count, http_count, other_count);
         fflush(networks_log);
        }
}
void print_statistics(FILE *networks_log,int tcp_count, int udp_count, int icmp_count, int http_count, int other_count)
{
    printf("TCP packets: %d, UDP packets: %d, ICMP packets: %d, HTTP packets: %d, Other packets: %d\n", tcp_count, udp_count, icmp_count, http_count, other_count);
     fprintf(networks_log,"TCP packets: %d, UDP packets: %d, ICMP packets: %d, HTTP packets: %d, Other packets: %d\n", tcp_count, udp_count, icmp_count, http_count, other_count);  
      fflush(networks_log);
}

int main(int argc, char **argv) {
    pthread_t network_thread, tid_cpu, tid_process;
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "";
    bpf_u_int32 mask, net;
    
    //打开日志文件
    open_log_files();
    
    start_time = time(NULL);
    
   
    
     if (pthread_create(&tid_cpu, NULL, (void*)monitor_cpu, NULL) != 0) {
        perror("pthread_create failed");
        exit(1);
    }

    if (pthread_create(&tid_process, NULL, (void*)monitor_process, NULL) != 0) {
        perror("pthread_create failed");
        exit(1);
    }
    // 创建网络监控线程
    if (pthread_create(&network_thread, NULL, network_monitor, NULL) != 0) {
        fprintf(stderr, "Error creating network monitoring thread\n");
        return 1;
    }

    // 获取默认网络接口
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 2;
    }
    printf("Using device: %s\n", dev);

    // 获取网络接口的掩码和IP地址
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    // 打开网络接口
    handle = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, TIMEOUT_MS, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // 编译BPF过滤器
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // 设置过滤器
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // 捕获数据包并处理
    pcap_loop(handle, -1, packet_handler, (unsigned char *)networks_log);

    // 关闭网络接口
    pcap_close(handle);
    
    if (pthread_join(tid_cpu, NULL) != 0) {
        perror("pthread_join failed");
        exit(1);
    }

    if (pthread_join(tid_process, NULL) != 0) {
        perror("pthread_join failed");
        exit(1);
    }
    // 等待网络监控线程结束
    if(pthread_join(network_thread, NULL)!=0){
    perror("pthread_join failed");
        exit(1);
    }
  //关闭日志文件
    close_log_files();
    return 0;
}

