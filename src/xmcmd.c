#include "driver_hisi_lib_api.h"
#include "hostapd_if.h"
#include "wpa_supplicant.h"
#include "sys/socket.h"
#include "liteos/in.h"
#include "string.h"
#include "sys/endian.h"
#include "arpa/inet.h"
#include "unistd.h"
#include "stdlib.h"
#include "hisi_wifi.h"
#include "lwip/tcpip.h"
#include "lwip/sockets.h"
#include "los_mux.h"
#include "shell.h"
#include "linux/completion.h"



#include "xmconnect.h"
#include "xmextlib.h"

#include "xmnet.h"





#define NVR_IP_ADDR 						"172.25.123.1"
#define CONNNECTED_NVR_CONF 				"/jffs1/mnt/mtd/Config/last.conf"
#define CONNNECTED_SLEEP_FLAG 				"/jffs1/mnt/mtd/Config/sleep.conf"
#define IPC_INFO_ENABLE_FLAG 				"/jffs1/mnt/mtd/Config/heartbeat_info"
#define NVR_WIFI_SSID_PREFIX 				"WIFINVR"
#define BRG_WIFI_SSID_PREFIX				"WIFIBRG"
#define FRAME_WIDTH							704
#define FRAME_HEIGHT						576


extern unsigned int g_wake_event;						//唤醒条件使能事件集合		默认[000001DF]
extern unsigned int g_before_sleep_wlan_flag ;			//0:唤醒睡眠前没有配上网，1：唤醒睡眠前已经配上网
extern unsigned int g_variable_mux ;					//变量赋值互斥量
extern unsigned int g_function_mux ;					//程序段执行互斥量
extern unsigned int g_wakup_reason;						//主控唤醒的原因
extern unsigned int g_hostapd_had_run;					//0：hostapd没有运行		1：hostapd已经运行
extern unsigned int g_wpa_supplicant_had_run;			//0：wpa_supplicant没有运行	1：wpa_supplicant已经运行
extern unsigned int g_wpa_supplicant_had_sock ;			//0：没有成功连接sock		1：已经连接成功sock



extern int g_sockfd[4]; 								//记录tcp连接的socket描述符

extern unsigned char g_keepalive_switch;                //保活开关
extern unsigned char g_index ; 							//已经创建的tcp链数（本项目只用一个tcp链）



//外部库全局变量引用
extern unsigned int g_ul_xm_wlan_resume_state;			//系统启动标志 								libdvr/net.c定义

extern unsigned int g_force_sleep_flag;					//十分钟强制关闭标志								hi_ext_hal_mcu.c定义

extern unsigned int g_wpa_supplicant_had_connect;		//无线模块作为客户端，是否连接上热点并且获得ip				libdvr/net.c定义


extern struct completion  g_dhcp_complet;				//完成量变量：等待ip获取成功		app_init.c 定义



struct     hostapd_conf     g_hapd_conf ;








//测试queue队列
static Queue *test_queue = NULL;




static void cmd_connect_ap_help(void)
{

	printf("\nUsage:\n"
			"\tconnect_ap <channel> <ssid_name> <security_mode> <encryption> <security_key>\n"
			"\tchannel    : Channel number\n"
			"\tessid      : Name of access point\n"
			"\tsecurity   : [none] [wep-open] [wep-shared] [wpa] [wpa2] [wpa+wpa2]\n"
			"\tencryption : [tkip] [aes] [tkip+aes]-For WPA/WPA2 and key index for WEP\n"
			"\tkey        : Passphrase / WEP Key\n"
			"\nExample:\n"
			"\tconnect_ap 9 softap none\t(Connect with AP 'softap' in open authentication)\n"
			"\tconnect_ap 9 softap   wep_open 0 wepkey\t(Connect with AP 'softap' in wep open mode with key index 0 and key value of 'wpakey')\n"
			"\tconnect_ap 9 softap  wpa2 tkip wepkey\t(Connect with AP 'softap' in WPA2 mode in tkip encryption with key value of 'wpakey')\n");

}

static void cmd_connect_wpa_help(void)
{
	printf("\nUsage:\n"
			"\tconnect_wpa <ssid_name> <security_mode> <security_key>\n"
			"\tssid_name  : name of ssid\n"
			"\tsecurity   : [none] [wpa]  [wpa2] [wpa+wpa2]\n"
			"\tkey        : Passphrase / WEP Key\n"
			"\nExample:\n"
			"\tconnect_wpa ipctest open\t(Connect with AP 'ipctest' in open authentication)\n"
			"\tconnect_wpa ipctest wpa 12345678\t(Connect with AP 'ipctest' in wpa mode with key value of '12345678')\n"
			"\tconnect_wpa ipctest wpa2 12345678\t(Connect with AP 'ipctest' in wpa2 mode with key value of 'wpakey')\n");

}




static int cmd_get_attr_xm(int argc, unsigned char *argv[])
{
	struct netif    *pst_lwip_netif = NULL;

	struct in_addr ip_addr;
	struct in_addr mask_addr;
	struct in_addr gateway_addr;
	char hw_addr[32] = {0};

	unsigned int type = 0;
	type = atoi(argv[1]);
	
	
	
	pst_lwip_netif = netif_find(argv[0]);
	if (HISI_NULL == pst_lwip_netif)
	{
		printf("[%s]: get <struct netif> info error.\n", __FUNCTION__);
		return -1;
	}

	if(type == IP_ADDR)
	{
		ip_addr.s_addr = pst_lwip_netif->ip_addr.addr;
		printf("get IpAddr success: %s\n", inet_ntoa(ip_addr));
	}
	else if(type == NETMASK_ADDR)
	{
		mask_addr.s_addr = pst_lwip_netif->netmask.addr;
		printf("get NetmaskAddr success: %s\n", inet_ntoa(mask_addr));
	}
	else if(type == GATEWAY_ADDR)
	{
		gateway_addr.s_addr = pst_lwip_netif->gw.addr;
		printf("get  GatewayAddr success: %s\n", inet_ntoa(gateway_addr));
		
	}
	else if(type == HW_ADDR)
	{
		if(!XmGetHwAttr(argv[0], type, hw_addr))
		{
			printf("get MacAddr success: %02x%02x%02x%02x%02x%02x\n", hw_addr[0], hw_addr[1], hw_addr[2], hw_addr[3], hw_addr[4], hw_addr[5]);
		}
	}
	else
	{
		printf("the type is error.please input 0~3.\n");
		return -1;
	}

	
	return 0;
	
}

static int cmd_set_attr_xm(int argc, unsigned char *argv[])
{
	ip_addr_t        st_gw;
	ip_addr_t        st_ipaddr;
	ip_addr_t        st_netmask;

	char hw_addr[32] = {0};
	int type = 0;

	type = atoi(argv[1]);
	
	
	struct netif    *pst_lwip_netif = NULL;

	pst_lwip_netif = netif_find(argv[0]);
	if (HISI_NULL == pst_lwip_netif)
	{
		printf("cmd_start_hapd::Null param of netdev.\n");
		return -1;
	}

	
	
	if(type == IP_ADDR)
	{
		st_ipaddr.addr = inet_addr(argv[2]);
		netif_set_ipaddr(pst_lwip_netif, &st_ipaddr);
		printf("set IpAddr success: %s\n", argv[2]);
	}
	else if(type == NETMASK_ADDR)
	{
		st_netmask.addr = inet_addr(argv[2]);
		netif_set_netmask(pst_lwip_netif, &st_netmask);
		printf("set NetmaskAddr success: %s\n", argv[2]);
	}
	else if(type == GATEWAY_ADDR)
	{
		st_gw.addr = inet_addr(argv[2]);
		netif_set_gw(pst_lwip_netif, &st_gw);	
		printf("set GatewayAddr success: %s\n", argv[2]);
	}
	else if(type == HW_ADDR)
	{
		sscanf(argv[2],"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&hw_addr[0],&hw_addr[1],&hw_addr[2],
												&hw_addr[3], &hw_addr[4], 	&hw_addr[5]);
		
		netif_set_hwaddr(pst_lwip_netif, hw_addr, 6);
		printf("set HwAddr success: %s\n", argv[2]);

	}
	else
	{
		printf("the type is error.please input 0~3.\n");
		return -1;
	}
	
	return 0;
}






static int cmd_sock_test_xm(int argc, char *argv[])
{
	int selres;
	int clientfd;  
	struct sockaddr_in serveraddr;  
	char buffer[128] = {0}; 
	int ret = 0;
	struct  timeval tv;
	fd_set rfds, wfds ;
	int connected = 0;

	int cmdnum = 0, recesize = 0;

	//g_index =0;
	//g_sockfd[0] = -1;



	if((clientfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)  
	{  
		printf("socket error");  
		return -1;  
	}  
	else  
	{  
		printf("clientfd:%d\n",clientfd);  
	}  
	//设置服务端的IP地址和端口号  
	memset(&serveraddr,0,sizeof(serveraddr));  
	serveraddr.sin_family = AF_INET;  
	serveraddr.sin_port = htons(9988);  
	serveraddr.sin_addr.s_addr = inet_addr("172.25.123.88");  

	unsigned long ul = 1;
	ioctl(clientfd, FIONBIO, &ul); //设置为非阻塞模式

	ret = connect(clientfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr));	

	if(ret < 0)
	{
	
		
		if (errno == EINPROGRESS)
		{
			int times = 0;  
			while (times++ < 5) 
			{
				tv.tv_sec = 10;
				tv.tv_usec = 0;

				FD_ZERO(&rfds);
				FD_ZERO(&wfds);
				FD_SET(clientfd, &rfds);
				FD_SET(clientfd, &wfds);
				selres = select(clientfd+1, &rfds, &wfds, NULL, &tv);
				switch (selres)  
				{  
					case -1:  
						printf("select error\n");  
						connected = -1;  
						break;  
					case 0:  
						printf("select time out\n");  
						connected = -1;  
						break;  
					default:  
						if (FD_ISSET(clientfd, &rfds) || FD_ISSET(clientfd, &wfds))  
						{  
							printf("\nFD_ISSET(clientfd, &rfds): %d\nFD_ISSET(clientfd, &wfds): %d\n", FD_ISSET(clientfd, &rfds) , FD_ISSET(clientfd, &wfds));  
							connect(clientfd, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr_in));  
							
							int err = errno;  
							if  (err == EISCONN)  
							{  
								printf("connect success.\n");  
								connected = 1;  
							}  
							else  
							{  
								printf("connect failed. errno = %d\n", errno);  
								
								connected = 0;  
							}  

						}  
						else  
						{  
							printf("haha\n");  
						}  
				}  

				if (-1 != selres && (connected != 1))  
				{  
					printf("check connect result again... %d\n", times);  
					continue;  
				}  
				else  
				{  
					break;  
				}  


			}
		}
	}

	unsigned long ull = 0;
	ioctl(clientfd, FIONBIO, &ull); //设置为非阻塞模式

	if(connected == 1)  
	{  
		//g_index =1;
		//g_sockfd[0] = clientfd;
		
		while(1)
		{
			memcpy(buffer, "IPC999", 6);

			usleep(1000*1000*25);
		
			if(send(clientfd,buffer,7,0) == -1)  
			{  
				perror("send error"); 
				printf("begin to close clientfd.\n");
				close(clientfd);
				return 0;  
			}  
			else
			{
				printf("send success!\n");
				
			}
			memset(buffer,0,sizeof(buffer)); //清空buffer  
			
			recesize = recv(clientfd,buffer,sizeof(buffer),0);
			if(recesize < 0)
			{
				printf("can not recv any thing..\n");
				return -1;
			}		
			
			printf("recv buf:%s\n", buffer);

		}						
		
	}  
	else
	{
		//g_index =0;
		//g_sockfd[0] = -1;
	}
	close(clientfd);  

	return 0;  


}

static int cmd_arp_test_xm(void)
{
	Wireless_Ipconfig(0);

	return 0;
}

static int cmd_nvr_connect_xm(void)
{
	int uwRet = 0;
	int sockfd = -1;

	
	//判断是否开启ap模式，如果开启，关闭
	if(g_hostapd_had_run)
	{
		hapd_stop_xm();
	}

	if(g_ul_xm_wlan_resume_state == 0)
	{
		if(g_wpa_supplicant_had_run)
		{		
			wpa_stop_xm();
		}
	 
	    uwRet = wpa_supplicant_start("wlan0", "hisi", NULL);

	    if (uwRet != 0)
	    {
	        printf("cmd_wpa_start fail.\n");
	        return -1;
	    }
		else
		{
			printf("cmd_wpa_start success\n");
			Mux_Operate(&g_wpa_supplicant_had_run, 1);
		}
		
		hisi_wlan_enable_channel_14();

		
	}

	if(g_wpa_supplicant_had_connect)
	{
		wpa_disconnect_xm();
	}
	
	struct wpa_assoc_request wpa_assoc_req ;

	
	memset(&wpa_assoc_req, 0, (sizeof(struct wpa_ap_info)));	

	memcpy(wpa_assoc_req.ssid, "WIFINVR00ac78540001", 33);
	memcpy(wpa_assoc_req.key, "XMNVR123456", strlen("XMNVR123456"));
	
	wpa_assoc_req.auth = 4;
	wpa_assoc_req.hidden_ssid = 0;

	uwRet = wpa_cli_connect(&wpa_assoc_req);
	if(uwRet == 0)
	{
		printf("wpa_cli_connect success.wait udhc get ip\n");
		
		init_completion(&g_dhcp_complet);

		uwRet = wait_for_completion_timeout(&g_dhcp_complet, LOS_MS2Tick(40000));//40s超时
		if (0 == uwRet)
		{
			printf("can not  get ip\n");
			return -1;
		}
		else
		{
			printf("success get ip\n");
			memcpy(g_IpcRuningData.WifiNvrInfo.ssid, wpa_assoc_req.ssid, sizeof(wpa_assoc_req.ssid));
			
		}
		
		
	}

#if 0	
	sockfd = ConnectNvrSocket(NVR_IP_ADDR);
	if (sockfd < 0)
	{
		printf("ConnectNvrSocket failed\n");
		
	}
	else
	{
		printf("ConnectNvrSocket succeed\n");
		
    }
#endif


	return 0;
}


static void cmd_get_station_xm(void)
{

	
	struct station_info st_sta ;

	memset(&st_sta, 0, sizeof(st_sta));
	
	/*获取station信息*/
	if (HISI_SUCC != hisi_wlan_get_station(&st_sta))
	{
		printf("get station info fail!\n");
		return;
	}

	if(!g_wpa_supplicant_had_connect)
	{
		st_sta.l_signal = 0;
		st_sta.l_txrate = 0;
	}

	printf("get station info succ!\n");
	
	printf("connect = %d,rssi = %d,tx rate = %d/10 Mbps\n",g_wpa_supplicant_had_connect, st_sta.l_signal,st_sta.l_txrate);

	return;
}







static void cmd_wpa_connect_xm(int argc, char *argv[])
{
	struct wpa_assoc_request wpa_assoc_req;
	unsigned char auth_type[32],key[64];
	unsigned char err;
	int uwRet = 0;

	//判断是否开启ap模式，如果开启，关闭
	if(g_hostapd_had_run)
	{
		hapd_stop_xm();
	}
	

	//帮助信息
	if ((argc < 2) ||(memcmp(argv[0], "help", 4) == 0))
	{
		
		cmd_connect_wpa_help();
		return;
	}

	//开启wpa_supplicant
	if(g_ul_xm_wlan_resume_state == 0)
	{
		if(g_wpa_supplicant_had_run)
		{		
			wpa_stop_xm();
		}
	 
	    uwRet = wpa_supplicant_start("wlan0", "hisi", NULL);

	    if (uwRet != 0)
	    {
	        printf("cmd_wpa_start fail.\n");
	        return;
	    }
		else
		{
			printf("cmd_wpa_start success\n");
			Mux_Operate(&g_wpa_supplicant_had_run, 1);
		}
		
		hisi_wlan_enable_channel_14();
	}

	
	if(g_wpa_supplicant_had_connect)
	{
		wpa_disconnect_xm();
	}
	
	//开始连接指定热点
	memset(&wpa_assoc_req , 0 ,sizeof(struct wpa_assoc_request));

	//get hidden_ssid
	wpa_assoc_req.hidden_ssid=0;

	//get ssid
	if (strlen(argv[0]) >= sizeof(wpa_assoc_req.ssid))
	{
		cmd_connect_wpa_help();
		return;
	}
	strcpy(wpa_assoc_req.ssid,argv[0]);
	printf("wpa_connect: ssid: %s\n",wpa_assoc_req.ssid);

	//get auth_type
	if (strlen(argv[1]) >= sizeof(auth_type))
	{
		cmd_connect_wpa_help();
		return;
	}
	strcpy(auth_type,argv[1]);
	if (!strcmp(auth_type, "open"))
	{
		wpa_assoc_req.auth = WPA_SECURITY_OPEN;
	}
	else if (!strcmp(auth_type, "wep"))
	{
		wpa_assoc_req.auth = WPA_SECURITY_WEP;
	}
	else if (!strcmp(auth_type, "wpa"))
	{
		wpa_assoc_req.auth = WPA_SECURITY_WPAPSK;
	}
	else if (!strcmp(auth_type, "wpa2"))
	{
		wpa_assoc_req.auth = WPA_SECURITY_WPA2PSK;
	}
	else if (!strcmp(auth_type, "wpa+wpa2"))
	{
		wpa_assoc_req.auth = WPA_SECURITY_WPAPSK_WPA2PSK_MIX;
	}
	else
	{
		cmd_connect_wpa_help();
		return;
	}

	printf("wpa_connect: Authentication Type = %d\n",wpa_assoc_req.auth);

	//get key
	if (argc >= 3)
	{
		if (strlen(argv[2]) >= sizeof(wpa_assoc_req.key))
		{
			cmd_connect_wpa_help();
			return;
		}
		strcpy(wpa_assoc_req.key, argv[2]);

		printf("wpa_connect: Key = %s\n",wpa_assoc_req.key);

	}

	uwRet = wpa_cli_connect(&wpa_assoc_req);
	if(uwRet == 0)
	{
		printf("wpa_cli_connect success.\n");
		
		uwRet = wait_for_completion_timeout(&g_dhcp_complet, LOS_MS2Tick(40000));//40s超时
		if (0 == uwRet)
		{
			printf("can not  get ip\n");
			return ;
		}
		else
		{
			printf("success get ip\n");
			memcpy(g_IpcRuningData.WifiNvrInfo.ssid, wpa_assoc_req.ssid, sizeof(wpa_assoc_req.ssid));
			
		}
	}


}




void cmd_hapd_connect_xm(int argc, unsigned char *argv[])
{
    ip_addr_t           st_gw;
    ip_addr_t           st_ipaddr;
    ip_addr_t           st_netmask;
    struct netif       *pst_lwip_netif = NULL;
    unsigned char      *puc_encipher_mode = NULL;

	//尝试删除wpa,ap,dhcp,dhcps
	if(g_wpa_supplicant_had_run)
	{
		wpa_stop_xm();
	}

	if(g_wpa_supplicant_had_connect)
	{
		wpa_disconnect_xm();
	}
	
	if(g_hostapd_had_run)
	{
		hapd_stop_xm();
	}
	
   
    memset(&g_hapd_conf, 0, sizeof(struct hostapd_conf));

    IP4_ADDR(&st_gw, 192, 168, 10, 1);
    IP4_ADDR(&st_ipaddr, 192, 168, 10, 1);
    IP4_ADDR(&st_netmask, 255, 255, 255, 0);

    pst_lwip_netif = netif_find("wlan0");
    if (HISI_NULL == pst_lwip_netif)
    {
        printf("cmd_start_hapd::Null param of netdev\n");
        return;
    }

	if ((memcmp(argv[0], "help", 4) == 0) ||(argc == 0) ||(atoi(argv[0]) > 14))
    {
        cmd_connect_ap_help();
        return;
    }

 
    memcpy(g_hapd_conf.driver, "hisi", 5);
    g_hapd_conf.channel_num = atoi(argv[0]);
    memcpy(g_hapd_conf.ssid, argv[1], 32);
    g_hapd_conf.ignore_broadcast_ssid = 0;
    memcpy(g_hapd_conf.ht_capab, "[HT20]", 7);

    puc_encipher_mode = argv[2];

    if (!strcmp(puc_encipher_mode, "none"))
    {
        g_hapd_conf.authmode = HOSTAPD_SECURITY_OPEN;
    }
    else if (!strcmp(puc_encipher_mode, "wpa"))
    {
        g_hapd_conf.authmode = HOSTAPD_SECURITY_WPAPSK;
    }
    else if (!strcmp(puc_encipher_mode, "wpa2"))
    {
        g_hapd_conf.authmode = HOSTAPD_SECURITY_WPA2PSK;
    }
    else if (!strcmp(puc_encipher_mode, "wpa+wpa2"))
    {
        g_hapd_conf.authmode = HOSTAPD_SECURITY_WPAPSK_WPA2PSK_MIX;
    }
    else
    {
       	cmd_connect_ap_help();
        return;
    }

    if (g_hapd_conf.authmode != HOSTAPD_SECURITY_OPEN)
    {   
    	if (argc != 5)
	    {
	       	cmd_connect_ap_help();
	        return;
	    }
        strcpy((char *)g_hapd_conf.key, argv[4]);
    }

    if (HOSTAPD_SECURITY_WPAPSK == g_hapd_conf.authmode ||
        HOSTAPD_SECURITY_WPA2PSK == g_hapd_conf.authmode ||
        HOSTAPD_SECURITY_WPAPSK_WPA2PSK_MIX == g_hapd_conf.authmode)
    {
        puc_encipher_mode = argv[3];
        if (!strcmp(puc_encipher_mode, "tkip"))
        {
            g_hapd_conf.wpa_pairwise = WPA_CIPHER_TKIP;
        }
        else if (!strcmp(puc_encipher_mode, "aes"))
        {
            g_hapd_conf.wpa_pairwise = WPA_CIPHER_CCMP;
        }
        else if (!strcmp(puc_encipher_mode, "tkip+aes"))
        {
            g_hapd_conf.wpa_pairwise = WPA_CIPHER_TKIP | WPA_CIPHER_CCMP;
        }
        else
        {
            cmd_connect_ap_help();
            return;
        }
    }

    /* 重新设置netif的网关和mac地址，防止STA切AP时，没有还原 */
    netif_set_addr(pst_lwip_netif, &st_ipaddr, &st_netmask, &st_gw);
/*
	printf("g_hapd_conf.channel_num 		=%d\n", g_hapd_conf.channel_num);
	printf("g_hapd_conf.ssid 		=%s\n", g_hapd_conf.ssid);
	printf("g_hapd_conf.ignore_broadcast_ssid 		=%d\n", g_hapd_conf.ignore_broadcast_ssid);
	printf("g_hapd_conf.ht_capab 		=%s\n", g_hapd_conf.ht_capab);
	printf("g_hapd_conf.authmode 		=%d\n", g_hapd_conf.authmode);
	printf("g_hapd_conf.wpa_pairwise 		=%d\n", g_hapd_conf.wpa_pairwise);
	printf("g_hapd_conf.key 		=%s\n", g_hapd_conf.key);

*/	

    if (0 != hostapd_start(HISI_NULL, &g_hapd_conf))
    {
        printf("hostapd start failed\n");
        return;
    }

    printf("hostapd start succ\n");
	Mux_Operate(&g_hostapd_had_run, 1);
	

    
    return;
}


static void cmd_led_test(int argc, char *argv[])
{
	unsigned char ledsta[6] = {0};
	int i = 0;

	if(argc < 6)
	{
		printf("the argc is error.please led_test 33 33 33 33 33 33...\n");
		return;
	}
	
	for(i = 0; i <6; i++)
	{
		sscanf(argv[i],"%hhd",&ledsta[i]);
		
	}

	printf("the ledsta is  :H[%x %x %x %x %x %x]\n", ledsta[0], ledsta[1], ledsta[2], ledsta[3], ledsta[4], ledsta[5]);
	printf("the ledsta is  :D[%d %d %d %d %d %d]\n", ledsta[0], ledsta[1], ledsta[2], ledsta[3], ledsta[4], ledsta[5]);
	if((argc == 7) && (atoi(argv[6]) == 1))
	{
		HI_HAL_MCUHOST_LedState_Control(ledsta);
	}

	return;

}


void cmd_pir_test(int argc, char *argv[])
{
	
	if(argc != 2)
	{
		printf("Invalid parameter\n"
			  	"Example:\n"
			  	"pir_test [period time] [check time]\n");
		return;
	}

	bool whether = 0;
	unsigned char check_time = 0;
	whether = atoi(argv[0]);
	check_time = atoi(argv[1]);
	Host_Wake_PirSet(whether, check_time);

	return;
}

void cmd_sleep(void)
{
	int uwRet = 0;
	char sleep_ssid[32] = {0};
	char wlan_flag[2] = {0};
	
	wap_start_xm();

	XmSuspendByWlan("cmd_sleep suspend");
	
	return;
}

void cmd_arp(int argc, char *argv[])
{
	
	int i = 0;
	int num = 0;

	char buf[64] = {0};

	char filename[] = "/jffs1/mnt/mtd/Config/arp_addr.conf";
	ArpAddr_s arpaddr;

	char addr_hdr[6][24] ={"src_mac_hdr=", "dst_mac_hdr=", "src_mac=",  "src_ip=" , "dst_mac=","dst_ip="};
	char addr_val[6][64] = {0};
	

	memset(&arpaddr, 0, sizeof(arpaddr));

	for(i = 0; i < 6; i++)
	{
		Get_File_Value(filename, addr_hdr[i], addr_val[i]);
		if((argc == 3) && (atoi(argv[2]) == 1))
		{
			printf("the %s	%s\n", addr_hdr[i], addr_val[i]);
		}
		

		if(strlen(addr_val[i]) > 0)
		{
			switch(i)
			{
				case 0:
					sscanf(addr_val[0],"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&arpaddr.src_mac_hdr[0],&arpaddr.src_mac_hdr[1],&arpaddr.src_mac_hdr[2],
												&arpaddr.src_mac_hdr[3], &arpaddr.src_mac_hdr[4], &arpaddr.src_mac_hdr[5]);
					break;
				case 1:
					sscanf(addr_val[1],"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&arpaddr.dst_mac_hdr[0],&arpaddr.dst_mac_hdr[1],&arpaddr.dst_mac_hdr[2],
												&arpaddr.dst_mac_hdr[3], &arpaddr.dst_mac_hdr[4], &arpaddr.dst_mac_hdr[5]);
					break;
				case 2:
					sscanf(addr_val[2],"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&arpaddr.src_mac[0],&arpaddr.src_mac[1],&arpaddr.src_mac[2],
												&arpaddr.src_mac[3], &arpaddr.src_mac[4], &arpaddr.src_mac[5]);
					break;

				case 3:
					memcpy(arpaddr.src_ip, addr_val[3], strlen(addr_val[3]));
					//sscanf(addr_val[3],"%hhx.%hhx.%hhx.%hhx",&arpaddr.src_ip[0],&arpaddr.src_ip[1],&arpaddr.src_ip[2],&arpaddr.src_ip[3]);
					break;
				case 4:
					sscanf(addr_val[4],"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&arpaddr.dst_mac[0],&arpaddr.dst_mac[1],&arpaddr.dst_mac[2],
												&arpaddr.dst_mac[3], &arpaddr.dst_mac[4], &arpaddr.dst_mac[5]);
					break;
				case 5:
					memcpy(arpaddr.dst_ip, addr_val[5], strlen(addr_val[5]));
					//sscanf(addr_val[5],"%hhx.%hhx.%hhx.%hhx",&arpaddr.dst_ip[0],&arpaddr.dst_ip[1],&arpaddr.dst_ip[2],&arpaddr.dst_ip[3]);
					break;

			}

		}
	}	
	
	num = atoi(argv[1]);
	//printf("the num is %d\n", num);
	
	for(i = 0; i< num; i++)
	{
		if((argc == 3) && (atoi(argv[2]) == 1))
		{
			send_Gratuitous_Arps_test(atoi(argv[0]), &arpaddr, atoi(argv[2]));
		}
		else
		{
			send_Gratuitous_Arps_test(atoi(argv[0]), &arpaddr, 0);
		}
		
		usleep(1000*1000);
	}

	return;
}

int cmd_sed(int argc, char *argv[])
{
	
    FILE *fpSrc = NULL,*fpDes = NULL;  
	char *p = NULL;
	
    char filename1[128]={0};  
    char filename2[64]="/jffs1/mnt/mtd/Config/copy.conf";  
	
    //要求查找的字符串，替换的字符串；  
    char ps[128]={0};  
    char pd[128]={0};  
	
   
	
   
    char Src_buf[128] = {0};  
  	char Des_buf[128] = {0};  

	int ret = 0;

	if(argc != 3)
	{
		printf("the argc should 3..\n");
		return -1;
	}

	memcpy(filename1, argv[0], strlen(argv[0]) +1);
	memcpy(ps, argv[1], strlen(argv[1]) +1);	
	memcpy(pd, argv[2], strlen(argv[2]) +1);

	 //求取所查找和替换的字符串的长度；  
    int len_src=strlen(ps);  
    int len_des=strlen(pd);  

	printf("the file is:	%s\n", filename1);

	printf("the ps is:	%s	<%d>\n", ps, len_src);
	printf("the pd is:	%s	<%d>\n", pd, len_des);
	

	
        //打开文件  
    if((fpSrc=fopen(filename1,"r"))==NULL)  
    {  
        printf("fail to open the file1 !\n");  
       return -1;   
    }  
    if((fpDes=fopen(filename2,"w+"))==NULL)  
    {  
        printf("fail to open the file2 !\n");  
        return -1;  
    }  
    //进行循环读取  

	while(fgets(Src_buf,128,fpSrc) != NULL)
	{
		printf("****************************************\n");
		//printf("the src_buf is:		%s\n", Src_buf);

		memset(Des_buf, 0, sizeof(Des_buf));

		p = strstr(Src_buf, ps);  
		if(p != NULL)
		{
			printf("find..\n");		
			
			memcpy(Des_buf, ps, strlen(ps));
			printf("the des buf is:	%s\n", Des_buf);
			
		
			strcpy(Des_buf + strlen(ps), pd);
			Des_buf[len_src + len_des] = '\n';
			printf("the des buf is:	%s\n", Des_buf);

			// 跳过被替换串.  
			//pi = p + nSrcLen;  
			// 调整指向输出串的指针位置.  
			//po = po + nLen + nDstLen;  
			// 继续查找.  
			//p = strstr(pi, pSrc);  		
			// 复制剩余字符串.  
			//strcpy(po, pi);  
			
		}
		else
		{
			printf("not find..\n");
			strcpy(Des_buf, Src_buf);
		}

		//printf("the src_buf is:		%s\n", Src_buf);
		printf("the des_buf is:	%s\n", Des_buf);
		
		fputs(Des_buf,fpDes); 
	}

	

    fclose(fpSrc);  
	
    fclose(fpDes);  

	
        //打开文件  
    if((fpSrc=fopen(filename1,"w"))==NULL)  
    {  
        printf("fail to open the file1 !\n");  
       return -1;   
    }  
    if((fpDes=fopen(filename2,"r"))==NULL)  
    {  
        printf("fail to open the file2 !\n");  
        return -1;  
    }  

	int ch;
	while((ch = fgetc(fpDes)) != -1)
	{
		fputc(ch, fpSrc);
	}

	
	fclose(fpSrc);	
	  
	fclose(fpDes);  

	remove(filename2);

	return 0;
}

int cmd_bat_show(void)
{
	int ret = 0;
	int chgstate = 0;
	unsigned char chgvalue = 0;
	
	HI_HAL_MCUHOST_Power_Poll();

	//chgstate = g_chg_state;
	if(chgstate >= 2)
	{
		chgstate = 2;
	}
	printf("the chg state is %x\n", chgstate );

	

	ret = XmBatShow(&chgvalue, chgstate);
	if(ret != 0)
	{
		printf("get chg value error\n");
		return -1;
	}

	printf("the chg value is %d\n", chgvalue);
	
	return 0;
}


void cmd_set_wake_flag(int argc , char *argv[])
{
	int i = 0;
	g_wake_event = 0;

	if(argc != 9)
	{
		printf("the argc error, must be <10>\n");
		return;
	}
	for(i = 0; i < 10; i++)
	{
		if(atoi(argv[i]))
		{
			printf("%d..\n", i);	
			switch(i)
			{
			
				case 0:
					g_wake_event |=HISI_WOW_EVENT_MAGIC_PACKET; 			///* Wakeup on Magic Packet */
					break;
				case 1:
					g_wake_event |=HISI_WOW_EVENT_NETPATTERN_TCP;			///* Wakeup on TCP NetPattern */
					break;			
				case 2:
					g_wake_event |=HISI_WOW_EVENT_NETPATTERN_UDP;			//* Wakeup on UDP NetPattern */
					break;
				case 3:
					g_wake_event |=HISI_WOW_EVENT_DISASSOC; 				///* 去关联/去认证，Wakeup on Disassociation/Deauth */
					break;
				case 4:
					g_wake_event |=HISI_WOW_EVENT_AUTH_RX;					///* 对端关联请求，Wakeup on auth */
					break;
				case 5:
					g_wake_event |=HISI_WOW_EVENT_HOST_WAKEUP;			///* Host wakeup */
					break;
				case 6:
					g_wake_event |=HISI_WOW_EVENT_TCP_UDP_KEEP_ALIVE;		///* Wakeup on TCP/UDP keep alive timeout */
					break;
				case 7:
					g_wake_event |=HISI_WOW_EVENT_OAM_LOG_WAKEUP;			///* OAM LOG wakeup */
					break;
				case 8:
					g_wake_event |=HISI_WOW_EVENT_SSID_WAKEUP;				///* SSID Scan wakeup */
					break;
					
			}			
	
			printf("the g_wake_event is[0000%02x%02x]\n", (g_wake_event >> 8),(g_wake_event & 0xff));		

			

		}
		

	}	

	
	printf("the g_wake_event is %d\n", g_wake_event);
	hisi_wlan_set_wow_event(g_wake_event);

	return;
}

void cmd_search_wifi(void)
{
	int uwRet = 0, num = 0;
	int times = 0;
	unsigned char ssid[33] = {0};
	
	//char *WifiPrefix[2] = {NVR_WIFI_SSID_PREFIX, BRG_WIFI_SSID_PREFIX};
	char *WifiPrefix[2] = {"zhaozuoen", "zuoen"};

	struct wpa_ap_info *pwifi_result = NULL;
	pwifi_result = malloc(sizeof(struct wpa_ap_info) * 60);

	if(NULL == pwifi_result)
	{
		printf("malloc wpa_ap_info error \n");
		return ;
	}

	memset(pwifi_result, 0, (sizeof(struct wpa_ap_info) * 60));

	wap_start_xm();

	
	
	uwRet = Search_Wifi(pwifi_result, &num, WifiPrefix);

	if(uwRet && (num == 0))
	{
		
		while((uwRet != 1) && (times < 1))
		{
			memset(pwifi_result, 0, (sizeof(struct wpa_ap_info) * 60));
			printf("search wifi can not find nvr or brg.try again......\n");
			uwRet = Search_Wifi(pwifi_result, &num, WifiPrefix);
			times++;
		}
	}

	if(times >= 1)
	{
		free(pwifi_result);
		XmSuspendByWlan("cmd_wifiscan suspend");
	}

	free(pwifi_result);



	return;
}



void cmd_rtc_wake_up(int argc, char *argv[])
{
	int uwRet = 0;
	int times = atoi(argv[0]);
	
	

	if((g_ul_xm_wlan_resume_state == 0) &&( g_wpa_supplicant_had_run != 1))
	{
		uwRet = wpa_supplicant_start("wlan0", "hisi", NULL);
		if(0 != uwRet)
		{
			printf("fail to start wpa_supplicant\n");
		}
		Mux_Operate(&g_wpa_supplicant_had_run, 1);
		
		hisi_wlan_enable_channel_14();
	}
	
	Host_Wake_RtcSet(times);

	return;
}




void cmd_mcu_time(void)
{
	
	unsigned char buf[6] = {0};
	int i = 0;
	
	HI_HAL_MCUHOST_Systemtime_Get();
	usleep(1000*1000);


	
	
	return;
}

void cmd_wpa_start(void)
{
	wap_start_xm();


	return;
}

void cmd_country_set(void)
{
	int ret = 0;
	unsigned char *countryname = NULL;
	unsigned char country[6] = {0};

	countryname = hisi_wlan_get_country();
	memcpy(country, countryname, 6);
	printf("the country is :	%s\n", country);

	memset(&country, 0, 6);
	strcpy(country, "JP");
	printf("the country is :	%s\n", country);
	ret = hisi_wlan_set_country(country);
	if(ret == 0)
	{
		printf("set country success..\n");

	}

	return;
}






void cmd_qr_test(void)
{
	int i = 0;

	hicap_capture_start();

	while(1)
	{		
		if(g_QrBarcodeState.barState)
		{
			g_QrBarcodeState.barState = 0;
			printf("the qrdate is [%s]\n", g_QrBarcodeState.barResult);
			
			i ++;
			if(i > 8)
			{
				hicap_capture_stop();
				break;
			}		
		}
		usleep(1000*1000);
	}

	
	return;

}

void cmd_qr_test1(void)
{

	int ret = 0;
	char *addr = NULL;
	int fp = -1;
	char filename[50] = "/mnt/sd0/frame.yuv";

	

	char buf[50] = {0};
	addr=malloc(FRAME_WIDTH*FRAME_HEIGHT*sizeof(char));

	if ((fp = open(filename, O_RDWR)) < 0)
	{
		printf("open file error.\n");

		return;
	}

	ret = read(fp, addr, FRAME_HEIGHT*FRAME_WIDTH);

	if(ret == 0)
	{
		printf("read error\n");
		close(fp);
		free(addr);
		return ;
	}
	
	
	ret = xmYuvCallBack1(0, addr, FRAME_WIDTH*FRAME_WIDTH);
	

	close(fp);
	free(addr);

	

	return;

}




void WifiCmdReg(void)
{
	osCmdReg(CMD_TYPE_EX, "set_addr",           0, 	(CMD_CBK_FUNC)cmd_set_attr_xm);
	osCmdReg(CMD_TYPE_EX, "get_addr",         	0,	(CMD_CBK_FUNC)cmd_get_attr_xm);
	osCmdReg(CMD_TYPE_EX, "nvr_connect",     	0, 	(CMD_CBK_FUNC)cmd_nvr_connect_xm);
	osCmdReg(CMD_TYPE_EX, "socket_test",       	0, 	(CMD_CBK_FUNC)cmd_sock_test_xm);
	osCmdReg(CMD_TYPE_EX, "arp_test",           0, 	(CMD_CBK_FUNC)cmd_arp_test_xm);	
	osCmdReg(CMD_TYPE_EX, "get_station",       	0, 	(CMD_CBK_FUNC)cmd_get_station_xm);
	osCmdReg(CMD_TYPE_EX, "connect_ap",       	0, 	(CMD_CBK_FUNC)cmd_hapd_connect_xm);	
	osCmdReg(CMD_TYPE_EX, "connect_wpa",  		0, 	(CMD_CBK_FUNC)cmd_wpa_connect_xm);
	osCmdReg(CMD_TYPE_EX, "rssi_zero",  		0, 	(CMD_CBK_FUNC)wpa_disconnect_xm);	
	osCmdReg(CMD_TYPE_EX, "led_test",  			0, 	(CMD_CBK_FUNC)cmd_led_test);
	osCmdReg(CMD_TYPE_EX, "pir_test",  			0, 	(CMD_CBK_FUNC)cmd_pir_test);
	osCmdReg(CMD_TYPE_EX, "sleep",  			0, 	(CMD_CBK_FUNC)cmd_sleep);
	osCmdReg(CMD_TYPE_EX, "arp_send",  			0, 	(CMD_CBK_FUNC)cmd_arp);
	osCmdReg(CMD_TYPE_EX, "sed",  				0, 	(CMD_CBK_FUNC)cmd_sed);
	osCmdReg(CMD_TYPE_EX, "bat_show",  			0, 	(CMD_CBK_FUNC)cmd_bat_show);
	osCmdReg(CMD_TYPE_EX, "wake_event",  		0, 	(CMD_CBK_FUNC)cmd_set_wake_flag);
	osCmdReg(CMD_TYPE_EX, "wifiscan",  			0, 	(CMD_CBK_FUNC)cmd_search_wifi);	
	osCmdReg(CMD_TYPE_EX, "rtc_set",  			0, 	(CMD_CBK_FUNC)cmd_rtc_wake_up);	
	osCmdReg(CMD_TYPE_EX, "mcu_time",  			0, 	(CMD_CBK_FUNC)cmd_mcu_time);
	osCmdReg(CMD_TYPE_EX, "wpa_start",  		0, 	(CMD_CBK_FUNC)cmd_wpa_start);
	osCmdReg(CMD_TYPE_EX, "country_set",  		0, 	(CMD_CBK_FUNC)cmd_country_set);
	//osCmdReg(CMD_TYPE_EX, "qr_test",  			0, 	(CMD_CBK_FUNC)cmd_qr_test);
	//osCmdReg(CMD_TYPE_EX, "qr_test1",  			0, 	(CMD_CBK_FUNC)cmd_qr_test1);
	
	
}






























