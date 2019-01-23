#include "driver_hisi_lib_api.h"
#include "wpa_supplicant.h"

#include "malloc.h"
#include "string.h"
#include "strings.h"

#include "asm-generic/errno.h"
#include "asm/io.h"



#include"unistd.h"

#include "stdlib.h"
#include "stdio.h"

#include "lwip/netif.h"
#include "shell.h"
#include "linux/completion.h"

#include "xmextlib.h"
#include "xmconnect.h"
#include "xmnet.h"
#include "xmcmd.h"

#define 	FACTORY_SSID 				"XmBarcodeSign"
#define		NVR_WIFI_SSID_PREFIX 		"WIFINVR"
#define		BRG_WIFI_SSID_PREFIX		"WIFIBRG"
#define	 	NVR_WIFI_PASSWD				"XMNVR123456"
#define 	NVR_IP_ADDR					"172.25.123.92"
#define 	PORT 						9988

//#define NVR_IP_ADDR "192.168.10.1"

#define IPC_INFO_ENABLE_FLAG 		"/jffs1/mnt/mtd/Config/heartbeat_info"
#define FORCE_CONNECT_FLAG 			"/jffs1/mnt/mtd/Config/FORCE_FLAG"
#define CONNNECTED_NVR_CONF 		"/jffs1/mnt/mtd/Config/last.conf"
#define CONNNECTED_SLEEP_FLAG 		"/jffs1/mnt/mtd/Config/sleep.conf"
#define SPI_INFO 					"/jffs1/mnt/mtd/Config/spi.txt"
#define BRIDGE_SIGNAL_LEVEL_FNAME    "jffs1/mnt/mtd/Config/bridge_singal_level" 

#define MIN_PAIRING_SIGNAL_LEVEL 				60
#define SWITCH_TO_BRIDGE_STRONG_SIGNAL_LEVEL	80
#define SWITCH_TO_BRIDGE_MIDDLE_SIGNAL_LEVEL	70
#define SWITCH_TO_BRIDGE_WEAK_SIGNAL_LEVEL		60

#define SCAN_AP_LIMIT 				64
#define SYS_CTRL_REG_BASE_XM		0x20050000

unsigned int g_wake_event = 0;					//唤醒条件使能事件集合     	默认[000001DF]
unsigned int g_before_sleep_wlan_flag = 0;			//0:唤醒睡眠前没有配上网，1：唤醒睡眠前已经配上网
unsigned int g_variable_mux = 0;					//变量赋值互斥量
unsigned int g_function_mux = 0;					//程序段执行互斥量
unsigned int g_wakup_reason = 0;					//主控唤醒的原因
unsigned int g_hostapd_had_run = 0;					//0：hostapd没有运行		1：hostapd已经运行
unsigned int g_wpa_supplicant_had_run = 0;			//0：wpa_supplicant没有运行	1：wpa_supplicant已经运行
unsigned int g_wpa_supplicant_had_sock = 0;			//0：没有成功连接sock		1：已经连接成功sock



int g_sockfd[4] = {0}; 								//记录tcp连接的socket描述符
unsigned char g_keepalive_switch = 0;               //保活开关
unsigned char g_index = 0; 							//已经创建的tcp链数（本项目只用一个tcp链）

int g_heartime = 0;									//socket交互成功用时





//外部库全局变量引用
extern unsigned int g_ul_xm_wlan_resume_state;		//系统启动标志 								libdvr/net.c定义
extern unsigned int g_force_sleep_flag;				//十分钟强制关闭标志,该标志置1说明要主控睡眠				hi_ext_hal_mcu.c定义
extern unsigned int g_wpa_supplicant_had_connect;	//无线模块作为客户端，是否连接上热点并且获得ip				libdvr/net.c定义


extern struct completion  g_dhcp_complet;			//完成量变量：等待ip获取成功		app_init.c 定义






void RebootSystem(void)
{
	printf("\n**************************************************************************\n");
	printf("******************cannot connect ssid,begin to reboot system**********************\n");
	usleep(1000*50);
	sync();
	writel(0xffffffff, (SYS_CTRL_REG_BASE_XM + 0x4));
	
}



int XmConvertdBm2RSSI(int dBm)
{
	int level = 0;

	if (dBm < 0 && dBm >= -40)
	{
		level = 100;
	}
	else if (dBm <-40 && dBm >= -50)
	{
		level = (dBm+90)*2;
	}
	else if (dBm < -50 && dBm >= -80)
	{
		level = dBm + 129;
	}
	else if (dBm < -80 && dBm > -100)
	{
		level = (dBm + 100) * 2;
	}
	else if(dBm <= -100)
	{
		level = 0;
	}

	return level;
}

int LevelSort(struct wpa_ap_info * wifiinfo, int num)
{
	if (!wifiinfo)
		return -1;

	struct wpa_ap_info wifitmp;
	int i, j;

	if (wifiinfo[0].rssi < 0)	//如果驱动里读出来是负的，需要转换为0~100
	{
		for (i=0; i<num; i++)
		{
			wifiinfo[i].rssi = (XmConvertdBm2RSSI(wifiinfo[i].rssi/100))*100;
		}
	}

	for (i=0; i<num; i++)
	{
		for (j=0; i+j<num-1; j++)
		{
			if ((wifiinfo[j].rssi/100) < (wifiinfo[j+1].rssi/100))
			{
				wifitmp = wifiinfo[j];
				wifiinfo[j] = wifiinfo[j+1];
				wifiinfo[j+1] = wifitmp;
			}
		}
	}

	return 0;
}


static void wpa_scan_results(struct wpa_ap_info *pwlan_scan_result, int *pResultNum, char **keys)
{

	
	struct wpa_ap_info *pst_results = HISI_NULL;
	
	unsigned int   num = SCAN_AP_LIMIT ;
	unsigned int   ul_loop;
	unsigned int ul_result = 0;
	unsigned int keyNum = 2;
	

	pst_results = malloc(sizeof(struct wpa_ap_info) * SCAN_AP_LIMIT);

	if(HISI_NULL == pst_results)
	{
		printf("wpa_scan_results, OAL_PTR_NULL == pst_results\n");
		
		return;
	}

	memset(pst_results, 0, (sizeof(struct wpa_ap_info) * SCAN_AP_LIMIT));
	wpa_cli_scan_results(pst_results,&num);
	printf("\n**********************search***********************\n");
	printf("scan results number is %d.\n", num);


	for (ul_loop = 0; (ul_loop < num) && (ul_loop < SCAN_AP_LIMIT); ul_loop++)
	{
		printf("num:%d	",ul_loop);	
		if(strlen(pst_results[ul_loop].ssid) < 33)
		{
			printf("ssid:%-32s",pst_results[ul_loop].ssid);
		}

		else
		{
			printf("ssid:[can not recognizable]\n");
			continue;
		}
				
		printf("bssid:%s	",pst_results[ul_loop].bssid);		
		printf("channel:%d	",pst_results[ul_loop].channel);		
		printf("rssi:%d	",pst_results[ul_loop].rssi/100);
		
		switch(pst_results[ul_loop].auth)
		{
			case WPA_SECURITY_OPEN:
				printf("auth type: open\n");			
				break;
			case WPA_SECURITY_WEP:
				printf("auth type: wep\n");				
				break;
			case WPA_SECURITY_WPAPSK:
				printf("auth type: wpa\n");			
				break;
			case WPA_SECURITY_WPA2PSK:
				printf("auth type: wpa2\n");				
				break;
			case WPA_SECURITY_WPAPSK_WPA2PSK_MIX:
				printf("auth type: wpa+wpa2\n");				
				break;
			default:
				printf("auth type error\n");				
				break;
		}

		bool IsSsidMatched = FALSE;
		int k = 0;
		for (k = 0; k < keyNum; k++)
		{
			if (memcmp(pst_results[ul_loop].ssid, keys[k], strlen(keys[k])) == 0)
			{
				IsSsidMatched = TRUE;
				break;
			}
		}		
		
		if (IsSsidMatched)
		{
			
			memcpy(pwlan_scan_result[ul_result].ssid, pst_results[ul_loop].ssid, 33);
			memcpy(pwlan_scan_result[ul_result].bssid, pst_results[ul_loop].bssid, 18);
			pwlan_scan_result[ul_result].channel = pst_results[ul_loop].channel;
			pwlan_scan_result[ul_result].rssi = pst_results[ul_loop].rssi;
			pwlan_scan_result[ul_result].auth = pst_results[ul_loop].auth;			
			
			ul_result++;
		}

		memset(&g_QrBarcodeState, 0, sizeof(g_QrBarcodeState));
		if( g_QrBarcodeState.barSwitch == START_BAR_OFF && !memcmp(pst_results[ul_loop].ssid,FACTORY_SSID,strlen(FACTORY_SSID)) && pst_results[ul_loop].rssi> -60*100)
		{
			char ledstate[6] = {0};
			g_QrBarcodeState.barSwitch = START_BAR_ON;
			printf("\033[33mstart barcode\033[0m\n");
			ledstate[0] = 1;
			ledstate[3] = 1;
			HI_HAL_MCUHOST_LedState_Control(ledstate);
			
			pthread_exit(NULL);
		}
		
	}

	*pResultNum  = ul_result;
	
	free(pst_results);
	pst_results = HISI_NULL;
}


int Search_Wifi(struct wpa_ap_info *pwifi_scan, int *pResultNum, char **keys)
{
	unsigned int i, j;
	unsigned int num = 0, num1 = 0;
	int searched =-1;
	unsigned int uwRet = 0;
	struct wpa_ap_info *pwlan_scan_result = NULL;
	
	
	//开始搜索附近热点	

	printf("******begin to search %s	%s.\n", keys[0], keys[1]);
	
	pwlan_scan_result = malloc(sizeof(struct wpa_ap_info) * SCAN_AP_LIMIT);

	if(NULL == pwlan_scan_result)
	{
		printf("malloc wpa_ap_info error \n");
		return -1;
	}

	memset(pwlan_scan_result, 0, (sizeof(struct wpa_ap_info) * SCAN_AP_LIMIT));
	uwRet = wpa_cli_scan();
	if(uwRet != 0)
	{
		printf("\n******wpa_cli_scan error*****\n");
		free(pwlan_scan_result);
		pwlan_scan_result = HISI_NULL;

		return -1;
	}	

	usleep(1000*1000);

	
	wpa_scan_results(pwlan_scan_result, &num, keys );
	
	printf("the num is %d.\n", num);
	if (num <= 0)
	{
		printf("Can't find WIFINVR\n");
		free(pwlan_scan_result);
		pwlan_scan_result = HISI_NULL;

		return -1;
	}	

	for (i=0; i<num; i++)
	{
		memcpy(pwifi_scan[i].ssid, pwlan_scan_result[i].ssid, 33);
		memcpy(pwifi_scan[i].bssid, pwlan_scan_result[i].bssid, 18);
		pwifi_scan[i].channel = pwlan_scan_result[i].channel;
		pwifi_scan[i].rssi = pwlan_scan_result[i].rssi;
		pwifi_scan[i].auth = pwlan_scan_result[i].auth;	

		searched = 1;
		
	}

	LevelSort(pwifi_scan, num);	

	printf("\n\n*************************************\n");
	for (i=0; i<num; i++)
	{
		if (pwifi_scan[i].ssid[0])
		{
			if(strlen(pwifi_scan[i].ssid) < 33)
			{
				printf("ssid:%-32s",pwifi_scan[i].ssid);
			}
			else
			{
				continue;
			}
			printf("channel:%d	",pwifi_scan[i].channel);		
			printf("level:%d\n",pwifi_scan[i].rssi/100);
			
		}
		else
		{
			num = i+1;
			break;
		}
	}
	printf("*************************************\n\n");

	*pResultNum = num;

	free(pwlan_scan_result);
	pwlan_scan_result = HISI_NULL;	

	return searched;

}



int XmEthNameValid(const char *pEthName)
{
	if (pEthName == NULL)
	{
		printf("pEthName == NULL!\n");
		return -1;
	}
	if (memcmp("wlan0", pEthName, 5) == 0)
	{
		return 0;
	}
	
	else
	{
		printf("Not Support Device %s\n", pEthName);
		return -1;
	}

	return 0;
	
}



int GetLevel(int *ipclevel, int * txratelevel)
{
	struct station_info st_sta ;

	memset(&st_sta, 0, sizeof(st_sta));
	
	if (HISI_SUCC != hisi_wlan_get_station(&st_sta))
	{
		printf("get station info fail!");
		return -1;
	}

	if(g_wpa_supplicant_had_connect != 1)
	{
		*ipclevel = 0;
		*txratelevel = 0;
		//printf("the g_wpa_supplicant_had_connect is <%d>\n", g_wpa_supplicant_had_connect);
	}
	else
	{
		*ipclevel = st_sta.l_signal;
		*txratelevel = st_sta.l_txrate;
	}	

	return 0;
}


int GetWifiLevel(char * ifname)
{
	//char strval[128] = {'\0'};
	int ipcLevel = 0;
	int txrateLevel = 0;
	int bridgeLevel = 100;
	int ret = 0;

	ret = GetLevel(&ipcLevel, &txrateLevel);
	if(ret <0)
	{
		printf("get level error.!\n");
	}
	

	if (ipcLevel < 0)	//如果驱动里读出来是负的，需要转换为0~100
	{	
		ipcLevel = (XmConvertdBm2RSSI(ipcLevel));		
	}

	//如果通过中继设备连接NVR，而且中继距离NVR比较远，信号比较弱时，IPC的码率调整应该基于中继的信号强度，防止码率过大出现卡顿
	
	if (access(BRIDGE_SIGNAL_LEVEL_FNAME, F_OK) == 0)
	{
		char buffer[128] = {0};

		FileSimpleRead(BRIDGE_SIGNAL_LEVEL_FNAME, buffer, 128);
		bridgeLevel = atoi(buffer);
		
	}
	ipcLevel = ipcLevel < bridgeLevel ? ipcLevel : bridgeLevel ;

	return ipcLevel;
}


int ConnectNvrSocket(char *NvrIpaddr)
{
	int sockfd = -1;
	struct sockaddr_in serv_addr;
	struct sockaddr_in client_addr;
	char ipBuf[0x20]={0},netmaskBuf[0x20]={0};
   	char macBuf[40] = {0};
	
	int on = 1;
	struct  timeval tv;
	fd_set rfds, wfds;
	int ret = 0;
	int selected = 0, nums = 2;
	int connected = -1;
	int i = 0, err = 0;	

	

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		printf("opening socket error:%s\n", strerror(errno));
		goto __RET;
	}
	printf("the sockfd is %d.\n", sockfd);
	
	if((XmGetEthAttr("wlan0", IP_ADDR, ipBuf) == 0) && (memcmp(&ipBuf[0], "0", 1) != 0) )
	{
		client_addr.sin_addr.s_addr = inet_addr(ipBuf);

	}
	
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(0);

	if ((setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))<0)
	{
		close(sockfd);
		sockfd = -1;
		goto __RET;
	}

	if (bind(sockfd, (struct sockaddr *)&client_addr, sizeof(struct sockaddr)) == -1)
	{
		printf("bind error.\n");
		close(sockfd);
		sockfd = -1;
		goto __RET;
	}

	tv.tv_sec = 4;
	tv.tv_usec = 0;
	if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
	{
		printf("setopt SO_RCVTIMEO error.the error is %d	%s.\n", errno, strerror(errno));
		close(sockfd);
		sockfd = -1;
		goto __RET;
	}	

	bzero(&serv_addr, sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);
	serv_addr.sin_addr.s_addr = inet_addr(NvrIpaddr);

	unsigned long ul = 1;
	ioctl(sockfd, FIONBIO, &ul); //设置为非阻塞模式
	printf("Waiting for socket to be connected...\n");
	ret = connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
	
	err = errno;
	if ( ret < 0)
	{
		if (err == EINPROGRESS)
		{
			
			int times = 0;
			while(times++ < 4)
			{
				//printf("Connect timeout, waiting: %d, %s\n",err, strerror(err));
				tv.tv_sec = 4;
				tv.tv_usec = 0;

				FD_ZERO(&rfds);			
				FD_ZERO(&wfds);	
				usleep(1000*50);
				FD_SET(sockfd, &rfds);
				FD_SET(sockfd, &wfds);

				selected = select(sockfd+1, &rfds, &wfds, NULL, &tv);

				if (selected > 0)
				{
					
					if (FD_ISSET(sockfd, &rfds) || FD_ISSET(sockfd, &wfds))  
					{  
						//printf("\nFD_ISSET(sockfd, &rfds): %d\nFD_ISSET(sockfd, &wfds): %d\n", FD_ISSET(sockfd, &rfds) , FD_ISSET(sockfd, &wfds));  
						connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in));  
						
						err = errno;  
						if  (err == EISCONN)  
						{  
							printf("Connect succeed, the sockfd is  %d\n", sockfd);  
							connected = 0;
							break;
							
						}  
						else  
						{  
							printf("Connect failed<%d>!%s\n", err, strerror(err));
							connected = -1;
							continue;
							
						}  

					}  
								
					
				}
				else if(selected == 0)
				{
					 printf("select time out\n"); 
					 connected = -1;
					 continue;
					 
				}
				else
				{
					printf("Connect failed!%s\n", strerror(errno));
					connected = -1;
					continue;
					
				}

			}
			

			if(connected != 0)
			{				
				close(sockfd);
				sockfd = -1;
				goto __RET;
			}
			
		
		}
		else
		{
			printf("the errno is %d.\n", errno);
			printf("Connect failed!%s\n", strerror(errno));
			close(sockfd);
			sockfd = -1;
			goto __RET;
		}

	}

__RET:
	
	if(sockfd > 0)
	{
		Mux_Operate_Lock();
		g_wpa_supplicant_had_sock = 1;
		g_index = 1;
		g_sockfd[0] = sockfd;
		Mux_Operate_Unlock();
	}
	else
	{
		Mux_Operate_Lock();
		g_wpa_supplicant_had_sock = 0;
		g_index = 0;
		g_sockfd[0] = sockfd;
		Mux_Operate_Unlock();
	}
	g_IpcRuningData.DeamonSocketFd = sockfd;
		
	return sockfd;
}



int CloseNvrSocket(int *pSockFd)
{
	if (*pSockFd < 0)
	{
		printf("Invalid socketFd: %d\n", *pSockFd);
		return -1;
	}
	close(*pSockFd);
	*pSockFd = -1;
	g_IpcRuningData.DeamonSocketFd = -1;
	return 0;
}



int PairingWithNVR(void)
{
	int sockfd;
	int ret = 0, recived = 0;
	unsigned char buffer[128];
	char 	HwAddr[12] = {0};
	fd_set rfds, wfds;
	struct  timeval tv1;

	printf("\n-------------fist pairing with nvr-----------------\n");	

	sockfd = ConnectNvrSocket(NVR_IP_ADDR);
	
	if (sockfd < 0)
	{
		printf("ConnectNvrSocket failed\n");
		goto __RET;
	}

	printf("the return sockfd is %d.\n", sockfd);	

	memset(buffer, 0, sizeof(buffer));

	if( XmGetEthAttr("wlan0", HW_ADDR, HwAddr) != 0)
	{
		
		printf("get addr error");
		goto __RET;
		
	}	

	snprintf((char*)buffer, 128, "WIFIIPC%02x%02x%02x%02x%02x%02x%03d",
	         HwAddr[0], HwAddr[1], HwAddr[2], HwAddr[3], HwAddr[4], HwAddr[5],
	         GetWifiLevel("wlan0"));	

	printf("send:%s\n", buffer);
	
	unsigned long ull = 0;
	ioctl(sockfd, FIONBIO, &ull);//设置为阻塞模式
	
	while(!recived)
	{
		ret = send(sockfd, buffer, strlen((char *)buffer)+1, 0);
		if(ret > 0)
		{	
			printf("send ok............\n");

			FD_ZERO(&rfds);
			FD_SET(sockfd,&rfds);
			tv1.tv_sec = 2;
		   	tv1.tv_usec = 0;
			ret = select(sockfd+1, &rfds, NULL, NULL, &tv1);
			if(ret<0)
			{
				if (errno == EINTR ||errno == EAGAIN )
				{
					printf("errno is %d.\n",errno);
					continue;
				}
				else
				{
					printf("select error..\n");
					continue;
				}
			}
			else if (ret == 0 )
			{
				printf("select timeout\n");
				continue;
			}

			if(FD_ISSET(sockfd, &rfds))
			{
				memset(buffer, 0, sizeof(buffer));
				ret = recv(sockfd, buffer, sizeof(buffer), 0);
				if (ret > 0)
				{
					printf("recv %s\n", buffer);
					g_IpcRuningData.DeamonSocketFd = sockfd;
					if (!memcmp(buffer, "OK", 2))
					{
						recived = 1;
						
					}
					else
					{
						break;
					}
						
				}
				else
				{
					printf("recv error ..the errno is %d.\n", errno);
					continue;
		
				}

			}			
		
		}

	}

	if(recived)
	{
		printf("the fist connect to nvr success......\n");
		return 1;

	}
	else
	{
		goto __RET;
	}
	
	
__RET:
	printf("begin to close sockfd...........\n");
	CloseNvrSocket(&sockfd);
	
	sync();
	return 0;
}


static int TryConnect(struct wpa_ap_info pwifi_scan, int hidden, int force)
{
	unsigned int i, times = 0;
	unsigned int uwRet = 0, connected = 0;
	int  getip_num = 0;
	char ipBuf[20] = {0};
	struct wpa_assoc_request wpa_assoc_req ;

	printf("\nTry to connect %s with %d!\n", pwifi_scan.ssid, force);
	printf("\033[33mthe g_wpa_supplicant_had_run <%d>,  g_wpa_supplicant_had_connect<%d>\033[0m\n", g_wpa_supplicant_had_run, g_wpa_supplicant_had_connect );


	
	//查看是否已经连接上热点了，如果已经连接，则先进行去关联
	
	XmGetEthAttr("wlan0", IP_ADDR, ipBuf);
	if((memcmp(ipBuf, "0.0.0.0", 7) != 0 ) ||( g_wpa_supplicant_had_connect == 1))
	{
		
		printf("begin to wpa_cli_disconnect............................................\n");
		
		
		wpa_cli_disconnect();
		
		usleep(1000*100);
		memset(ipBuf, 0, sizeof(ipBuf));
	}
	
	memset(&wpa_assoc_req, 0, (sizeof(struct wpa_ap_info)));	

	memcpy(wpa_assoc_req.ssid, pwifi_scan.ssid, 33);
	memcpy(wpa_assoc_req.key, "XMNVR123456", strlen("XMNVR123456"));
	
	wpa_assoc_req.auth = pwifi_scan.auth;
	wpa_assoc_req.hidden_ssid = hidden;

	(memcmp(wpa_assoc_req.ssid, "WIFINVR", 7) == 0)?(getip_num = 20):(getip_num = 40);

	uwRet = wpa_cli_connect(&wpa_assoc_req);
	if(uwRet == 0)
	{
		printf("wpa_cli_connect success.wait udhc get ip\n");
		
		init_completion(&g_dhcp_complet);
		uwRet = wait_for_completion_timeout(&g_dhcp_complet, LOS_MS2Tick(1000*getip_num));//40s超时
		if (0 == uwRet)
		{
			printf("hsl_demo_connect_prepare:cannot get ip\n");
			return connected;
		}
		else
		{
			memcpy(&g_IpcRuningData.WifiNvrInfo, &pwifi_scan, sizeof(g_IpcRuningData.WifiNvrInfo));
				
		}
		
		int timescount = 0;
		
		xm_get_tick("wpa_cli connected", &timescount);
		
		connected = 1;	

	}
	
	if(g_wpa_supplicant_had_connect)
	{

		/*
		
		if (force == WIRELESS_PAIRING)
		{
			connected = PairingWithNVR();
			if(connected)
			{
				
			}
		}
		*/

		if (memcmp(pwifi_scan.ssid, "WIFINVR_", 8) != 0) //有线中继，跳过连接socket
		{
			int sockfd;
			sockfd = ConnectNvrSocket(NVR_IP_ADDR);
			if (sockfd < 0)
			{
				printf("ConnectNvrSocket failed\n");
				connected = 0;
			}
			else
			{
				printf("ConnectNvrSocket succeed\n");
				connected = 1;
				
		    }
		}
		
	}	

	unsigned int tick = 0;
	xm_get_tick(__FUNCTION__, &tick);
	
	//如果最终连接成功的，做个标记
	if (g_wpa_supplicant_had_sock && g_wpa_supplicant_had_connect)
	{
		printf("Connect %s Succeed\n", pwifi_scan.ssid);
		
		
		memcpy(&g_IpcRuningData.WifiNvrInfo, &pwifi_scan, sizeof(g_IpcRuningData.WifiNvrInfo));
		if ((force == WIRELESS_PAIRING) && (memcmp(pwifi_scan.ssid, "WIFINVR", 7) == 0))		//Bridge 不需要保存标志
		{			
			printf("\033[32mSave the last.conf.\033[0m\n");
			FileParam_s wFileParam;
			memset(&wFileParam, 0, sizeof(wFileParam));
			strncpy(wFileParam.ssid, pwifi_scan.ssid, strlen(pwifi_scan.ssid));
			wFileParam.authType = pwifi_scan.auth;
			Write_Config_File(CONNNECTED_NVR_CONF, wFileParam);
						
		}

		
	}	

	return connected;

}

void ReadSpiInfo(void)
{
	printf("***begin to read the spi info......................................................................\n");
	char  * spibuf = NULL;
	spibuf = (char *)malloc(30000);
	if(spibuf == NULL)
	{
		printf("Cannot Malloc Memory For Buf At %s\n",__FUNCTION__);
		return;
	}
	memset(spibuf, 0, 30000);
	extern int hispinor_read(void* memaddr, unsigned long start, unsigned long size);
	hispinor_read(spibuf,0x770000,30000);
	FileSimpleWrite(SPI_INFO, spibuf, 30000);	

}



int WirelessPairing(int pairing_type)
{
	unsigned int uwRet = 0;
	unsigned int num = 0;
	int connected = -1, last = -1;
	int i, j;
	int lastWifiinfoIndex[10];
	int lastWifiCount = 0;
	
	char *WifiPrefix[2] = {NVR_WIFI_SSID_PREFIX, BRG_WIFI_SSID_PREFIX};
	
	unsigned int search_times = 0;
	unsigned int event = 0;
	unsigned char sleep_flag[2] = {0};

	FileParam_s rFileParam;

	
	

	//先读取 是否是唤醒还是正常开机，已经唤醒前网络状况标志

	if(access(CONNNECTED_SLEEP_FLAG, F_OK) == 0)
	{		
		Read_Config_File(CONNNECTED_SLEEP_FLAG, &rFileParam);
		g_before_sleep_wlan_flag = rFileParam.wlanFlag;
		printf("the g_before_sleep_wlan_flag is %d.\n", g_before_sleep_wlan_flag);
	}

	

	//先检验是重新上电开机还是待机唤醒状态，待机唤醒跳过配网过程
	//仅当唤醒的原因为tcp或udp唤醒时，直接跳过连饺鹊阌的过程，进行后面的socket连接通信
	if((g_ul_xm_wlan_resume_state == 1) && (g_before_sleep_wlan_flag == 1) && 
		((g_wakup_reason == 3) ||(g_wakup_reason == 2) ||(g_wakup_reason == 11) ||(g_wakup_reason == 12) ||(g_wakup_reason == 18)))
	{
		printf("\n*****************had connected .go to heartbeat******************\n");
		g_wakup_reason = 20;
		memset(g_IpcRuningData.WifiNvrInfo.ssid, 0, 33);
		Read_Config_File(CONNNECTED_SLEEP_FLAG, &rFileParam);
		strncpy(g_IpcRuningData.WifiNvrInfo.ssid, rFileParam.ssid, strlen(rFileParam.ssid));
		
		g_wpa_supplicant_had_connect = 1;

		if(hisi_wlan_set_keepalive_switch(0, 1) == 0)
			printf("off keepalive success...............\n");
		
		//ReadSpiInfo();
		return 1;

	}	

	//先不搜索无线，直接连接快速连接文件里的无线	,当唤醒原因不为对端去关联去认证时，



	if((access(CONNNECTED_NVR_CONF, F_OK) == 0) && (g_wakup_reason != 20))
	{
		struct wpa_ap_info last_result ;
		
		Read_Config_File(CONNNECTED_NVR_CONF, &rFileParam);
		
		
		if(strlen(rFileParam.ssid) != 0)
		{			
			memset(&last_result, 0, sizeof(struct wpa_ap_info));
			memcpy(last_result.ssid, rFileParam.ssid, strlen(rFileParam.ssid));
			last_result.auth = rFileParam.authType;
			
			
			int timescount = 0;
			xm_get_tick("fast connect", &timescount);
			
			if (TryConnect(last_result, 0, FAST_PAIRING))
			{
				return 1;
			}
			
		}
	}
	
	//快速连接不成功，开始搜索附近的NVR /BRG

	struct wpa_ap_info *pwifi_result = NULL;
	pwifi_result = malloc(sizeof(struct wpa_ap_info) * SCAN_AP_LIMIT);

	if(NULL == pwifi_result)
	{
		printf("malloc wpa_ap_info error \n");
		return -1;
	}

	memset(pwifi_result, 0, (sizeof(struct wpa_ap_info) * SCAN_AP_LIMIT));
	
	uwRet = Search_Wifi(pwifi_result, &num, WifiPrefix);
	while((uwRet != 1) && (search_times < 6))
	{
		memset(pwifi_result, 0, (sizeof(struct wpa_ap_info) * SCAN_AP_LIMIT));
		printf("search wifi can not find nvr or brg.try again......\n");
		uwRet = Search_Wifi(pwifi_result, &num, WifiPrefix);
		search_times++;
	}

	//如果连续搜索了6次都没有搜索到NVR或中继，设置主控睡眠，识别到快速连接的ssid后唤醒
	if(search_times >= 6)
	{
		XmSuspendByWlan("search NVR not find suspend");
		
	}
		
	printf("search wifi done!the num = %d.\n", num);	

	//如果有强制连接标志，直接连接，不进入配对流程
	
	if ( !access(FORCE_CONNECT_FLAG, F_OK) )
	{
		printf("***************************force to Pairing \n");
		char buf[128] = {0};

		FileSimpleRead(FORCE_CONNECT_FLAG, buf, 128);

		for (i=0; i<num; i++)
		{
			if (memcmp(buf, pwifi_result[i].ssid, strlen(pwifi_result[i].ssid)) == 0)
			{
				if (TryConnect(pwifi_result[i], 0, FORCE_PAIRING))
				{
					connected = i;
					break;
				}				
			}
		}
	}

	
	//查看上次成功连接过的

	if ( (!access(CONNNECTED_NVR_CONF, F_OK) ) && (-1==connected))
	{
		

		if(Read_Config_File(CONNNECTED_NVR_CONF,&rFileParam) != 0)
		{
			printf("read file <%s> error.\n", CONNNECTED_NVR_CONF);

		}

		for (i=0; i<num; i++)
		{
			if (strlen(rFileParam.ssid) == strlen(pwifi_result[i].ssid)
				&& !memcmp(rFileParam.ssid, pwifi_result[i].ssid, strlen(rFileParam.ssid)))
			{
				last = i;
				break;
			}
			else
			{
				last = -1;
			}
		}

		for (i=0; i<num; i++)
		{
			if 	(((strlen(rFileParam.ssid) == strlen(pwifi_result[i].ssid)
					&& !memcmp(rFileParam.ssid, pwifi_result[i].ssid, strlen(rFileParam.ssid))))
				||((memcmp(pwifi_result[i].ssid, BRG_WIFI_SSID_PREFIX, 7) == 0)
					&& (memcmp(&rFileParam.ssid[7], &pwifi_result[i].ssid[7], 12) == 0)))
			{
				lastWifiinfoIndex[lastWifiCount++] = i;
				printf("The last related ap:%s\n", pwifi_result[i].ssid);
				if ( i == last)
				{
					break;	//比NVR信号弱的BRG都丢弃掉
				}
			}
		}
	}
	

	//尝试连接没有连接过的NVR

	if (pairing_type != LAST_PAIRING)
	{
		
		for (i=0; (-1==connected) && (i<num); i++)
		{
			if (i == last)
				continue;//上次成功连接过的，这里暂时先不连	

			if (memcmp(pwifi_result[i].ssid, BRG_WIFI_SSID_PREFIX, 7) == 0)
				continue;//Bridge不用配对，只与NVR配对

			if (pwifi_result[i].rssi< MIN_PAIRING_SIGNAL_LEVEL*100)
				continue;//信号强度>60, 配对需要放在NVR附近

			printf("***************************Try to pairing the new nvr\n");

			if (TryConnect(pwifi_result[i], 0, WIRELESS_PAIRING))
			{
				connected = i;
				break;
			}
		}



	}
	

	
	/********************************************************
	 * 没有在配对的NVR，那就强制连接上次的,如果能连上
	 ********************************************************/

	if ( connected == -1 && lastWifiCount > 0)
	{
		printf("**************************Try to connect the last NVR or related Bridge\n");
		
		if (last >= 0)
		{
			printf("Find NVR, Try last NVR.	the last ssid rssi is %d.\n", pwifi_result[last].rssi/100);
		//如果NVRlevel>80, 直接连接NVR
			if (pwifi_result[last].rssi> SWITCH_TO_BRIDGE_STRONG_SIGNAL_LEVEL*100)		
			{
				if (TryConnect(pwifi_result[last], 0, LAST_PAIRING))
				{
					connected = last;
				}
			}
			
		//如果 80<=NVRleverl>70,只有bridge超过NVR10以上，才连中继
			else if (pwifi_result[last].rssi> SWITCH_TO_BRIDGE_MIDDLE_SIGNAL_LEVEL*100)	
			{
				for (i = 0; i < lastWifiCount - 1; i++)
				{
					if (pwifi_result[lastWifiinfoIndex[i]].rssi>  (pwifi_result[last].rssi/100 + 10)*100)
					{
						if (pwifi_result[lastWifiinfoIndex[i]].rssi < 100*(pwifi_result[last].rssi/100 + 5))
						{
							printf("Too weak bridge signal level: %d, %d, skip it\n", 	pwifi_result[lastWifiinfoIndex[i]].rssi, pwifi_result[last].rssi);
							continue;
						}
						
						if (TryConnect(pwifi_result[lastWifiinfoIndex[i]], 0,  LAST_PAIRING))
						{
							connected = lastWifiinfoIndex[i];
							break;
						}
						else		//如果连不上，再试一次
						{
							printf("Connect %s failed, try again\n", pwifi_result[lastWifiinfoIndex[i]].ssid);
							if (TryConnect(pwifi_result[lastWifiinfoIndex[i]], 0,  LAST_PAIRING))
							{
								connected = lastWifiinfoIndex[i];
								break;
							}
						}
					}
				}

				if (connected < 0)												//如果无中继level超过NVR 10 以上或连不上，连上次连接过的
				{
					if (TryConnect(pwifi_result[last], 0, LAST_PAIRING))
					{
						connected = last;
					}
				}
			}

		//如果 70<=NVRleverl>60,只有bridge超过NVR5以上，才连中继
			else if (pwifi_result[last].rssi > 100*SWITCH_TO_BRIDGE_WEAK_SIGNAL_LEVEL)
			{
				for (i = 0; i < lastWifiCount - 1; i++)
				{
					if (pwifi_result[lastWifiinfoIndex[i]].rssi >  100*(pwifi_result[last].rssi/100 + 5))
					{
						if (TryConnect(pwifi_result[lastWifiinfoIndex[i]], 0,  LAST_PAIRING))
						{
							connected = lastWifiinfoIndex[i];
							break;
						}
						else		//如果连不上，再试一次
						{
							printf("Connect %s failed, try again\n", pwifi_result[lastWifiinfoIndex[i]].ssid);
							if (TryConnect(pwifi_result[lastWifiinfoIndex[i]], 0,  LAST_PAIRING))
							{
								connected = lastWifiinfoIndex[i];
								break;
							}
						}
					}
				}

				if (connected < 0)												//如果无中继level超过NVR5以上或连不上，连NVR
				{
					if (TryConnect(pwifi_result[last], 0,  LAST_PAIRING))
					{
						connected = last;
					}
				}
			}

		//NVRLevel < 60,信号很弱，哪个强连哪个
			else																	
			{
				for (i = 0; i < lastWifiCount; i++)
				{
					if (TryConnect(pwifi_result[lastWifiinfoIndex[i]], 0, LAST_PAIRING))
					{
						connected = lastWifiinfoIndex[i];
						break;
					}
					else		//如果连不上，再试一次
					{
						printf("Connect %s failed, try again\n", pwifi_result[lastWifiinfoIndex[i]].ssid);
						if (TryConnect(pwifi_result[lastWifiinfoIndex[i]], 0, LAST_PAIRING))
						{
							connected = lastWifiinfoIndex[i];
							break;
						}
					}
				}
			}
		}


	//找不NVR,直接连中继
		else																		
		{
			printf("NOT find NVR, try BRG.......\n");
			for (i = 0; i < lastWifiCount; i++)
			{
				if (TryConnect(pwifi_result[lastWifiinfoIndex[i]], 0, LAST_PAIRING))
				{
					connected = lastWifiinfoIndex[i];
					break;
				}
				else		//如果连不上，再试一次
				{
					printf("Connect %s failed, try again\n", pwifi_result[lastWifiinfoIndex[i]].ssid);
					if (TryConnect(pwifi_result[lastWifiinfoIndex[i]], 0, LAST_PAIRING))
					{
						connected = lastWifiinfoIndex[i];
						break;
					}
				}
			}
		}
	}

	free(pwifi_result);
	return connected>=0?1:0;	

}

int ReconnectWithNvr(void)
{
	int sockfd = -1;
	int i = 10, times = 0;
	int connectStatus = 0;

	do
	{
		sockfd = ConnectNvrSocket(NVR_IP_ADDR);
		if (sockfd < 0)
		{
			printf("ConnectNvrSocket failed\n");
		}
		usleep(1000*1000);
	}while((sockfd < 0) && (i-- > 0));

	if ((i <= 0) && (sockfd < 0))
	{
		printf("Cannot connect the NVR, redo the wireless pairing\n");
		do
		{
			connectStatus = WirelessPairing(LAST_PAIRING);
		}while((!connectStatus) && (times ++ < 5));

		if(times >= 5)
		{
			RebootSystem();
		}
		else
		{
			sockfd = g_IpcRuningData.DeamonSocketFd;
		}
		
	}

	return sockfd;
}


int ForceConnect(char *pSsid)
{
	int num = 0;
	struct wpa_ap_info wifiinfo[20];
	FileParam_s rFileParam;
	memset(&rFileParam, 0, sizeof(rFileParam));
	
	char buf[64] = {0};
	int ret = -1;
	int retry = 3;	

	if ( memcmp(g_IpcRuningData.WifiNvrInfo.ssid, pSsid, strlen(pSsid)) == 0)
	{
		IPC_INFO("Same ssid: %s, %s, needn't to redo the pairing\n", g_IpcRuningData.WifiNvrInfo.ssid, pSsid);

		if (access(FORCE_CONNECT_FLAG, F_OK) == 0)
		{
			if ((FileSimpleRead(FORCE_CONNECT_FLAG, buf, 64) == 0)
				&& (memcmp(buf, pSsid, strlen(pSsid)) == 0))
			{
				return 0;
			}
			else
			{
				remove(FORCE_CONNECT_FLAG);
				
			}
		}

		FileSimpleWrite((const char *)FORCE_CONNECT_FLAG, pSsid, strlen(pSsid)+1); 	
		
		return 0;
	}

	int count = 5;
	while(count-- > 0)
	{
		retry = 3;
		while(retry-- > 0)
		{
			printf("retry %d\n", retry);
			memset(wifiinfo, 0, sizeof(wifiinfo));
			ret = Search_Wifi(wifiinfo, &num, &pSsid);
			
			if ((ret < 0) || (num <= 0))
			{
				printf("Can't find: %s\n", pSsid);
				usleep(1000*1000);
				continue;
			}
			else
			{
				if (TryConnect(wifiinfo[0], 0, FORCE_PAIRING))
				{
					ret = g_IpcRuningData.DeamonSocketFd;
					FileSimpleWrite((const char *)FORCE_CONNECT_FLAG, pSsid, strlen(pSsid)+1); 
					return ret;
				}
			}
		}

		printf("connect %s failed\n", pSsid);
		if (memcmp(pSsid, "WIFINVR", 7) != 0)
		{
			Read_Config_File(CONNNECTED_NVR_CONF, &rFileParam);
			printf("Cannot connect to bridge: %s, try to NVR host: %s\n", pSsid, rFileParam.ssid);

			memset(wifiinfo, 0, sizeof(wifiinfo));
			char *p = rFileParam.ssid;
			ret = Search_Wifi(wifiinfo, &num, &p);
			if ((ret < 0) || (num <= 0))
			{
				printf("Can't find: %s\n", rFileParam.ssid);
				continue;
			}

			if (TryConnect(wifiinfo[0], 0, FORCE_PAIRING))
			{
				ret = g_IpcRuningData.DeamonSocketFd;
				return ret;
			}
		}
	}
	//如果都连不上中继，也连不上NVR，说明IPC异常，重新初始化wifi模块
	printf("\n\nforce connect can not success.....\n\n");
	hisi_wlan_wifi_deinit();
	return -1;
}

int RedoPairing(void)
{
	int sockfd = -1;
	int connectStatus = 0;
	int level = 0;
	unsigned int times = 0;

	printf("Redo pairing\n");
	if ((level = GetWifiLevel("wlan0")) < 60)	//信号强度很低，重新寻找是否有中继
	{
		printf("GetIpcWifiLevel = %d",level);
		do
		{
			connectStatus = WirelessPairing(LAST_PAIRING);
		}while((!connectStatus) && (times ++ < 5));

		if(times >= 5)
		{			
			RebootSystem();
		}
		else
		{
			sockfd = g_IpcRuningData.DeamonSocketFd;
		}

		
	}
	else
	{
		sockfd = ConnectNvrSocket(NVR_IP_ADDR);
		if (sockfd < 0)
		{
			printf("ConnectNvrSocket failed, redo the pairing\n");
			do
			{
				connectStatus = WirelessPairing(LAST_PAIRING);
				
			}while((!connectStatus) && (times++ < 5));
			
			if(times >= 5)
			{
				RebootSystem();
			}
			else
			{
				sockfd = g_IpcRuningData.DeamonSocketFd;
			}

		}
	}
	return sockfd;
}


int Switch2Bridge(void)
{
	//int connected = -1;
	int i, num = 0;
	int ret = 0;
	
	struct wpa_ap_info wifiinfo[20];
	
	char bridgePrefix[64];
	FileParam_s rFileParam;
	memset(&rFileParam, 0, sizeof(rFileParam));
	
	Read_Config_File(CONNNECTED_NVR_CONF, &rFileParam);
	
	char *WifiPrefix[2] = {rFileParam.ssid, bridgePrefix};
	

		

	memset(bridgePrefix, 0x00, 64);
	memcpy(bridgePrefix, g_IpcRuningData.WifiNvrInfo.ssid, 19);
	memcpy(bridgePrefix, "WIFIBRG", 7);
	memset(wifiinfo, 0, sizeof(wifiinfo));
	
	ret = Search_Wifi(wifiinfo, &num, WifiPrefix);
	if ((ret != 1) || (num <= 0))
	{
		printf("Can't find nvr or brg . try again\n");
		ret = Search_Wifi(wifiinfo, &num, WifiPrefix);
		if ((ret != 1) || (num <= 0))
		{
			printf("Can't find nvr or brg .\n");			
			return ret;
		}		
	}

	for (i=0; i<num; i++)
	{
		if ((strlen(g_IpcRuningData.WifiNvrInfo.ssid) == strlen(wifiinfo[i].ssid))
			&& (memcmp(g_IpcRuningData.WifiNvrInfo.ssid, wifiinfo[i].ssid, strlen(g_IpcRuningData.WifiNvrInfo.ssid)) == 0))
		{
			printf("The same SSID, needn't switch\n");
			if(memcmp(g_IpcRuningData.WifiNvrInfo.ssid, "WIFIBRG", 7) == 0)
			{
				break;
			}
			
			continue;			
		}
		else
		{
					
			if (TryConnect(wifiinfo[i], 0, LAST_PAIRING))
			{
				printf("Switch to %s\n", wifiinfo[i].ssid);
				ret = g_IpcRuningData.DeamonSocketFd;
				break;
			}
			else
			{
				ret = -1;
			}
		}
	}

	return ret;
}





int WirelessHeartbeat(void)
{
	int sockfd;
	int ret;
	int count = 0;
	char heartBeat[64];
	int noAckHeartBeatCount = 0;
	int connectStatus = 0;
	int DisconnectionCount = 0;
	int weakSignalCount = 0;
	int firstHeart = 0;
	fd_set fdRead;
	struct timeval tv;
	char recvBuf[1024];
	int  recvSize,recvBufSize=1024;
	
	char keybuf[64];
	char* localip_eth2 = NULL;
	unsigned int tick = 0, times = 0;

	FileParam_s rFileParam;
	
	
	int cmdnum = 0;	

	memset(recvBuf, 0x00, recvBufSize);

	xm_get_tick(__FUNCTION__, &tick);
	
	printf("\n\n\033[33mPairing succeed, enter WirelessHeartbeat...\033[0m\n");
	
	sockfd = g_IpcRuningData.DeamonSocketFd;
	XmGetEthAttr("wlan0", HW_ADDR, g_IpcRuningData.LanMac);
	while(1)
	{
		
		//printf("\n\nthe count is %d.		weaksig is %d.\n", count, weakSignalCount);
		
		/* Send heartbeat */
		if ((count++)%3 == 0)
		{
			g_IpcRuningData.WifiNvrInfo.rssi = GetWifiLevel("wlan0");
			

			if (g_IpcRuningData.WifiNvrInfo.rssi < 10)
			{
				printf("Link level = 0, the WIFINVR or Bridge lost\n");
				if (DisconnectionCount++ > 10)
				{
					CloseNvrSocket(&sockfd);
					do
					{
						connectStatus = WirelessPairing(LAST_PAIRING);
						usleep(1000*50);
					}while((!connectStatus) && (++times <3));

					if(times < 3)
					{
						times = 0;
						weakSignalCount = 0;
						DisconnectionCount = 0;
						sockfd = g_IpcRuningData.DeamonSocketFd;
					}
					else
					{	
						times = 0;
						RebootSystem();
					}
					
				}
				usleep(1000*100);
				continue;
			}
			else if (g_IpcRuningData.WifiNvrInfo.rssi < 60)
			{
				if (weakSignalCount++ > 10)
				{
					int ret = 0;
					weakSignalCount = 0;
					printf("Weak signal, try to switch to bridge\n");
					ret = Switch2Bridge();
					if (ret == 0)
					{
						printf("No bridge to switch\n");
					}
					else if (ret < 0)
					{
						CloseNvrSocket(&sockfd);
						continue;
					}
					else
					{
						
						DisconnectionCount = 0;
						//CloseNvrSocket(&sockfd);
						//g_IpcRuningData.DeamonSocketFd = ret;
						sockfd = g_IpcRuningData.DeamonSocketFd;
					}
				}
			}
			else
			{
				weakSignalCount = 0;
				DisconnectionCount = 0;
			}
			if (noAckHeartBeatCount++ >= 10)
			{
				printf("Lost heartbeat ACK %d\n", noAckHeartBeatCount);

			       CloseNvrSocket(&sockfd);
				sockfd = RedoPairing();
				if (sockfd < 0)
				{
					printf("ReconnectNvrSocket failed\n");
					sleep(1);
					continue;
				}
				else
				{
					noAckHeartBeatCount = 0;
				}
			}

			memset(heartBeat, 0x00, 64);
			if (memcmp(g_IpcRuningData.WifiNvrInfo.ssid, "WIFINVR", 7) == 0)
			{
				if ((access(FORCE_CONNECT_FLAG, F_OK) == 0)
					&& (Read_Config_File(FORCE_CONNECT_FLAG, &rFileParam) == 0)
					&& (memcmp(g_IpcRuningData.WifiNvrInfo.ssid, rFileParam.ssid,strlen(rFileParam.ssid)+1) == 0))
				
				{
					snprintf((char*)heartBeat, 64, "IPC%02x%02x%02x%02x%02x%02x%03dF",
						g_IpcRuningData.LanMac[0], g_IpcRuningData.LanMac[1],
						g_IpcRuningData.LanMac[2], g_IpcRuningData.LanMac[3],
						g_IpcRuningData.LanMac[4], g_IpcRuningData.LanMac[5],
						g_IpcRuningData.WifiNvrInfo.rssi);
				}
				else
				{
					snprintf((char*)heartBeat, 64, "IPC%02x%02x%02x%02x%02x%02x%03dA",
											g_IpcRuningData.LanMac[0], g_IpcRuningData.LanMac[1],
											g_IpcRuningData.LanMac[2], g_IpcRuningData.LanMac[3],
											g_IpcRuningData.LanMac[4], g_IpcRuningData.LanMac[5],
											g_IpcRuningData.WifiNvrInfo.rssi);

				}
			}
			else if (memcmp(g_IpcRuningData.WifiNvrInfo.ssid, "WIFIBRG", 7) == 0)
			{
				if ((access(FORCE_CONNECT_FLAG, F_OK) == 0)
					&& (Read_Config_File(FORCE_CONNECT_FLAG, &rFileParam) == 0)
					&& (memcmp(g_IpcRuningData.WifiNvrInfo.ssid, rFileParam.ssid, strlen(rFileParam.ssid)+1) == 0))
				{
					snprintf((char*)heartBeat, 64, "BPC%02x%02x%02x%02x%02x%02x%03dm%sF",
						g_IpcRuningData.LanMac[0], g_IpcRuningData.LanMac[1],
						g_IpcRuningData.LanMac[2], g_IpcRuningData.LanMac[3],
						g_IpcRuningData.LanMac[4], g_IpcRuningData.LanMac[5],
						g_IpcRuningData.WifiNvrInfo.rssi,
						g_IpcRuningData.WifiNvrInfo.ssid+19);
				}
				else
				{
					snprintf((char*)heartBeat, 64, "BPC%02x%02x%02x%02x%02x%02x%03dm%sA",
						g_IpcRuningData.LanMac[0], g_IpcRuningData.LanMac[1],
						g_IpcRuningData.LanMac[2], g_IpcRuningData.LanMac[3],
						g_IpcRuningData.LanMac[4], g_IpcRuningData.LanMac[5],
						g_IpcRuningData.WifiNvrInfo.rssi,
						g_IpcRuningData.WifiNvrInfo.ssid+19);
				}
			}
			else
			{
				printf("Irregular ssid %s\n", g_IpcRuningData.WifiNvrInfo.ssid);
			}
			//IPC_INFO("send heartbeat:%s\n", heartBeat);
			IPC_INFO("\033[33msend heartbeat:%s\033[0m\n", heartBeat);
			
			ret = send(sockfd, heartBeat, strlen(heartBeat)+1, 0);
			if (ret <= 0)
			{
				printf("Socket %d send failed %d, %s\n",sockfd, errno, strerror(errno));
				

				if (errno == EPIPE)
				{
					CloseNvrSocket(&sockfd);
					sockfd = ReconnectWithNvr();
				}
				else if (errno == EBADF)
				{
					CloseNvrSocket(&sockfd);
					sockfd = ConnectNvrSocket(NVR_IP_ADDR);
				    if (sockfd < 0)
				    {
						printf("ConnectNvrSocket failed\n");
						continue;
				    }
				}
			}
		}		

		if (sockfd < 0)
		{
			printf("Socket disconneted\n");
			usleep(1000*1000);
			continue;
		}
		FD_ZERO(&fdRead);
		FD_SET(sockfd,&fdRead);
		tv.tv_sec = 1;
	   	tv.tv_usec = 0;
		ret = select(sockfd+1, &fdRead, NULL, NULL, &tv);
		if(ret<0)
		{
			if (errno == EINTR ||errno == EAGAIN )
			{
				printf("at heartbeat select error, the error is %d\n",errno);
				continue;
			}
			else
			{
				printf("at hearbeat select error\n");
				continue;
			}
		}
		else if (ret == 0 )
		{
			//printf("select timeout\n");
			continue;
		}
		if(FD_ISSET(sockfd, &fdRead))
		{
			memset(recvBuf, 0x0, recvBufSize);
			recvSize = recv(sockfd, recvBuf, recvBufSize,0);
			if (recvSize <= 0)
			{
				int i = 5;
				printf("Receive failed\n");
				

				g_IpcRuningData.WifiNvrInfo.rssi = GetWifiLevel("wlan0");
				//printf("the rssi is %d.\n", g_IpcRuningData.WifiNvrInfo.rssi);
				if (g_IpcRuningData.WifiNvrInfo.rssi < 10)
				{
					printf("Link level = 0, the WIFINVR or Bridge lost\n");
					DisconnectionCount++;
					continue;
				}

				CloseNvrSocket(&sockfd);
				do
				{
					sockfd = ConnectNvrSocket(NVR_IP_ADDR);
					if (sockfd < 0)
					{
						printf("ConnectNvrSocket failed\n");
					}
					usleep(1000*50);					
					
				}while((sockfd < 0) && (i-- > 0));

				if (i <= 0)
				{
					printf("Cannot connect the NVR, redo the wireless pairing\n");
					i = 5;
				
					do
					{					
						connectStatus = WirelessPairing(LAST_PAIRING);						
						
					}while((!connectStatus)&& (i-- > 0));
					
					if(i < 0)
					{						
						RebootSystem();
					}
					
				}

				
				
				continue;
			}
			noAckHeartBeatCount = 0;
			//data_dump(recvBuf, recvSize);
			IPC_INFO("Recieve data:%s\n", recvBuf);
			cmdnum = StringToNum(recvBuf);
			
			switch(cmdnum)
			{
				case GOTOBRG:
					{
						CloseNvrSocket(&sockfd);	//不再ACK，直接关闭socket
						do
						{
							connectStatus = WirelessPairing(LAST_PAIRING);
							
						}while((!connectStatus) && (++times < 4));

						if(times < 4)
						{
							sockfd = g_IpcRuningData.DeamonSocketFd;
							times = 0;
						}
						else
						{
							times = 0;
							RebootSystem();
						}
					}					
					break;
				case BRGSIG:
					{
						char *p = recvBuf + 6;
						int bridgeSignal = atoi(p);

						if ( bridgeSignal > 20 )
						{
							IPC_INFO("Update the bridge signal level:%d\n", bridgeSignal);
							FileSimpleWrite((const char *)BRIDGE_SIGNAL_LEVEL_FNAME, p, 3);
						}
						else
						{
							printf("Unrecognized bridge signal level:%d\n", bridgeSignal);
						}						
					}					
					break;
				case IPC_ACK:
					{
						if(!firstHeart)
						{
							xm_get_tick("First Heart", &g_heartime);
							firstHeart = 1;
						}
						IPC_INFO("Heartbeat ACK\n");	
					}					
					break;
				case REBOOT:
					{
						RebootSystem();
					}					
					break;			
				case FORCE:
					{
						char ssid[128] = {0};
						IPC_INFO("Force switch: %s\n", &recvBuf[6]);	

						
						if ((memcmp(&recvBuf[6], "NVR", 3) == 0)
							|| (memcmp(&recvBuf[6], "BRG", 3) == 0))
						{
							snprintf(ssid, sizeof(ssid),  "WIFI%s", &recvBuf[6]);
							ret = ForceConnect(ssid);
							if (ret > 0)
							{
								CloseNvrSocket(&sockfd);
								sockfd = ret;
							}
						}
						else
						{
							printf("Invalid SSID\n");
						}
					}
					break;
				case AUTOSWITCH:
					{
						char cmdBuffer[64] = {0x00};

						printf("Recived AUTOSWITCH command, remove the [FORCE] configuration\n");
						if ( !access(FORCE_CONNECT_FLAG, F_OK) )
						{
							remove(FORCE_CONNECT_FLAG);
							
						}
						
						if (ret = GetWifiLevel("wlan0") > 80)
						{
							printf("Excllent signal, skip the redo pairing\n");
						}
						else
						{
							printf("Redo the pairing\n");
							CloseNvrSocket(&sockfd);
							do
							{
								connectStatus = WirelessPairing(LAST_PAIRING);
								
							}while((!connectStatus) && (++times < 4));

							if(times < 4)
							{
								times = 0;
								sockfd = g_IpcRuningData.DeamonSocketFd;
							}
							else
							{
								times = 0;
								RebootSystem();
							}
						
							
						}
					}
					break;
				case IPconflict:
					{
						
						ret = XmGetEthAttr("wlan0", IP_ADDR, localip_eth2 );
						if( strlen(localip_eth2) == strlen(recvBuf)-11)
						{
							if( memcmp(localip_eth2 ,recvBuf+11,strlen(recvBuf)-11) == 0)
							{
								CloseNvrSocket(&sockfd);
								Wireless_Ipconfig(1);
								sockfd = ReconnectWithNvr();
							}
						}
					}
					break;
				case GOTOSLEEP:
					{
						XmSuspendByWlan("tcp cmd suspend");	
					}									
					break;
				case GOTOWAKE:
					{
						//tcp唤醒用，睡眠状态唤醒主控已经处理了，上电过程中此命令无效，打印就行
						IPC_INFO("GOTOWAKE\n");
					}									
					break;
				case PIR_SET:
					{
						char *p = recvBuf + 8;
						memset(g_IpcRuningData.pirInfo, 0, sizeof(g_IpcRuningData.pirInfo));
						strcpy(g_IpcRuningData.pirInfo, p);
						printf("rec:<%s>\n", g_IpcRuningData.pirInfo);						
						Host_Wake_PirSet();
					}
					break;
				case RTC_SET:
					{						
						char *p = recvBuf + 8;
						int rtctime = 0;
						rtctime = atoi(p);						
						Host_Wake_RtcSet(rtctime);
					}
					break;
				default:
					{
						printf("Invalid command:%s\n", recvBuf);
					}
					break;

			}			
		
		}
		usleep(1000*500);
		
	}
	return -1;
}

void xmconnect_init(void)
{
	unsigned int uwTickCount_wlan_start = 0;
	int uwRet = 0;
	FileParam_s rFileParam;

	//挂载SD卡，测试使用
	mkdir("/mnt/sd0", 0777);
	mount("/dev/mmcblk0p0", "/mnt/sd0", "vfat", 0, NULL);
	

	//获得wifi配网此时的tick数
	xm_get_tick("xmconnect_start", &uwTickCount_wlan_start);

	//初始化一个互斥量g_mux
	LOS_MuxCreate(&g_variable_mux);
	LOS_MuxCreate(&g_function_mux);

	//注册命令
	WifiCmdReg();

	//启动表示和原因显示
	printf("\033[33mthe g_ul_xm_wlan_resume_state is %d\033[0m\n", g_ul_xm_wlan_resume_state);
	HostWake_Reason_Show();	

	//设置唤醒条件
	set_wake_flag();

	if(g_ul_xm_wlan_resume_state == 0)
	{
		wpa_start_xm();		
	}


	//清唤醒ssid
	hisi_wlan_clear_wakeup_ssid();

	memset(&g_QrBarcodeState, 0, sizeof(g_QrBarcodeState));

	//pir设置
	Host_Wake_PirSet();


	return;
}




int xmconnect_start(void)
{
	

	pthread_attr_t attr;
	
	pthread_t sleepThread;
	pthread_t sendheartThread;
	pthread_t keepaliveThread;
	
	pthread_t uarthandleThread;
	pthread_t barcodeThread;
	

	//无线配网初始化
	xmconnect_init();
	
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 0x10000);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	//和单片机通信发送心跳包，正式版本隐藏
	pthread_create(&sendheartThread, &attr, (void*)xm_sendheart_demo_build, NULL);

	//uart测试线程，正式版本隐藏
	pthread_create(&uarthandleThread, &attr, (void*)xm_uarthandle_demo_build, NULL);

	

	//配网，创建和nvr服务器心跳的任务	
	pthread_create(&keepaliveThread, &attr, (void*)xm_keepalive_demo_build, NULL);
	

	//创建休眠的任务，正式版本隐藏
	//pthread_create(&sleepThread, &attr, (void*)xm_sleep_demo_build, NULL);

	//创建厂测模式线程
	//pthread_create(&barcodeThread, &attr, (void*)xm_barcode_demo_build, NULL);
	

}






#if 0
static int  Search_Wifi(struct wpa_ap_info *pwifi_scan, int *pResultNum, char **keys)
{
	unsigned int i, j;
	unsigned int num = 0, num1 = 0;
	unsigned int searched = 0;
	unsigned int uwRet = 0;
	struct wpa_ap_info *pwlan_scan_result = NULL;
	struct wpa_ap_info *pwlan_scan_result_1 = NULL;

	
	//第一次搜索	
	
	pwlan_scan_result = malloc(sizeof(struct wpa_ap_info) * SCAN_AP_LIMIT);

	if(NULL == pwlan_scan_result)
	{
		printf("malloc wpa_ap_info error \n");
		return -1;
	}

	memset(pwlan_scan_result, 0, (sizeof(struct wpa_ap_info) * SCAN_AP_LIMIT));
	uwRet = wpa_cli_scan();
	if(uwRet != 0)
	{
		printf("\n******wpa_cli_scan error*****\n");
		free(pwlan_scan_result);
		pwlan_scan_result = HISI_NULL;

		return -1;
	}	

	usleep(1000*1000);

	
	wpa_scan_results(pwlan_scan_result, &num, keys );
	
	printf("the num is %d.\n", num);
	if (num <= 0)
	{
		printf("Can't find WIFINVR\n");
		free(pwlan_scan_result);
		pwlan_scan_result = HISI_NULL;

		return -1;
	}

	//第二次搜索
	pwlan_scan_result_1 = malloc(sizeof(struct wpa_ap_info) * SCAN_AP_LIMIT);

	if(NULL == pwlan_scan_result_1)
	{
		printf("malloc wpa_ap_info error \n");
		free(pwlan_scan_result);
		pwlan_scan_result = HISI_NULL;

		return -1;
	}

	memset(pwlan_scan_result_1, 0, (sizeof(struct wpa_ap_info) * SCAN_AP_LIMIT));

	uwRet = wpa_cli_scan();
	if(uwRet != 0)
	{
		printf("\n******wpa_cli_scan error*****\n");
		free(pwlan_scan_result);
		pwlan_scan_result = HISI_NULL;

		free(pwlan_scan_result_1);
		pwlan_scan_result_1 = HISI_NULL;
	}	

	usleep(1000*1000);
	
	wpa_scan_results(pwlan_scan_result_1, &num1, keys );
	
	printf("the num1 is %d.\n", num);
	if (num <= 0)
	{
		printf("Can't find WIFINVR\n");
		free(pwlan_scan_result);
		pwlan_scan_result = HISI_NULL;

		free(pwlan_scan_result_1);
		pwlan_scan_result_1 = HISI_NULL;
		
		return -1;
	}

	//比较两次信号强度平均
	if((num >0) && (num1 >0))
	{
		for (i=0; i<num; i++)
		{
			if (pwlan_scan_result[i].ssid[0])
			{
				for (j = 0; j < num1; j++)
				{
					if (memcmp(pwlan_scan_result[i].ssid, pwlan_scan_result_1[j].ssid, strlen(pwlan_scan_result[i].ssid)) == 0)
					{
						pwlan_scan_result[i].rssi = (pwlan_scan_result[i].rssi + pwlan_scan_result_1[j].rssi) / 2;						
						break;
					}
				}
			}
		}


	}

	

	for (i=0; i<num; i++)
	{
		memcpy(pwifi_scan[i].ssid, pwlan_scan_result[i].ssid, 33);
		memcpy(pwifi_scan[i].bssid, pwlan_scan_result[i].bssid, 18);
		pwifi_scan[i].channel = pwlan_scan_result[i].channel;
		pwifi_scan[i].rssi = pwlan_scan_result[i].rssi;
		pwifi_scan[i].auth = pwlan_scan_result[i].auth;	

		searched = 1;
		
	}

	LevelSort(pwifi_scan, num);

	

	printf("\n\n*************************************\n");
	for (i=0; i<num; i++)
	{
		if (pwifi_scan[i].ssid[0])
		{
			if(strlen(pwifi_scan[i].ssid) < 33)
			{
				printf("ssid:%-32s",pwifi_scan[i].ssid);
			}
			else
			{
				continue;
			}
			printf("channel:%d	",pwifi_scan[i].channel);		
			printf("level:%d\n",pwifi_scan[i].rssi/100);
			
		}
		else
		{
			num = i+1;
			break;
		}
	}
	printf("*************************************\n\n");

	*pResultNum = num;

	free(pwlan_scan_result);
	pwlan_scan_result = HISI_NULL;

	free(pwlan_scan_result_1);
	pwlan_scan_result_1 = HISI_NULL;

	return searched;

}

#endif

#if 0
static int TryConnect(struct wpa_ap_info pwifi_scan, int hidden, int force)
{
	unsigned int i;
	unsigned int uwRet = 0;
	int connected = 0;
	struct wpa_assoc_request wpa_assoc_req ;

	printf("\nTry to connect %s with %d!\n", pwifi_scan.ssid, force);

	memset(&wpa_assoc_req, 0, (sizeof(struct wpa_ap_info)));
	

	memcpy(wpa_assoc_req.ssid, pwifi_scan.ssid, 33);
	memcpy(wpa_assoc_req.key, "XMNVR123456", strlen("XMNVR123456"));
	
	wpa_assoc_req.auth = pwifi_scan.auth;
	wpa_assoc_req.hidden_ssid = hidden;

	uwRet = wpa_cli_connect(&wpa_assoc_req);
	if(uwRet == 0)
	{
		printf("wpa_cli_connect success.\n");
		connected = 1;	

	}

	if(connected)
	{
		
		if (force == WIRELESS_PAIRING)
		{
			connected = PairingWithNVR();
		}

		else if (memcmp(pwifi_scan.ssid, "WIFINVR_", 8) != 0) //有线中继，跳过连接socket
		{
			int sockfd;
			sockfd = ConnectNvrSocket(NVR_IP_ADDR);
			if (sockfd < 0)
			{
				printf("ConnectNvrSocket failed\n");
				connected = 0;
			}
			else
			{
				printf("ConnectNvrSocket succeed\n");
				connected = 1;
		       }
		}
		
	}

	
	//如果最终连接成功的，做个标记
	if (connected)
	{
		printf("Connect %s Succeed\n", pwifi_scan.ssid);
		
		memcpy(&g_IpcRuningData.WifiNvrInfo, &pwifi_scan, sizeof(g_IpcRuningData.WifiNvrInfo));
		if ((force == WIRELESS_PAIRING) && (memcmp(pwifi_scan.ssid, "WIFINVR", 7) == 0))		//Bridge 不需要保存标志
		{
			
			printf("\033[32mSave the last.conf.\033[0m\n");
			FileParam_s wFileParam;
			memset(&wFileParam, 0, sizeof(wFileParam));
			strncpy(wFileParam.ssid, pwifi_scan.ssid, strlen(pwifi_scan.ssid));
			wFileParam.authType = pwifi_scan.auth;
			Write_Config_File(CONNNECTED_NVR_CONF, wFileParam);
		}
	}	

	return connected;

}

#endif








