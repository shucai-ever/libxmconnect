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
#include "sys/prctl.h"


#include "xmextlib.h"
#include "xmconnect.h"
#include "xmnet.h"
#include "xmcmd.h"

#include "zbar.h"
#include "image.h"



#define PATH_WLAN_STATE 					"/jffs1/mnt/mtd/Config/wlanstate"	
#define NVR_IP_ADDR 						"172.25.123.92"
#define CONNNECTED_NVR_CONF 				"/jffs1/mnt/mtd/Config/last.conf"
#define CONNNECTED_SLEEP_FLAG 				"/jffs1/mnt/mtd/Config/sleep.conf"
#define LOGGER_CONF							"/jffs1/mnt/mtd/Config/logger.conf"
#define IPC_INFO_ENABLE_FLAG 				"/jffs1/mnt/mtd/Config/heartbeat_info"
#define KEEPALIVE_BUF1         				"sleep" //保活包内容
#define BROADCAST_MONITOR_PORT 				4555 

#define UF_START 							0
#define UF_LEN 								1
#define UF_CMD 								2
#define UF_DATA 							3
#define UF_DATA1 							4
#define UF_DATA2 							5
#define UF_DATA3 							6
#define UF_DATA4 							7
#define UF_DATA5 							8
#define UF_DATA6 							9

#define FRAME_WIDTH							704
#define FRAME_HEIGHT						576
#define             DHCP_IP_SET         0
#define             DHCP_IP_DEL         1



#define 	TCP_KEEPALIVE_FLAG					1
#define 	UDP_KEEPALIVE_FLAG					1
#define		LOGGER_FLAG							1



extern unsigned int g_wake_event;						//唤醒条件使能事件集合	默认[000001DF]
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

extern int g_heartime;									//socket交互成功用时





//外部库全局变量引用
extern unsigned int g_ul_xm_wlan_resume_state;			//系统启动标志 								libdvr/net.c定义
extern unsigned int g_force_sleep_flag;					//十分钟强制关闭标志								hi_ext_hal_mcu.c定义

extern unsigned int g_wpa_supplicant_had_connect;		//无线模块作为客户端，是否连接上热点并且获得ip				libdvr/net.c定义

extern int g_power_state;


extern struct completion  g_dhcp_complet;				//完成量变量：等待ip获取成功		app_init.c 定义









StringToNum_s cmdstring[] = {
							{ "GOTOBRG",	GOTOBRG },
							{ "BRGSIG",     BRGSIG },
							{ "IPC_ACK",      IPC_ACK },
							{ "REBOOT",      REBOOT },							
							{ "FORCE:",     FORCE },
							{ "AUTOSWITCH:",      AUTOSWITCH },
							{ "IPconflict:",      IPconflict },
							{ "GOTOSLEEP",	GOTOSLEEP },
							{ "GOTOWAKE",	GOTOWAKE },
							{ "PIR_SET:",      PIR_SET },
							{ "RTC_SET:",      RTC_SET },
							{ NULL,    Invalid },
						};




//这里为了调试方便，发送心跳和单片机进行通讯，
extern pthread_mutex_t uartSendMutex;
extern int mcu_fd;


int Xm_KeepAlive_Set(void)
{

	int ret, i;
	
	pthread_mutex_lock(&uartSendMutex);
	
	unsigned char uart2_buffer[64] = {0};
	uart2_buffer[1] = 0x04;
	uart2_buffer[2] = 0x9e;

	
	
    uart2_buffer[0] = 0x7B;
    uart2_buffer[uart2_buffer[1] - 1] = XOR_Inverted_Check(uart2_buffer, uart2_buffer[1] - 1);

	if ( !access(IPC_INFO_ENABLE_FLAG, F_OK) )
	{
		printf ("\n");
		printf("\033[32m Data: \033[0m");	
		for(i=0;i<uart2_buffer[1];i++)
			printf("\033[32m%02x \033[0m",uart2_buffer[i]);
		printf("\n");
	}
	

	for (i = 0; i < uart2_buffer[1]; i++)
	{
		ret = write(mcu_fd, &uart2_buffer[i], 1);
		usleep(50);
		if (ret != 1)
		{
			printf("write %d fd return %d\n", mcu_fd, ret);
			pthread_mutex_unlock(&uartSendMutex);
			return -1;
		}
	}

	if ( !access(IPC_INFO_ENABLE_FLAG, F_OK) )
	{
		printf("\033[32m uart send ok! \033[0m");
    	printf("\n");
	}
	
	pthread_mutex_unlock(&uartSendMutex);
	
    return 0;

}

int HI_HAL_MCUHOST_Systemtime_Get(void)
{
	unsigned char uart2_buffer[64] = {0};
	uart2_buffer[UF_LEN] = 0x4;
	uart2_buffer[UF_CMD] = 0xd0;	
	USART_Send_Data(mcu_fd,uart2_buffer);

	return 0;
}

int HI_HAL_MCUHOST_McuInfo_Get(char state)
{
	unsigned char uart2_buffer[64] = {0};
	uart2_buffer[UF_LEN] = 0x5;
	uart2_buffer[UF_CMD] = 0xf0;
	uart2_buffer[UF_DATA] = state;
	USART_Send_Data(mcu_fd,uart2_buffer);

	return 0;
}


int StringToNum(const char * str)
{
	int i;

	for (i = 0; cmdstring[i].name; i++)
	{
		if (memcmp(str, cmdstring[i].name, strlen(cmdstring[i].name)) == 0)
		{
			return cmdstring[i].num;
		}		
		
	}

	return Invalid;

}

int NumToDate(int set, char *out)
{
	switch(set)
	{
		case Sunday:
			strcpy(out, "Sunday");
			break;
		
		case Monday:
			strcpy(out, "Monday");
			break;
		case Tuesday:
			strcpy(out, "Tuesday");
			break;
		case Wednesday:
			strcpy(out, "Wednesday");
			break;
		case Thursday:
			strcpy(out, "Thursday");
			break;
		case Friday:
			strcpy(out, "Friday");
			break;
		case Saturday:
			strcpy(out, "Saturday");
			break;

	}
	

	return 0;

}

static void ReasonToString(int reason, char *out)
{

	switch(reason)
	{
		case REASON_TYPE_NULL:				
			strcpy(out, "normal start");
			break;
		case REASON_TYPE_MAGIC_PACKET:			
			strcpy(out, "magic packet");
			break;
		case REASON_TYPE_NETPATTERN_TCP:
			
			strcpy(out, "tcp netpattern");
			break;
		case REASON_TYPE_NETPATTERN_UDP:
		
			strcpy(out, "udp netpattern");
			break;
		case REASON_TYPE_DISASSOC_RX:
			
			strcpy(out, "receive disassociation");
			break;
		case REASON_TYPE_DISASSOC_TX:
			
			strcpy(out, "send disassociation");
			break;
		case REASON_TYPE_AUTH_RX:
			strcpy(out, "receive authentication");
			break;
		case REASON_TYPE_TCP_UDP_KEEP_ALIVE:
			strcpy(out, "keep alive timeout");
			break;
		case REASON_TYPE_HOST_WAKEUP:
			strcpy(out, "host");
			break;
		case REASON_TYPE_OAM_LOG:
			strcpy(out, "error wifi log");
			break;
		case REASON_TYPE_SSID_SCAN:
			strcpy(out, "specially ssid find");
			break;
		case REASON_TYPE_MCU_KEY:
			strcpy(out, "mcu key press");
			break;
		case REASON_TYPE_MCU_PIR:
			strcpy(out, "mcu pir wake");
			break;
		case REASON_TYPE_MCU_RESET:
			strcpy(out, "mcu reset press");
			break;
		case REASON_TYPE_MCU_RTC:
			strcpy(out, "mcu rtc wake");
			break;
		default:
			strcpy(out, "not know reason");
			break;
	}


	return;
}



void xm_get_tick(const char * ch, int *tick)
{
	UINT64 uwTickCount = 0;

	uwTickCount = LOS_TickCountGet();
	if(0 != uwTickCount)
	{
		printf("\033[32m[ %s ]:	LOS_TickCountGet = %d \033[0m\n", ch, (UINT32)uwTickCount);
	}
	*tick = uwTickCount;
}


int Mux_Operate(int *variable, int num)
{
	int ret = 0;
	ret = LOS_MuxPend(g_variable_mux, LOS_WAIT_FOREVER);
	if(ret != 0)
	{
		printf("mux_pend error.\n");
		return -1;
	}
				
	*variable = num;
	LOS_MuxPost(g_variable_mux);

	return 0;
}

int Mux_Operate_Lock(void)
{
	int ret = 0;
	ret = LOS_MuxPend(g_function_mux, LOS_WAIT_FOREVER);
	if(ret != 0)
	{
		printf("g_function_mux lock error.\n");
		return -1;
	}

	return 0;
}

int Mux_Operate_Unlock(void)
{
	int ret = 0;
	
	ret = LOS_MuxPost(g_function_mux);
	if(ret != 0)
	{
		printf("g_function_mux unlock error.\n");
		return -1;
	}

	return 0;
}



static void Host_WakeReason_McuGet(int *reason)
{
	
	unsigned char buf[256] = {0};
	Queue * nvrQueue = NULL;
	
	nvrQueue = GetNvrQueue();
	if(De_Queue(nvrQueue, buf) == 0)
	{
		*reason = buf[2];
	}
	else
	{
		printf("nvrQueue have not info..\n");
	}

	return;

}

static void HostWake_Reason_ShowExport(const char *src)
{
	if(g_wakup_reason < 11)
	{
		printf("\033[33m************host reason [%d]:	%s	************\33[0m\n", g_wakup_reason, src);
	}
	else
	{
		printf("\033[33m************mcu reason [%d]:	%s	************\33[0m\n", g_wakup_reason, src);
	}


	return;
}


void HostWake_Reason_Show(void)
{
	int wakup_reason= 0;
	int count = 0;
	int logFlag = LOGGER_FLAG;
	char reason[30] = {0};

	//从NVR Queue队列取唤醒原因
	Host_WakeReason_McuGet(&wakup_reason);
	
	//从无线模块获取唤醒原因
	hisi_wlan_get_wakeup_reason(&g_wakup_reason);
	if(wakup_reason != 0)
	{
		g_wakup_reason = wakup_reason +10;
	}

	
	xm_get_tick("wake up reason", &count);
	ReasonToString(g_wakup_reason, reason);
	HostWake_Reason_ShowExport(reason);
	if(logFlag)
		XmLogInfoWrite(POWER_UP, reason);

}

int XmBatShow(unsigned char * pCap, int state)
{
	int ret = 0;

	ret = GetSystemPowerCap(pCap, state);
	if(ret != 0)
	{
		printf("get power cap error\n");
		return -1;
	}

	return 0;
}

static void XmMcuInfoShow(char state, McuInfo_s * mcuInfo)
{
	char power[] = "POWER";
	char pir[] = "PIR";
	char force[] = "FORCE";
	char rtc[] = "RTC";
	char weekday[15] = {0};
	
	printf("\033[33m******************************MCU INFO************************************\033[0m\n");
	if((state == 0x0) ||(state == 0xf))	//电源状态
	{
		printf("%-8s:USB CHARGED[%d] BATT FULL[%d]\n", power, mcuInfo->powerInfo&0x1, (mcuInfo->powerInfo&0x2)>> 1);
	}
	if((state == 0x1) ||(state == 0xf))	//pir信息
	{
		printf("%-8s:enCheck[%01d] enSwitch[%01d] checkTime[%d] SecTime0[%01d][%02d:%02d:%02d-%02d:%0d:%02d] SecTime1[%01d][%02d:%02d:%02d-%02d:%0d:%02d]\n",
						pir, mcuInfo->pirInfo.enCheck, mcuInfo->pirInfo.enSwitch, mcuInfo->pirInfo.checkTime,
						mcuInfo->pirInfo.enPirTime[0], mcuInfo->pirInfo.pirTime[0].hour, mcuInfo->pirInfo.pirTime[0].minute,mcuInfo->pirInfo.pirTime[0].second,
												mcuInfo->pirInfo.pirTime[1].hour, mcuInfo->pirInfo.pirTime[1].minute,mcuInfo->pirInfo.pirTime[1].second,
						mcuInfo->pirInfo.enPirTime[1], mcuInfo->pirInfo.pirTime[2].hour, mcuInfo->pirInfo.pirTime[2].minute,mcuInfo->pirInfo.pirTime[2].second,
												mcuInfo->pirInfo.pirTime[3].hour, mcuInfo->pirInfo.pirTime[3].minute,mcuInfo->pirInfo.pirTime[3].second);						
	}
	if((state == 0x2) ||(state == 0xf))	//强制关机信息
	{
		printf("%-8s:enForce[%d] setTime[%d] waitTime[%d] curTime[%d]\n", force, mcuInfo->forceInfo.enForce, mcuInfo->forceInfo.setTime, mcuInfo->forceInfo.waitTime,
																							mcuInfo->forceInfo.curTime);
	}
	if((state == 0x3) ||(state == 0xf))	//单片机rtc时间信息
	{
		NumToDate(mcuInfo->timeInfo.wday, weekday);
		printf("%-8s:mcuTime[%d.%02d.%02d %02d:%02d:%02d %s]\n", rtc, mcuInfo->timeInfo.year, mcuInfo->timeInfo.month, mcuInfo->timeInfo.day,
															mcuInfo->timeInfo.hour, mcuInfo->timeInfo.minute, mcuInfo->timeInfo.second, weekday);
	}

	printf("\033[33m******************************MCU INFO END************************************\033[0m\n");

	return;
}

int XmMcuInfoGet(char state, McuInfo_s * mcuInfo)
{
	
	unsigned char buf[256] = {0};
	char weekday[15] = {0};
	int day = 0, year = 0;
	
	Queue * nvrQueue = NULL;	

	memset(mcuInfo, 0, sizeof(mcuInfo));

	if((state == 0xf) || (state == 0x0))
		HI_HAL_MCUHOST_Power_Poll();
	HI_HAL_MCUHOST_McuInfo_Get(state);
	if(state == 0xf)
		usleep(1000*100);
	else
		usleep(1000*50);

	nvrQueue = GetNvrQueue();
	

	if((state == 0xf) || (state == 0x0))
	{
		xm_wifiqueue_addrshow(nvrQueue);
		mcuInfo->powerInfo = g_power_state;
	}
		
	
	while(De_Queue(nvrQueue, buf) == 0)
	{
		if(buf[2] == 0xf0)
		{			
			if(buf[1] == 21)		//Pir Info
			{
				xm_wifiqueue_addrshow(nvrQueue);
				mcuInfo->pirInfo.enCheck = buf[3];
				mcuInfo->pirInfo.enSwitch = buf[4];
				mcuInfo->pirInfo.checkTime = buf[5];
				mcuInfo->pirInfo.enPirTime[0] = buf[6];
				mcuInfo->pirInfo.pirTime[0].hour = buf[7];
				mcuInfo->pirInfo.pirTime[0].minute = buf[8];
				mcuInfo->pirInfo.pirTime[0].second = buf[9];
				mcuInfo->pirInfo.pirTime[1].hour = buf[10];
				mcuInfo->pirInfo.pirTime[1].minute = buf[11];
				mcuInfo->pirInfo.pirTime[1].second = buf[12];
				mcuInfo->pirInfo.enPirTime[1] = buf[13];
				mcuInfo->pirInfo.pirTime[2].hour = buf[14];
				mcuInfo->pirInfo.pirTime[2].minute = buf[15];
				mcuInfo->pirInfo.pirTime[2].second = buf[16];
				mcuInfo->pirInfo.pirTime[3].hour = buf[17];
				mcuInfo->pirInfo.pirTime[3].minute = buf[18];
				mcuInfo->pirInfo.pirTime[3].second = buf[19];
			}
			else if(buf[1] == 17)	//Force time Info
			{
				xm_wifiqueue_addrshow(nvrQueue);
				mcuInfo->forceInfo.enForce = buf[3];
				mcuInfo->forceInfo.setTime = (buf[4] << 24) |(buf[5] << 16) |(buf[6] << 8) | (buf[7] << 0);
				mcuInfo->forceInfo.waitTime = (buf[8] << 24) |(buf[9] << 16) |(buf[10] << 8) | (buf[11] << 0);
				mcuInfo->forceInfo.curTime =(buf[12] << 24) |(buf[13] << 16) |(buf[14] << 8) | (buf[15] << 0);
			}
			else if(buf[1] == 10)	//mcu time Info
			{
				xm_wifiqueue_addrshow(nvrQueue);				
			
				day = (buf[3] << 24) | (buf[4] << 16) | (buf[5] << 8) | (buf[6] << 0);
				year = (buf[7] << 8) | (buf[8] << 0);			
			
				mcuInfo->timeInfo.year = year;
				mcuInfo->timeInfo.wday = (day >> 26) & 0x3f;	
				mcuInfo->timeInfo.month = (day >> 22) & 0xf;
				mcuInfo->timeInfo.day = (day >> 17) & 0x1f;
				mcuInfo->timeInfo.hour = (day >> 12 ) & 0x1f;
				mcuInfo->timeInfo.minute = (day >> 6) & 0x3f;
				mcuInfo->timeInfo.second = (day >> 0) & 0x3f;				

			}
		}		
	}
	
	XmMcuInfoShow(state, mcuInfo);
	

	return 0;
}




static int XmTcpKeepaliveSet(bool state)
{
	WLAN_KEEPALIVE_CONFIG wlanparam;
	memset(&wlanparam, 0, sizeof(wlanparam));
	wlanparam.sockfd = g_sockfd[0];
	wlanparam.ul_sess_id = 1;
	wlanparam.ul_interval_timer = 60000;	//10s
	wlanparam.ul_retry_interval_timer = 3000;	//3s重传周期
	wlanparam.us_retry_max_count = 8;		//最大重传次数
	strncpy(wlanparam.keepalive_buf, "sleep_demo", 10);
	wlanparam.keepalive_buf_len = strlen(wlanparam.keepalive_buf);
	WlanSetKeepAliveTcpParams(&wlanparam);
	WlanKeepAliveSwitch(state, 1);

	return 0;
}

static void XmNetPatternSet(int tcpflag, int udpflag)
{
	char hw[6] = {0};
	char hwChange[13] = {0};
	char auc_pattern[40] = {0};
	
				
	hisi_wlan_del_netpattern(0);
	hisi_wlan_del_netpattern(1);
	hisi_wlan_del_netpattern(2);
	hisi_wlan_del_netpattern(3);
	if(udpflag)
	{
		XmGetEthAttr("wlan0", HW_ADDR, hw);
		snprintf(hwChange, 13, "%02x%02x%02x%02x%02x%02x", hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]); 
		snprintf(auc_pattern, 22, "GOTOWAKE:%s", hwChange);
		hisi_wlan_add_netpattern(0, auc_pattern, strlen(auc_pattern));
	}

	if(tcpflag)
	{
		hisi_wlan_add_netpattern(1, "GOTOWAKE", 8);
	}
		
	return;
}




int XmSuspendByWlan(const char *reason)
{
	int tcpKeepFlag = TCP_KEEPALIVE_FLAG;
	int udpKeepFlag = UDP_KEEPALIVE_FLAG;
	int loggerFlag = LOGGER_FLAG;
	
	//睡眠前保存文件
	Host_Sleep_Conf_Handle(g_wpa_supplicant_had_connect);

	//主控上下电日志保存
	if(loggerFlag)
		XmLogInfoWrite(POWER_DOWN, reason);

	//设置唤醒字符串
	XmNetPatternSet(tcpKeepFlag, udpKeepFlag);

	//使能tcp唤醒
	if(tcpKeepFlag)
		XmTcpKeepaliveSet(g_wpa_supplicant_had_connect);

	//执行睡眠操作
	sync();
	hisi_wlan_suspend();

	return 0;
}



int XmGetHwAttr(const char *ifname, AddrType_e type, unsigned char* out)
{
	int i = 0;
	unsigned char mac[6] = {0};
	extern unsigned char* hisi_wlan_get_macaddr(void);
	
	
	unsigned char *puc_macaddr = NULL;
	puc_macaddr = hisi_wlan_get_macaddr();
	for(i=0;i<6;i++)
	{
		mac[i] = *(puc_macaddr+i);
	}
	memcpy(out, mac, 6);	
	//printf("the mac is %02x %02x %02x %02x %02x %02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	//printf("the mac is %02x %02x %02x %02x %02x %02x\n", *out, *(out+1), *(out+2), *(out+3), *(out+4), *(out+5));
	
	return 0;

}


int XmGetEthAttr(const char *ifname, AddrType_e type, char* out)
{
	struct netif    *pst_lwip_netif = NULL;

	struct in_addr ip_addr;
	struct in_addr mask_addr;
	struct in_addr gateway_addr;
	char hw_addr[32] = {0};	
	
	pst_lwip_netif = netif_find(ifname);
	if (HISI_NULL == pst_lwip_netif)
	{
		printf("[%s]: get <struct netif> info error.\n", __FUNCTION__);
		return -1;
	}

	if(type == IP_ADDR)
	{
		ip_addr.s_addr = pst_lwip_netif->ip_addr.addr;
		memcpy(out, inet_ntoa(ip_addr), 15);
		printf("get IpAddr success: %s\n", out);
	}
	else if(type == NETMASK_ADDR)
	{
		mask_addr.s_addr = pst_lwip_netif->netmask.addr;
		strcpy(out, inet_ntoa(mask_addr));
		printf("get NetmaskAddr success: %s\n", out);
	}
	else if(type == GATEWAY_ADDR)
	{
		gateway_addr.s_addr = pst_lwip_netif->gw.addr;
		strcpy(out, inet_ntoa(gateway_addr));
		printf("get  GatewayAddr success: %s\n", out);
		
	}
	else if(type == HW_ADDR)
	{
		if(!XmGetHwAttr(ifname, type, hw_addr))
		{
			
			memcpy(out, hw_addr, 6);
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



int XmSetEthAttr(const char *ifname, AddrType_e type, const char *str)
{
	ip_addr_t        st_gw;
	ip_addr_t        st_ipaddr;
	ip_addr_t        st_netmask;

	char hw_addr[32] = {0};
	
	
	struct netif    *pst_lwip_netif = NULL;

	pst_lwip_netif = netif_find("wlan0");
	if (HISI_NULL == pst_lwip_netif)
	{
		printf("cmd_start_hapd::Null param of netdev.\n");
		return -1;
	}

	
	
	if(type == IP_ADDR)
	{
		st_ipaddr.addr = inet_addr(str);
		netif_set_ipaddr(pst_lwip_netif, &st_ipaddr);
		printf("set IpAddr success: %s\n", str);
	}
	else if(type == NETMASK_ADDR)
	{
		st_netmask.addr = inet_addr(str);
		netif_set_netmask(pst_lwip_netif, &st_netmask);
		printf("set NetmaskAddr success: %s\n", str);
	}
	else if(type == GATEWAY_ADDR)
	{
		st_gw.addr = inet_addr(str);
		netif_set_gw(pst_lwip_netif, &st_gw);	
		printf("set GatewayAddr success: %s\n", str);
	}
	else if(type == HW_ADDR)
	{
		sscanf(str,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&hw_addr[0],&hw_addr[1],&hw_addr[2],
												&hw_addr[3], &hw_addr[4], 	&hw_addr[5]);
		
		netif_set_hwaddr(pst_lwip_netif, hw_addr, 6);
		printf("set HwAddr success: %s\n", str);

	}
	else
	{
		printf("the type is error.please input 0~3.\n");
		return -1;
	}

	netif_set_up(pst_lwip_netif);
	
	return 0;
}




static int XmSetStaticAddr(const char * ip)
{	
	ip_addr_t        st_gw;
	ip_addr_t        st_ipaddr;
	ip_addr_t        st_netmask;
	unsigned int ipaddr = 0;

	struct netif    *pst_lwip_netif = NULL;

	pst_lwip_netif = netif_find("wlan0");
	if (HISI_NULL == pst_lwip_netif)
	{
		printf("cmd_start_hapd::Null param of netdev.\n");
		return -1;
	}
	
	st_ipaddr.addr = inet_addr(ip);
	st_netmask.addr = inet_addr("255.255.255.0");
	st_gw.addr = inet_addr("172.25.123.2");

	netif_set_up(pst_lwip_netif);
		
	netif_set_addr(pst_lwip_netif,&st_ipaddr,&st_netmask,&st_gw);

	hisi_wlan_ip_notify_intf(ipaddr, DHCP_IP_SET);
	extern struct completion g_dhcp_complet;
	complete_all(&g_dhcp_complet);
	g_wpa_supplicant_had_connect = 1;

	printf("\033[32mset static ip success..\033[0m\n");


	return 1;

}

int XmSetStaticIp(int type)
{
	int ret = 0;
	unsigned char mac[6] = {0};
	unsigned char randomIp[18] = {0};
	unsigned int random = 0, i = 0;
	unsigned char *puc_macaddr = NULL;

	if(type)
		return -1;
	
	puc_macaddr = hisi_wlan_get_macaddr();
	for(i=0;i<6;i++)
	{
		mac[i] = *(puc_macaddr+i);
	}
	
	
	random = mac[5]%248+3;
	snprintf(randomIp, 15,  "172.25.123.%d", random);

	
	printf("get random ip [%s]\n", randomIp);
	

	ret = XmSetStaticAddr(randomIp);



	return ret;


}



int FileSimpleRead(const char * path,char *buf,int count)
{
	if (!path || !buf || count<=0)
		return -1;

	int fd = -1;	

	if ((fd=open(path,O_RDONLY))<0)
	{
		perror("open");
		return -1;
	}
	
	if (read(fd,buf,count)<=0)
	{
		perror("read");
		close(fd);
		return -1;
	}

	close(fd);

	return 0;

}

int FileSimpleWrite(const char * path,const char *buf,int count)
{
	if (!path || !buf || count<=0)
		return -1;

	int fd = -1;	

	if ((fd=open(path,O_WRONLY|O_CREAT))<0)
	{
		perror("open");
		return -1;
	}
	
	if (write(fd,buf,count)!=count)
	{
		perror("write");
		close(fd);
		return -1;
	}

	close(fd);

	return 0;
}



int Read_Config_File(const char *path, FileParam_s *rFileParam)
{
	char line[256] = {0};
	char buf_type[16] = {0}; 
	FILE *fp = NULL;
	char *p = NULL;
	int len = -1;
	int type = 0;

	memset(rFileParam, 0, sizeof(rFileParam));

	if(path == NULL)
	{
		return -1;
	}

	p = strstr(path, "sleep");
	if(p != NULL)
	{
		type = 1;
	}
			
	if ((fp = fopen(path,"r+")) == NULL)
	{
		printf("open file %s fail!\n",path);
		return -1;
	}
	
	while (fgets(line, sizeof(line), fp))
	{
		p = strstr(line, "ssid=");		
		if (p != NULL)
		{			
			p += strlen("ssid=");
			p[strlen(p)-1] = 0;
			strcpy(rFileParam->ssid, p);			
		}

		p = strstr(line, "authType=");
		if (p != NULL)
		{			
			p += strlen("authType=");
			p[strlen(p)-1] = 0;
			rFileParam->authType = atoi(p);
		}

		p = strstr(line, "wlanFlag=");
		if(p != NULL)
		{
			p += strlen("wlanFlag=");
			p[strlen(p)-1] = 0;
			rFileParam->wlanFlag = atoi(p);
		}

		p = strstr(line, "pirInfo=");		
		if (p != NULL)
		{			
			p += strlen("pirInfo");
			p[strlen(p)-1] = 0;
			strcpy(rFileParam->pirInfo, p);			
		}
		
	}
	fclose(fp);
	return 0;
}


int Write_Config_File(const char *path, FileParam_s fileParam)
{																		
	FILE *fp = NULL;

	char *p = NULL;
	char buf[256] = {0};
	char buf_type[16] = {0};
	int type = 0;

	if(path == NULL)
	{	
		return -1;
	}

	p = strstr(path, "sleep");
	if(p != NULL)
	{
		type = 1;
	}
	
	if ((fp = fopen(path,"w+")) == NULL)	 
	{
		printf("fopen file error.%d:	%s\n", errno, strerror(errno));
		
	}
	
	memset(buf, 0, sizeof(buf));

	if(type)
	{
		snprintf(buf, 256, "ssid=%s\nwlanFlag=%d\npirInfo=%s\n", fileParam.ssid, fileParam.wlanFlag, fileParam.pirInfo);
	}
	else
	{
		snprintf(buf, 256, "ssid=%s\nauthType=%d\n", fileParam.ssid, fileParam.authType);
	}
	
				
	fprintf(fp, "%s", buf);

	//printf("write info is :\n%s\n", buf);
	
	fclose(fp);
	
	
	return 0;
}

int XmLogInfoWrite(bool state, const char *reason)
{
	FILE *fp = NULL;
	int times = 0;
	char *p = NULL;
	char line[256] = {0};
	char timeStr[60] = {0};
	char weekday[15] = {0};

	McuInfo_s rmcuInfo;

	if ((fp = fopen(LOGGER_CONF,"a+")) == NULL)	 
	{
		printf("fopen file error.%d:	%s\n", errno, strerror(errno));
		
	}

	fseek(fp, -64L, SEEK_END);
	while (fgets(line, sizeof(line), fp))
	{
		p = strstr(line, "Times:");
		if(p != NULL)
		{
			p += strlen("Times:");
			times = atoi(p);
		}
	}
	fseek(fp, 0, SEEK_END);
	times ++;
	printf("times:[%d]\n", times);

	//获取单片机rtc时间值
	XmMcuInfoGet(0x3, &rmcuInfo);
	NumToDate(rmcuInfo.timeInfo.wday, weekday);
	
	snprintf(timeStr, sizeof(timeStr), "[%04d-%02d-%02d %02d:%02d:%02d %-15s]", rmcuInfo.timeInfo.year, rmcuInfo.timeInfo.month, rmcuInfo.timeInfo.day,
											rmcuInfo.timeInfo.hour, rmcuInfo.timeInfo.minute, rmcuInfo.timeInfo.second, weekday);
	//printf("timeStr:%s\n", timeStr);
	
	memset(line, 0, sizeof(line));
	if(state == POWER_UP)
		snprintf(line, 256, "\n%s%-10s-------[Reason:%-30s]-------Times:%04d", timeStr, "Power Up", reason, times);
	else if(state == POWER_DOWN)
		snprintf(line, 256, "\n%s%-10s-------[Reason:%-30s]-------[Heart:%04d]Times:%04d", timeStr, "Power Down", reason, g_heartime, times);
	
	fprintf(fp, "%s", line);

	fclose(fp);

	return 0;
}


int Get_File_Value(const char * filename, const char *src, char *out)
{
	FILE *fpSrc = NULL;
	char *p = NULL;
	
	char line[128] = {0};
	
	
	if((fpSrc=fopen(filename,"r"))==NULL)  
    {  
        printf("fail to open %s\n", filename);  
       return -1;   
    }  

	while(fgets(line,128,fpSrc) != NULL)
	{
		p = strstr(line, src);  
		if(p != NULL)
		{
			strcpy(out, p+strlen(src));
			//printf("the out is 	%s\n", out);
		}
		
	}


	return 0;
}



int send_Gratuitous_Arps(const char* device_name)
{
	char ip[4] = {0};
	
	int sock = -1, optval = 1;	

	struct sockaddr_ll peer_addr;
	struct arpMsg	 arp;	/* arp message */

	unsigned long src_ip = 0;
	XmGetEthAttr(device_name, IP_ADDR, ip);
	src_ip = inet_addr(ip);	

	unsigned long dst_ip = src_ip;
	
	unsigned char dst_mac_hdr[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	unsigned char dst_mac[6] = {0x0,0x0,0x0,0x0,0x0,0x0};
	
	unsigned char src_mac[6] = {0};
	XmGetEthAttr(device_name, HW_ADDR, src_mac);

	
	//创建socket
	if((sock = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1)
	{
		printf("socket error\n");
		return -1;
	}
	
	struct ifreq req;  
	memset(&req, 0,  sizeof(struct ifreq));  
	strcpy(req.ifr_name, device_name);    
	if(ioctl(sock, SIOCGIFINDEX, &req) != 0)
	{
		perror("ioctl()");    
	}
		
	memset(&peer_addr, 0, sizeof(peer_addr));    
	peer_addr.sll_family = AF_PACKET;  	
	peer_addr.sll_ifindex = req.ifr_ifindex;    
	peer_addr.sll_protocol = htons(ETH_P_ARP);  

	if(bind(sock, (struct sockaddr *) &peer_addr, sizeof(peer_addr)) != 0)
	{
		perror("bind");
	}

	//构建arp包
	

	memset(&arp, 0,  sizeof(arp));
	memcpy((char *)arp.ethhdr.h_dest, (char *)dst_mac_hdr, 6);
	memcpy((char *)arp.ethhdr.h_source, (char *)src_mac, 6);
	
	arp.ethhdr.h_proto = htons(ETH_P_ARP);		/* protocol type (Ethernet) */
	arp.htype = htons(ARPHRD_ETHER);						/* hardware type */
	arp.ptype = htons(ETH_P_IP);				/* protocol type (ARP message) */
	arp.hlen = 6;								/* hardware address length */
	arp.plen = 4;								/* protocol address length */
	arp.operation = htons(ARPOP_REQUEST);				/* ARP op code */

	memcpy((char *)arp.sInaddr, (char *)&src_ip, 4);			/* source IP address */
	memcpy((char *)arp.sHaddr, (char *)src_mac, 6);
	memcpy((char *)arp.tHaddr, (char *)dst_mac, 6);
	memcpy((char *)arp.tInaddr, (char *)&dst_ip, 4);


	//打印arp包地址
/*
	printf("the dst hdr mac is %x %x %x %x %x %x\n", arp.ethhdr.h_dest[0], arp.ethhdr.h_dest[1], arp.ethhdr.h_dest[2],
											arp.ethhdr.h_dest[3],arp.ethhdr.h_dest[4],arp.ethhdr.h_dest[5]);
	printf("the src hdr mac is %x %x %x %x %x %x\n\n", arp.ethhdr.h_source[0], arp.ethhdr.h_source[1], arp.ethhdr.h_source[2],
											arp.ethhdr.h_source[3],arp.ethhdr.h_source[4],arp.ethhdr.h_source[5]);
	
	printf("the src mac is %x %x %x %x %x %x\n", arp.sHaddr[0], arp.sHaddr[1], arp.sHaddr[2],
											arp.sHaddr[3],arp.sHaddr[4],arp.sHaddr[5]);
	printf("the src ip is %hhu %hhu %hhu %hhu\n", arp.sInaddr[0], arp.sInaddr[1], arp.sInaddr[2], arp.sInaddr[3]);
	printf("the dst mac is %x %x %x %x %x %x\n", arp.tHaddr[0], arp.tHaddr[1], arp.tHaddr[2],
											arp.tHaddr[3],arp.tHaddr[4],arp.tHaddr[5]);
	printf("the dst ip is %hhu %hhu %hhu %hhu\n", arp.tInaddr[0], arp.tInaddr[1], arp.tInaddr[2], arp.tInaddr[3]);
*/

	//发送arp包	

	if (sendto(sock, &arp, sizeof(arp), 0, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0 )
	{
		printf("sendto arp wrong");
		close(sock);
		return -1;
	}
	else
	{

		printf("send success..\n");

	}

	close(sock);

	return 0;

}

int send_Gratuitous_Arps_test(int type, ArpAddr_s *arpaddr, int boo)
{
	
	
	int sock = -1, optval = 1;	

	struct sockaddr_ll peer_addr;
	struct arpMsg	 arp;	/* arp message */

	unsigned long src_ip = 0;
	unsigned long dst_ip = 0;
	
	src_ip = inet_addr(arpaddr->src_ip);
	dst_ip = inet_addr(arpaddr->dst_ip);

	

	//创建socket
	if((sock = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1)
	{
		printf("socket error\n");
		return -1;
	}
	
	struct ifreq req;  
	memset(&req, 0,  sizeof(struct ifreq));  
	strcpy(req.ifr_name, "wlan0");    
	if(ioctl(sock, SIOCGIFINDEX, &req) != 0)
	{
		perror("ioctl()");    
	}
	//printf("the index is %d\n", req.ifr_ifindex);
		
	memset(&peer_addr, 0, sizeof(peer_addr));    
	peer_addr.sll_family = AF_PACKET;  	
	peer_addr.sll_ifindex = req.ifr_ifindex;    
	peer_addr.sll_protocol = htons(ETH_P_ARP);  

	if(bind(sock, (struct sockaddr *) &peer_addr, sizeof(peer_addr)) != 0)
	{
		perror("bind");
	}

	//构建arp包
	

	memset(&arp, 0,  sizeof(arp));
	memcpy(arp.ethhdr.h_dest, arpaddr->dst_mac_hdr, 6);
	memcpy(arp.ethhdr.h_source, arpaddr->src_mac_hdr, 6);
	
	arp.ethhdr.h_proto = htons(ETH_P_ARP);		/* protocol type (Ethernet) */
	arp.htype = htons(ARPHRD_ETHER);						/* hardware type */
	arp.ptype = htons(ETH_P_IP);				/* protocol type (ARP message) */
	arp.hlen = 6;								/* hardware address length */
	arp.plen = 4;								/* protocol address length */
	arp.operation = htons(type);				/* ARP op code */

	memcpy(arp.sInaddr, (char *)&src_ip, 4);			/* source IP address */
	memcpy(arp.sHaddr, arpaddr->src_mac, 6);
	memcpy(arp.tHaddr, arpaddr->dst_mac, 6);
	memcpy(arp.tInaddr, (char *)&dst_ip, 4);


	//打印arp包地址

	if(boo)
	{		
		printf("the dst hdr mac is %02x %02x %02x %02x %02x %02x\n", arp.ethhdr.h_dest[0], arp.ethhdr.h_dest[1], arp.ethhdr.h_dest[2],
												arp.ethhdr.h_dest[3],arp.ethhdr.h_dest[4],arp.ethhdr.h_dest[5]);
		printf("the src hdr mac is %02x %02x %02x %02x %02x %02x\n\n", arp.ethhdr.h_source[0], arp.ethhdr.h_source[1], arp.ethhdr.h_source[2],
												arp.ethhdr.h_source[3],arp.ethhdr.h_source[4],arp.ethhdr.h_source[5]);
		
		printf("the src mac is %02x %02x %02x %02x %02x %02x\n", arp.sHaddr[0], arp.sHaddr[1], arp.sHaddr[2],
												arp.sHaddr[3],arp.sHaddr[4],arp.sHaddr[5]);
		printf("the src ip is %hhu %hhu %hhu %hhu\n", arp.sInaddr[0], arp.sInaddr[1], arp.sInaddr[2], arp.sInaddr[3]);
		printf("the dst mac is %02x %02x %02x %02x %02x %02x\n", arp.tHaddr[0], arp.tHaddr[1], arp.tHaddr[2],
												arp.tHaddr[3],arp.tHaddr[4],arp.tHaddr[5]);
		printf("the dst ip is %hhu %hhu %hhu %hhu\n", arp.tInaddr[0], arp.tInaddr[1], arp.tInaddr[2], arp.tInaddr[3]);
	}
	

	//发送arp包	

	if (sendto(sock, &arp, sizeof(arp), 0, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0 )
	{
		printf("sendto arp wrong");
		close(sock);
		return -1;
	}
	else
	{

		printf("send success..\n");

	}

	close(sock);

	return 0;

}


static int createRandomIp(char* randomIp,int usedefault )
{
	char LanMac[12 + 1] = {0};
	unsigned int random;
	if(randomIp == NULL)
	{
		return -1;
	}
	memset(randomIp,0,32);
	
	XmGetHwAttr("wlan0", HW_ADDR, LanMac);
	if(usedefault == 1)
	{
		random = LanMac[5]%248+3;
		snprintf(randomIp, 14,  "172.25.123.%02d", random);
		
	}
	else if(usedefault == 0)
	{
		srand(time(0));	
		random = (rand()+LanMac[3]+LanMac[4]+LanMac[5])%248+3;
		
		snprintf(randomIp, 14, "172.25.123.%02d", random);
		
	}
	return 0;
}

int Wireless_Ipconfig(int set)
{

	char ip[32]={0};
	char netmask[32]={0};
	char gateway[32] = {0};
	int check_cnt = 20;
//	unsigned char mac[6]={0};
	do{
		if(set == 0)
		{
			if(!XmGetEthAttr("wlan0", IP_ADDR, ip))
			{
				if(( memcmp(ip,"172.25.123.",strlen("172.25.123.")) == 0))
				{
					createRandomIp(ip,1);//ip define by mac
				}
			}
			else
			{
				printf("set ip error");
				set = 1;
			}
		}
		if(set == 1){
			createRandomIp(ip,0);//ip is random based on mac
		}

		printf("the changed ip is %s.\n", ip);
		set = 1;
		if(check_cnt-- < 0){
			return -1;
		}
	}while(IsIpConflict("wlan0",ip) == 1);
	strcpy(netmask,"255.255.255.0");
	strcpy(gateway,"172.25.123.1");
	
	
	
	XmSetEthAttr("wlan0", IP_ADDR, ip);	
	XmSetEthAttr("wlan0", NETMASK_ADDR, netmask);
	XmSetEthAttr("wlan0", GATEWAY_ADDR, gateway);

	send_Gratuitous_Arps("wlan0");
	
	

	return 0;
}





static int send_arp(int sockfd, struct sockaddr_ll *peer_addr,unsigned char* dst_ip)  
{
	int rtval;  
	struct arpMsg arp;  
	unsigned char dst_mac_hdr[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	unsigned char dst_mac[6] = {0x0,0x0,0x0,0x0,0x0,0x0};
	
	unsigned char src_mac[12] = {0};
	if (XmGetEthAttr("wlan0", HW_ADDR, src_mac) != 0)
	{
		printf("Get HwAddr failed\n");
		return 0;
	}
	


	memset(&arp, 0,  sizeof(arp));
	memcpy((char *)arp.ethhdr.h_dest, (char *)dst_mac_hdr, 6);
	memcpy((char *)arp.ethhdr.h_source, (char *)src_mac, 6);
	arp.ethhdr.h_proto = htons(ETH_P_ARP);		/* protocol type (Ethernet) */
	
	arp.htype = htons(ARPHRD_ETHER);						/* hardware type */
	arp.ptype = htons(ETH_P_IP);				/* protocol type (ARP message) */
	arp.hlen = 6;								/* hardware address length */
	arp.plen = 4;								/* protocol address length */
	arp.operation = htons(ARPOP_REQUEST);				/* ARP op code */

	
	memcpy((char *)arp.sHaddr, (char *)src_mac, 6);
	memset(arp.sInaddr, 0, 4);			/* source IP address */
	memset(arp.tHaddr, 0, 6);
	memcpy((char *)arp.tInaddr, (char *)dst_ip, 4);
/*
	printf("the dst hdr mac is %x %x %x %x %x %x\n", arp.ethhdr.h_dest[0], arp.ethhdr.h_dest[1], arp.ethhdr.h_dest[2],
											arp.ethhdr.h_dest[3],arp.ethhdr.h_dest[4],arp.ethhdr.h_dest[5]);
	printf("the src hdr mac is %x %x %x %x %x %x\n\n", arp.ethhdr.h_source[0], arp.ethhdr.h_source[1], arp.ethhdr.h_source[2],
											arp.ethhdr.h_source[3],arp.ethhdr.h_source[4],arp.ethhdr.h_source[5]);
	
	printf("the src mac is %x %x %x %x %x %x\n", arp.sHaddr[0], arp.sHaddr[1], arp.sHaddr[2],
											arp.sHaddr[3],arp.sHaddr[4],arp.sHaddr[5]);
	printf("the src ip is %hhu %hhu %hhu %hhu\n", arp.sInaddr[0], arp.sInaddr[1], arp.sInaddr[2], arp.sInaddr[3]);
	printf("the dst mac is %x %x %x %x %x %x\n", arp.tHaddr[0], arp.tHaddr[1], arp.tHaddr[2],
											arp.tHaddr[3],arp.tHaddr[4],arp.tHaddr[5]);
	printf("the dst ip is %hhu %hhu %hhu %hhu\n", arp.tInaddr[0], arp.tInaddr[1], arp.tInaddr[2], arp.tInaddr[3]);

*/	


	rtval = sendto(sockfd, &arp, sizeof(arp), 0,(struct sockaddr*)peer_addr, sizeof(struct sockaddr_ll));    
	if (rtval < 0) {  
		printf("send arp error");
		return -1;  
	} 
	return 0;  
}

static int recv_arp(int sockfd, struct sockaddr_ll *peer_addr,unsigned char* src_ip)  
{  
	int i = 0, ret = 0;
	int rtval;  
	struct arpMsg	 arp;  
	fd_set fdRead;
	struct timeval tv;

	FD_ZERO(&fdRead);
	FD_SET(sockfd,&fdRead);
	tv.tv_sec = 1;
   	tv.tv_usec = 0;
	ret = select(sockfd+1, &fdRead, NULL, NULL, &tv);
	if(ret<0)
	{
		printf("select error...\n");
		
		
	}
	else if (ret == 0 )
	{
		printf("select timeout\n");
		
	}

	printf("the FD_ISSET is %d.\n", FD_ISSET(sockfd, &fdRead));
	
	if(FD_ISSET(sockfd, &fdRead))
	{
		memset(&arp, 0, sizeof(arp));  
		rtval = recvfrom(sockfd, &arp, sizeof(arp), 0,NULL, NULL);  
		if (htons(ARPOP_REPLY) == arp.operation ) 
		{
			if(rtval > 0)
			{  				
				if (memcmp(arp.sInaddr, src_ip, 4) == 0)  
				{  
					printf( "IP address is common~\n");  
					for(i=0;i<sizeof(arp.ethhdr.h_source);i++)
						printf("%x ",arp.ethhdr.h_source[i]);
					printf("\n");
					return 0;  
				}  
			}  
		}
		
	}

	printf("not recv any info.\n");	
		
	
	return -1;  
}


int IsIpConflict(char* device , char* ip)  
{ 
	int sockfd;  
	int rtval = -1;  
	int check_cnt = 3;
	struct sockaddr_ll peer_addr;  
	unsigned char src_ip[4]={0};
	unsigned char dst_ip[4]={0};
	if(ip == NULL){
		printf("ip can't be null");
		return -1;
	}
	sscanf(ip,"%hhu.%hhu.%hhu.%hhu",&src_ip[0],&src_ip[1],&src_ip[2],&src_ip[3]);
	memcpy(dst_ip,src_ip,4);
	//printf("%hhu %hhu %hhu %hhu\n",src_ip[0],src_ip[1],src_ip[2],src_ip[3]);
	//printf("%hhu %hhu %hhu %hhu\n",dst_ip[0],dst_ip[1],dst_ip[2],dst_ip[3]);

	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));  
	if (sockfd < 0) 
	{  
		printf("sock error");
		return 0;
	} 
	

	memset(&peer_addr, 0, sizeof(peer_addr));    
	peer_addr.sll_family = AF_PACKET;    
	struct ifreq req;  
	memset(&req, 0,  sizeof(struct ifreq));  
	strcpy(req.ifr_name, device);    
	if(ioctl(sockfd, SIOCGIFINDEX, &req) != 0)
	{
		perror("ioctl()");    
		close(sockfd);
		return 0;
	}

	
	peer_addr.sll_ifindex = req.ifr_ifindex;    
	peer_addr.sll_protocol = htons(ETH_P_ARP);  

	if(bind(sockfd, (struct sockaddr *) &peer_addr, sizeof(peer_addr)) != 0)
	{
		perror("bind");
		close(sockfd);
		return 0;
	}

	
	while(check_cnt--) 
	{ 
		rtval = send_arp(sockfd, &peer_addr,dst_ip);  
		if ( rtval < 0) 
		{  
			printf("send arp error");
		}  

		rtval = recv_arp(sockfd, &peer_addr,src_ip);  
		if (rtval == 0) 
		{  
			printf ("Get packet from peer and IP conflicts!\n");  
			close(sockfd);
			return 1;
		} 
		else if (rtval < 0) 
		{  
			printf("Recv arp IP not conflicts: %s\n", strerror(errno));  
		} 
		else 
		{  
			printf("recv arp error");
		}  
	}  
	close(sockfd);
	return 0;  
}




void hapd_stop_xm(void)
{
	if (0 != hostapd_stop())
	{
	    printf("hostapd stop failed\n");
	    return;
	}
	else
	{
		Mux_Operate(&g_hostapd_had_run, 0);
	}
}



void wpa_stop_xm(void)
{
	int l_ret = 0;
	
	l_ret = wpa_supplicant_stop();
	if (l_ret != 0)
	{
		printf("cmd_wpa_stop fail.\n");
		return;
	}
	else
	{
		Mux_Operate(&g_wpa_supplicant_had_run, 0);
	}
}

void wap_start_xm(void)
{
	int uwRet = 0;
	
	if( g_wpa_supplicant_had_run != 1)
	{
		uwRet = wpa_supplicant_start("wlan0", "hisi", NULL);
		if(0 != uwRet)
		{
			printf("fail to start wpa_supplicant\n");
		}
		Mux_Operate(&g_wpa_supplicant_had_run, 1);
		
		hisi_wlan_enable_channel_14();		
		
	}

	return;
}


void wpa_disconnect_xm(void)
{
	int l_ret = 0;

	
	struct netif    *pst_lwip_netif = NULL;	

	pst_lwip_netif = netif_find("wlan0");
	
	if (HISI_NULL == pst_lwip_netif)
	{
		printf("netif_find error.\n");
		return ;
	}


	l_ret = wpa_cli_disconnect();	
	if (l_ret != 0)
	{
		printf("\ncmd_wpa_disconnect fail.\n");
	}
	else
	{
		printf("\ncmd_wpa_disconnect success\n");
	}

	
	
}








void set_wake_flag(void)
{	
	
	g_wake_event &=HISI_WOW_EVENT_ALL_CLEAR;		  		///* Clear all events */
	//g_wake_event |=HISI_WOW_EVENT_MAGIC_PACKET; 	  		///* Wakeup on Magic Packet */
	g_wake_event |=HISI_WOW_EVENT_NETPATTERN_TCP;			///* Wakeup on TCP NetPattern */
	g_wake_event |=HISI_WOW_EVENT_NETPATTERN_UDP;	  		//* Wakeup on UDP NetPattern */
	g_wake_event |=HISI_WOW_EVENT_DISASSOC; 		  		///* 去关联/去认证，Wakeup on Disassociation/Deauth */
	//g_wake_event |=HISI_WOW_EVENT_AUTH_RX;			  		///* 对端关联请求，Wakeup on auth */
	//g_wake_event |=HISI_WOW_EVENT_HOST_WAKEUP;		  	///* Host wakeup */
	g_wake_event |=HISI_WOW_EVENT_TCP_UDP_KEEP_ALIVE; 		///* Wakeup on TCP/UDP keep alive timeout */
	g_wake_event |=HISI_WOW_EVENT_OAM_LOG_WAKEUP;	  		///* OAM LOG wakeup */
	g_wake_event |=HISI_WOW_EVENT_SSID_WAKEUP;		  		///* SSID Scan wakeup */



	//printf("\033[33mthe g_wake_event is[0000%02x%02x]\033[0m\n", (g_wake_event >> 8),(g_wake_event & 0xff));
	
	hisi_wlan_set_wow_event(g_wake_event);

	return;
}

void Host_Sleep_Conf_Handle(bool state)
{
	FileParam_s rFileParam;
	FileParam_s wFileParam;
	memset(&wFileParam, 0, sizeof(wFileParam));
	


	printf("\033[32m*****************************SAVE SLEEP CONF START***********************\033[0m\n");
	
	if(access(CONNNECTED_SLEEP_FLAG, F_OK) != 0)
	{	
		printf("[%s] Not Exist\n");
		
		strncpy(wFileParam.ssid, g_IpcRuningData.WifiNvrInfo.ssid, strlen(g_IpcRuningData.WifiNvrInfo.ssid));
		strncpy(wFileParam.pirInfo, g_IpcRuningData.pirInfo, strlen(g_IpcRuningData.pirInfo));
		wFileParam.wlanFlag = g_wpa_supplicant_had_connect;
		printf("First Save..............................................\nssid[%s] wlanFlag[%d] pirInfo<%s>\n", wFileParam.ssid, wFileParam.wlanFlag, wFileParam.pirInfo);
		
		Write_Config_File(CONNNECTED_SLEEP_FLAG, wFileParam);
	}
	else
	{
		printf("[%s]  Exist\n", CONNNECTED_SLEEP_FLAG);
		Read_Config_File(CONNNECTED_SLEEP_FLAG, &rFileParam);
		

		strncpy(wFileParam.ssid, g_IpcRuningData.WifiNvrInfo.ssid, strlen(g_IpcRuningData.WifiNvrInfo.ssid));
		strncpy(wFileParam.pirInfo, g_IpcRuningData.pirInfo, strlen(g_IpcRuningData.pirInfo));
		wFileParam.wlanFlag = g_wpa_supplicant_had_connect;

		printf("ssid[%-33s] wlaFlag[%d] pirInfo[%-60s] Last\n", rFileParam.ssid, rFileParam.wlanFlag, rFileParam.pirInfo);
		printf("ssid[%-33s] wlaFlag[%d] pirInfo[%-60s] Now\n", wFileParam.ssid, wFileParam.wlanFlag, wFileParam.pirInfo);
		
		if((memcmp(rFileParam.ssid, wFileParam.ssid, strlen(rFileParam.ssid)) != 0) ||(rFileParam.wlanFlag != wFileParam.wlanFlag)
											||(memcmp(rFileParam.pirInfo, wFileParam.pirInfo, strlen(rFileParam.pirInfo)) != 0))
		{
			printf("param not same, begin to Save.....................................\n");
			Write_Config_File(CONNNECTED_SLEEP_FLAG, wFileParam);
		}
		else
			printf("param same, not Save.........................\n");
	}

	if(state == 0)
	{
		Read_Config_File(CONNNECTED_NVR_CONF, &rFileParam);
		printf("\033[33mSet Sleep SSID To Wake:[%s]", rFileParam.ssid );
		hisi_wlan_set_wakeup_ssid(rFileParam.ssid);
	}

	printf("\033[32m*****************************SAVE SLEEP CONF END***********************\033[0m\n");

	return;
}

int Host_Wake_PirSet(void)
{
	PirSetInfo_s pirSet;
	FileParam_s rFileParam;
	PirDNDModeList_s dndlist;
	SYSTEM_TIME systemTime[4];

	memset(&dndlist, 0, sizeof(dndlist));
	memset(&systemTime, 0, sizeof(systemTime));
	memset(&pirSet, 0, sizeof(pirSet));
	pirSet.delayTime = 5;
	
	if(access(CONNNECTED_SLEEP_FLAG, F_OK) != 0)
	{
		strcpy(g_IpcRuningData.pirInfo, "[00:00:00-00:00:00]&[00:00:00-00:00:00]&[00:00]");
		sscanf("[00:00:00-00:00:00]&[00:00:00-00:00:00]&[00:00]", "[%hhd:%hhd:%hhd-%hhd:%hhd:%hhd]&[%hhd:%hhd:%hhd-%hhd:%hhd:%hhd]&[%hhd:%hhd]",
						&systemTime[0].hour, &systemTime[0].minute, &systemTime[0].second, &systemTime[1].hour, &systemTime[1].minute, &systemTime[1].second,
						&systemTime[2].hour, &systemTime[2].minute, &systemTime[2].second, &systemTime[3].hour, &systemTime[3].minute, &systemTime[3].second,
						&pirSet.enSwitch, &pirSet.checkTime);
	}
	else
	{
		Read_Config_File(CONNNECTED_SLEEP_FLAG, &rFileParam);
		strcpy(g_IpcRuningData.pirInfo, rFileParam.pirInfo);
		sscanf(rFileParam.pirInfo, "[%hhd:%hhd:%hhd-%hhd:%hhd:%hhd]&[%hhd:%hhd:%hhd-%hhd:%hhd:%hhd]&[%hhd:%hhd]",
						&systemTime[0].hour, &systemTime[0].minute, &systemTime[0].second, &systemTime[1].hour, &systemTime[1].minute, &systemTime[1].second,
						&systemTime[2].hour, &systemTime[2].minute, &systemTime[2].second, &systemTime[3].hour, &systemTime[3].minute, &systemTime[3].second,
						&pirSet.enSwitch, &pirSet.checkTime);
	}

	if((systemTime[0].hour + systemTime[0].minute + systemTime[0].second + systemTime[1].hour + systemTime[1].minute + systemTime[1].second) != 0)
		dndlist.pirMode[0].weekDayEn = 0xff;
	if((systemTime[2].hour + systemTime[2].minute + systemTime[2].second + systemTime[3].hour + systemTime[3].minute + systemTime[3].second) != 0)
		dndlist.pirMode[1].weekDayEn = 0xff;
	dndlist.pirMode[0].pStartTime = &systemTime[0];
	dndlist.pirMode[0].pEndTime = &systemTime[1];
	dndlist.pirMode[1].pStartTime = &systemTime[2];
	dndlist.pirMode[1].pEndTime = &systemTime[3];

	HI_HAL_MCUHOST_Set_PIR_Time(pirSet.enSwitch, &pirSet.delayTime);
	HI_HAL_MCUHOST_Set_PIR_CheckTime(&pirSet.checkTime);
	HI_HAL_MCUHOST_Pir_DNDMode_Config(&dndlist);

	return 0;
}



void Host_Wake_RtcSet(int times)
{	

	char dst[10] = {0};
	

	SYSTEM_TIME SetTime;
	McuInfo_s mcuInfo;

	XmMcuInfoGet(0x3, &mcuInfo);

	memset(&SetTime, 0, sizeof(SetTime));
	SetTime.year = mcuInfo.timeInfo.year;
	SetTime.month =mcuInfo.timeInfo.month;
	SetTime.day = mcuInfo.timeInfo.day;
	SetTime.hour = mcuInfo.timeInfo.hour;
	SetTime.minute = mcuInfo.timeInfo.minute + (mcuInfo.timeInfo.second + times)/60;
	SetTime.second = (mcuInfo.timeInfo.second + times)%60;
	SetTime.wday = mcuInfo.timeInfo.wday;
	SetTime.isdst = mcuInfo.timeInfo.isdst;

	NumToDate(SetTime.wday, dst);

	printf("mcu now time is:	[%d-%d-%d	%d:%d:%d	%s]\n", mcuInfo.timeInfo.year, mcuInfo.timeInfo.month, mcuInfo.timeInfo.day, mcuInfo.timeInfo.hour,
																			mcuInfo.timeInfo.minute, mcuInfo.timeInfo.second, dst);
	printf("mcu set time is:	[%d-%d-%d	%d:%d:%d	%s]\n", SetTime.year, SetTime.month, SetTime.day, SetTime.hour, SetTime.minute, 
													SetTime.second, dst);
	
	
	HI_HAL_MCUHOST_Set_Wakeup_Time(1, 4, &SetTime, 1);

	

	XmSuspendByWlan("rtc time suspend");

	
	return;
}


int wlan_wpaSupplicant_connect(const char * ssid, const char *psk )
{
	int uwRet = 0;
	struct wpa_assoc_request wpa_assoc_req;
	
	//开始连接指定热点
	memset(&wpa_assoc_req , 0 ,sizeof(struct wpa_assoc_request));

	//get hidden_ssid
	wpa_assoc_req.hidden_ssid=0;

	//get ssid	
	strncpy(wpa_assoc_req.ssid,ssid, strlen(ssid));	

	//get auth_type
	wpa_assoc_req.auth = WPA_SECURITY_WPA2PSK;

	//get key	
	strcpy(wpa_assoc_req.key, psk);

		
	uwRet = wpa_cli_connect(&wpa_assoc_req);
	if(uwRet == 0)
	{
		printf("wpa_cli_connect success.\n");
		
		uwRet = wait_for_completion_timeout(&g_dhcp_complet, LOS_MS2Tick(40000));//40s超时
		if (0 == uwRet)
		{
			printf("can not  get ip\n");
			return -1;
		}
		else
		{
			printf("success get ip\n");
			
		}
	}
	else
	{
		printf("wpa_cli_connect error.\n");
		return -1;
	}

	return 0;

}

int led_flash_one(void)
{
	char ledstate[6] = {0};

	ledstate[0] = 1;
	HI_HAL_MCUHOST_LedState_Control(ledstate);
	usleep(1000*500);
	ledstate[0] = 0;
	HI_HAL_MCUHOST_LedState_Control(ledstate);
	usleep(1000*500);

	return 0;

}



int hicap_capture_stop(void)
{
	int ret = 0;
	int VpssGrp = 0;
	int exChn = 5;
	
	ret = HiCap_CaptureYUVStop(VpssGrp, exChn);
	if (0 != ret)
	{
		printf("HiCap_CaptureYUVStop error\n");
		return -1 ;
	}

	return 0;

}


#if 1
static void XmImageToFile(const char *pbuf, const char *name)
{
	int fpfp = -1, wret = -1;
	int buf1 = 0;
	if ((fpfp = open(name, O_RDWR|O_CREAT)) < 0)
	{
		printf("open file error.\n");

		return;
	}

	buf1 = FRAME_WIDTH * FRAME_HEIGHT;

	wret = write(fpfp, pbuf, buf1);
	if(wret  != buf1)
	{
		printf("write file error.\n");

		return;
	}

	close(fpfp);

	return;
}


int imageNum = 0;
zbar_image_scanner_t *pscanner = NULL;

int xmAnalyzeQRData(char * pdate)
{
	char *p = NULL;
	char sta_ssid[33] = {0};
	char sta_psk[20] = {0};
	char sta_ip[16] = {0};
	char ap_ssid[33] = {0};
	char ip[20] = {0};
	char gateway[20] = {0};
	char netmask[20] = {0};

	int channel = 0;
	int i = 0, len = 0;

	printf("\033[33mhad QR date!!!!!!\033[0m\n");
	
	if(memcmp(pdate, "A:", 2) == 0)
	{
		p = pdate + 2;
		for(i=0;i<2;i++)	
		{		
			for(len = 0; len< 128;len++)		
			{			
				if( (*(p+len) == '\0') || (*(p+len) == '\n') || (*(p+len) == ':') )			
				{
					if(i == 0)
					{
						strncpy(ap_ssid,p,len);
					}
					else if(i == 1)
					{
						channel = atoi(p);
					}
					
					p = p +len +1;				
									
					break;			
				}					
			}
		}

		printf("AP:ssid[%s]	channel[%d]\n", ap_ssid, channel);
		
	}
	else if(memcmp(pdate, "W:", 2) == 0)
	{
		p = pdate +2;
		for(i=0;i<3;i++)	
		{		
			for(len = 0; len< 128;len++)		
			{			
				if( (*(p+len) == '\0') || (*(p+len) == '\n') || (*(p+len) == ':') )			
				{
					if(i == 0)
					{
						strncpy(sta_ssid,p,len);
					}
					else if(i == 1)
					{
						strncpy(sta_psk, p, len);
					}
					else if(i == 2)
					{
						strncpy(sta_ip, p, len);

					}
					p = p +len +1;				
									
					break;			
				}					
			}			
		}
		
		printf("ssid[%s]	psk[%s]	ip[%s]\n", sta_ssid, sta_psk, sta_ip);

		wlan_wpaSupplicant_connect(sta_ssid, sta_psk);
		if(g_wpa_supplicant_had_connect)
		{
			XmGetEthAttr("wlan0", IP_ADDR, ip);
			usleep(1000*50);
			XmSetEthAttr("wlan0", IP_ADDR, sta_ip);
		}
		
	}
	else if(memcmp(pdate, "N:", 2) == 0)
	{
		p = pdate + 2;
		for(len = 0; len< 128;len++)		
		{			
			if( (*(p+len) == '\0') || (*(p+len) == '\n') || (*(p+len) == ':') )			
			{				
				strncpy(sta_ssid,p,len);				
				break;			
			}					
		}

		printf("ssid[%s]\\n", sta_ssid);
	}

	p = NULL;

	return 0;
}


int xmYuvCallBack1(long lYuvHandle, char* pBuffer, int nBufLen)
{
	int ret = -1, n = 0;

	char *dateAddr = NULL;

	dateAddr = malloc(FRAME_WIDTH*FRAME_HEIGHT*sizeof(char));

	memcpy(dateAddr, pBuffer, FRAME_WIDTH*FRAME_HEIGHT);

	printf("the Handle is %d.		pBuffer is %x.	buflen is %d\n", lYuvHandle, pBuffer, nBufLen);


	
	zbar_image_t *image = NULL;
	
	pscanner = zbar_image_scanner_create();
	
	zbar_image_scanner_set_config(pscanner, 0, ZBAR_CFG_ENABLE, 1);
	image = zbar_image_create();
	
	zbar_image_set_size(image, FRAME_WIDTH, FRAME_HEIGHT);

	image->data = (void*)dateAddr; 
	zbar_image_set_format(image, fourcc('Y', '8', '0', '0'));

	
	
	zbar_image_set_data(image, image->data, FRAME_WIDTH*FRAME_HEIGHT, NULL);

	
	n = zbar_scan_image(pscanner, image);
	if(n > 0)
	{
		printf("scan_image success..\n");
		const zbar_symbol_t *symbol = zbar_image_first_symbol(image);

		for(; symbol; symbol = zbar_symbol_next(symbol))
		{
			/* do something useful with results */
			zbar_symbol_type_t typ = zbar_symbol_get_type(symbol);
			const char *data = zbar_symbol_get_data(symbol);
			printf("decoded %s symbol \"%s\"\n", zbar_get_symbol_name(typ), data);
			g_QrBarcodeState.barState = BAR_RESULT_YES;
			memcpy(g_QrBarcodeState.barResult, data, strlen(data));
		}
	}
	else
	{
		printf("scan_image failed..\n");
	}

	

	zbar_image_destroy(image);
	zbar_image_scanner_destroy(pscanner);
	free(dateAddr);

	
	
	usleep(1000*1000);

	return ret;
}


int xmYuvCallBack(long lYuvHandle, char* pBuffer, int nBufLen)
{
	int ret = -1, n = 0;

	char *dateAddr = NULL;

	dateAddr = malloc(FRAME_WIDTH*FRAME_HEIGHT*sizeof(char));

	memcpy(dateAddr, pBuffer, FRAME_WIDTH*FRAME_HEIGHT);

	printf("the Handle is %d.		pBuffer is %x.	buflen is %d\n", lYuvHandle, pBuffer, nBufLen);

	
	#if 0
	char filename[60] = "/mnt/sd0/frame.yuv";
	sprintf(filename, "/mnt/sd0/frame%d.yuv", imageNum);
	printf("the filename is [%s]\n", filename);
	XmImageToFile(dateAddr, filename);
	imageNum++;


	if(imageNum > 20)
	{
		hicap_capture_stop();
		imageNum = 0;
	}
	#endif

	
	zbar_image_t *image = NULL;
	
	pscanner = zbar_image_scanner_create();
	
	zbar_image_scanner_set_config(pscanner, 0, ZBAR_CFG_ENABLE, 1);
	image = zbar_image_create();
	
	zbar_image_set_size(image, FRAME_WIDTH, FRAME_HEIGHT);

	image->data = (void*)dateAddr; 
	zbar_image_set_format(image, fourcc('Y', '8', '0', '0'));

	
	
	zbar_image_set_data(image, image->data, FRAME_WIDTH*FRAME_HEIGHT, NULL);

	
	n = zbar_scan_image(pscanner, image);
	#if 0
	if(n > 0)
	{
		printf("scan_image success..\n");
		const zbar_symbol_t *symbol = zbar_image_first_symbol(image);

		for(; symbol; symbol = zbar_symbol_next(symbol))
		{
			/* do something useful with results */
			zbar_symbol_type_t typ = zbar_symbol_get_type(symbol);
			const char *data = zbar_symbol_get_data(symbol);
			printf("decoded %s symbol \"%s\"\n", zbar_get_symbol_name(typ), data);
			g_QrBarcodeState.barState = BAR_RESULT_YES;
			memcpy(g_QrBarcodeState.barResult, data, strlen(data));
		}
	}
	else
	{
		printf("scan_image failed..\n");
	}
	#endif

	

	zbar_image_destroy(image);
	zbar_image_scanner_destroy(pscanner);
	free(dateAddr);

	
	
	usleep(1000*1000);

	return ret;
}

int hicap_capture_start(void)
{
	int ret = 0;
	int VpssGrp = 0;
	int exChn = 5;	
	
	ret = HiCap_CaptureYUVStart(VpssGrp, exChn, FRAME_WIDTH, FRAME_HEIGHT, xmYuvCallBack);
	if (0 != ret)
	{
		printf("HiCap_CaptureYUVStart error\n");
		return -1 ;
	}

	printf("HiCap_CaptureYUVStart success\n");
	
	return 0;
}

#endif




void xm_wifiqueue_addrshow(Queue * wifiqueue)
{
	#if 0
	//printf("start		addr:	%x\n", wifiqueue); 
	//printf("buf  		addr:	%x\n", wifiqueue->buf);
	printf("buf_start	addr:	%x\n", wifiqueue->buf_start_point);
	printf("buf_end 	addr:	%x\n", wifiqueue->buf_end_point);
	printf("hand		addr:	%x\n", wifiqueue->head);
	printf("tail		addr:	%x\n", wifiqueue->tail);
	printf("res is: %d\n", wifiqueue->res);
	#endif
}


void xm_uarthandle_demo_build(void)
{
	prctl(15, (unsigned long)"-xm_uarthandle_demo_build");
	
	int i = 0, num = 0;
	int ret = -1;
	unsigned int date[2] = {0};
	unsigned char buf[256] = {0};
	unsigned char datebuf[6] = {0};
	unsigned char dst[10] = {0};
	Queue * wifiqueue = NULL;

	SYSTEM_TIME datetime;



	while(1)
	{
	
		if(g_force_sleep_flag)
		{
			XmSuspendByWlan("force suspend");
		}

	

		usleep(1000*1000);
	}

	
	
	return;
}

void xm_sendheart_demo_build(void)
{
	prctl(15, (unsigned long)"-xm_sendheart_demo_build");

	while(1)
	{
		Xm_KeepAlive_Set();
		usleep(1000*3000);
	}



	return;
}






static int xm_keepalive_demo_send_tcp_params(unsigned char uc_index)
{
	struct tcpip_conn    st_sockt_info;
	hisi_tcp_params_stru st_tcp_params;
	unsigned int         ul_ret;
	int                  l_ret;
	char                *pc_buf;
	unsigned char       *puc_src_ip;
	unsigned char       *puc_dst_ip;

	l_ret = lwip_get_conn_info(g_sockfd[uc_index], &st_sockt_info);
	if (0 > l_ret)
	{
		printf("%s:get sockt info fail",__func__);
		return -1;
	}
	
	
	/* 准备参数 */
	memcpy(st_tcp_params.auc_dst_mac,&st_sockt_info.dst_mac,6);
	st_tcp_params.ul_sess_id  = uc_index + 1;
	st_tcp_params.us_src_port = st_sockt_info.srcport;
	st_tcp_params.us_dst_port = st_sockt_info.dstport;
	st_tcp_params.ul_seq_num  = st_sockt_info.seqnum + 1;
	st_tcp_params.ul_ack_num  = st_sockt_info.acknum;
	st_tcp_params.us_window   = st_sockt_info.tcpwin;
	st_tcp_params.ul_interval_timer       = 6000;  //60秒发一次
	st_tcp_params.ul_retry_interval_timer = 200;
	st_tcp_params.us_retry_max_count      = 5;
	pc_buf = (char*)malloc(sizeof(char) * sizeof(KEEPALIVE_BUF1));
	memset(pc_buf, 0, sizeof(char) * sizeof(KEEPALIVE_BUF1));
	memcpy(pc_buf, KEEPALIVE_BUF1, sizeof(char) * sizeof(KEEPALIVE_BUF1));
	st_tcp_params.puc_tcp_payload         = pc_buf;
	st_tcp_params.ul_payload_len          = sizeof(KEEPALIVE_BUF1);
	puc_src_ip = st_tcp_params.auc_src_ip;
	puc_dst_ip = st_tcp_params.auc_dst_ip;
	puc_src_ip[0] = ip4_addr1((unsigned char*)&st_sockt_info.src_ip);
	puc_src_ip[1] = ip4_addr2((unsigned char*)&st_sockt_info.src_ip);
	puc_src_ip[2] = ip4_addr3((unsigned char*)&st_sockt_info.src_ip);
	puc_src_ip[3] = ip4_addr4((unsigned char*)&st_sockt_info.src_ip);
	puc_dst_ip[0] = ip4_addr1((unsigned char*)&st_sockt_info.dst_ip);
	puc_dst_ip[1] = ip4_addr2((unsigned char*)&st_sockt_info.dst_ip);
	puc_dst_ip[2] = ip4_addr3((unsigned char*)&st_sockt_info.dst_ip);
	puc_dst_ip[3] = ip4_addr4((unsigned char*)&st_sockt_info.dst_ip);
	printf("src_ip:%d.%d.%d.%d\n",puc_src_ip[0],puc_src_ip[1],puc_src_ip[2],puc_src_ip[3]);
	printf("dst_ip:%d.%d.%d.%d\n",puc_dst_ip[0],puc_dst_ip[1],puc_dst_ip[2],puc_dst_ip[3]);
	printf("src_port:%d\n",st_tcp_params.us_src_port);
	printf("dst_port:%d\n",st_tcp_params.us_dst_port);
	printf("ul_seq_num:%d\n",st_tcp_params.ul_seq_num);
	printf("ul_ack_num:%d\n",st_tcp_params.ul_ack_num);
	ul_ret = hisi_wlan_set_tcp_params(&st_tcp_params);
	if (0 != ul_ret)
	{
		HISI_PRINT_ERROR("%s:set tcp params fail",__func__);
		return -1;
	}
	return 0;
}



int xm_keepalive_demo_set_switch(int off_on, int num)
{
	unsigned char  uc_index;
	unsigned int   ul_ret;
	unsigned int   ul_keepalive_num;

	g_keepalive_switch = off_on;
	if(0 == g_keepalive_switch)
	{
		g_index = 0;
		ul_ret = hisi_wlan_set_keepalive_switch(HISI_KEEPALIVE_OFF, 0);
		if (0 != ul_ret)
		{
			printf("%s:set keepalive switch fail[%d]\n",__func__,ul_ret);
			return -1;
		}
	}
	else
	{
		for(uc_index = 0; uc_index < g_index; uc_index++)
		{
			xm_keepalive_demo_send_tcp_params(uc_index);
		}
		ul_keepalive_num = num;
		hisi_wlan_set_keepalive_switch(HISI_KEEPALIVE_ON, ul_keepalive_num);
		printf("%s:keepalive_switch=%d\n",__func__,g_keepalive_switch);
		return HISI_SUCC;
	}
	
}


int xm_keepalive_demo_build(void)
{
	int socketed = 0, times = 0;
	int type = -1;
	
	prctl(15, (unsigned long)"-xm_keepalive_demo_build");
	
	//函数中加锁，解锁后才会运行其它线程
	Mux_Operate_Lock();

	//配网过程
	while(1)
	{		
		if (WirelessPairing(WIRELESS_PAIRING))
		{
			break;
		}
			
		usleep(1000*1000);		
	}

	
	//唤醒后重新连接nvr服务器
	if(access(CONNNECTED_NVR_CONF, F_OK) != 0)
	{
		type = WIRELESS_PAIRING;
	}
	

	if(g_wpa_supplicant_had_sock != 1)
	{
		/*
		if (type == WIRELESS_PAIRING)
		{
			socketed = PairingWithNVR();
			if(socketed)
			{
				
			}
		}
		*/

		if ((memcmp(g_IpcRuningData.WifiNvrInfo.ssid, "WIFINVR_", 8) != 0) && (g_IpcRuningData.WifiNvrInfo.ssid[0] != 0)) //有线中继，跳过连接socket
		{
			int sockfd;

			
			while(times <10)
			{

				//printf("1....................\n");
				sockfd = ConnectNvrSocket(NVR_IP_ADDR);
				if(sockfd > 0)
				{
					printf("ConnectNvrSocket succeed\n");
					socketed = 1;
					
					break;
				}
				times++;
			}
			if (sockfd < 0)
			{
				printf("ConnectNvrSocket failed\n");
				socketed = 0;
			}
			
		}

	}

	//函数中解锁，运行其它线程
	Mux_Operate_Lock();
	
	if(g_wpa_supplicant_had_connect && g_wpa_supplicant_had_sock)
	{
		WirelessHeartbeat();

	}

	return 0;
	

}

int xm_sleep_demo_build(void)
{

	prctl(15, (unsigned long)"-xm_sleep_demo_build");
	
	int sockListen;  
	int set = 1;  
	struct  timeval tv;
	
	if((sockListen = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{  
		printf("socket fail\n");  
		return -1;  
	}  
	
	
	setsockopt(sockListen, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(int));  
	struct sockaddr_in recvAddr;  
	memset(&recvAddr, 0, sizeof(struct sockaddr_in));  
	recvAddr.sin_family = AF_INET;  
	recvAddr.sin_port = htons(BROADCAST_MONITOR_PORT);  
	recvAddr.sin_addr.s_addr = INADDR_ANY;  
	// 必须绑定，否则无法监听
	
	if(bind(sockListen, (struct sockaddr *)&recvAddr, sizeof(struct sockaddr)) == -1)
	{  
		printf("bind fail\n");  
		return -1;  
	}  

	tv.tv_sec = 5;
	tv.tv_usec = 0;
	if(setsockopt(sockListen, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
	{
		printf("setopt SO_RCVTIMEO error.the error is %d	%s.\n", errno, strerror(errno));
		close(sockListen);
		sockListen = -1;
		
	}
	
	int recvbytes;  
	char recvbuf[128] = {0};  
	int addrLen = sizeof(struct sockaddr_in);  
	unsigned int event = 0;
	

	while(1)
	{
		
		if((recvbytes = recvfrom(sockListen, recvbuf, 128, 0,(struct sockaddr *)&recvAddr, &addrLen)) != -1)
		{  
			recvbuf[recvbytes] = '\0';  
			printf("receive a broadCast messgse:%s\n", recvbuf);  
			if(!memcmp(recvbuf, "GOTOSLEEP:", 10))
			{				
				unsigned char hwChange[32] = {0};
				unsigned char hw[32] = {0};
				
				
				XmGetEthAttr("wlan0", HW_ADDR, hw);
				snprintf(hwChange, 13, "%02x%02x%02x%02x%02x%02x", hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]); 
			

				if((strlen(&recvbuf[10]) == strlen(hwChange)) && (memcmp(hwChange, &recvbuf[10], strlen(hwChange)) == 0))
				{
					XmSuspendByWlan("udp cmd suspend");
				}				
				
			}

			else if(!memcmp(recvbuf, "PIR_SET:", 7))
			{
				char *p = recvbuf + 8;
				
				Host_Wake_PirSet();


			}

			else if(!memcmp(recvbuf, "PIR_SET:", 14))
			{
				char *p = recvbuf + 14;
				int rtctime = 0;

				rtctime = atoi(p);
				
				Host_Wake_RtcSet(rtctime);

			}
		}
		else
		{  
			//printf("\nnot receive anything\n");  
		}  

		usleep(1000*2000);

	}
	
	close(sockListen);  
	return 0;  

}

int xm_barcode_demo_build(void)
{
	
	prctl(15, (unsigned long)"-xm_barcode_demo_build");

	int ret = 0;
	char buf[64] = {0};
	char ledstate[6] = {0};

	while(hicap_capture_start() != 0)
	{
		usleep(1000*1000);
	}

	while(1)
	{
		if(g_QrBarcodeState.barSwitch == START_BAR_ON)
		{		
			
			if((g_QrBarcodeState.barState) && (strlen(g_QrBarcodeState.barResult) != 0))
			{
				HiCap_CaptureYUVStop(0, 5);
				//红灯灭
				ledstate[0] = 1;
				ledstate[3] = 0;
				HI_HAL_MCUHOST_LedState_Control(ledstate);
				g_QrBarcodeState.barSwitch = START_BAR_OFF;
				g_QrBarcodeState.barState = BAR_RESULT_NO;
				xmAnalyzeQRData(g_QrBarcodeState.barResult);
			}	

		}
		usleep(1000*1000*1);
	}

}


























