#ifndef _XMCONNECT_H_
#define _XMCONNECT_H_

#include "liteos/if_ether.h"
#include "liteos/if_arp.h"

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */





#define IPC_INFO(fmt, args...)	\
	do\
	{\
		if ( !access(IPC_INFO_ENABLE_FLAG, F_OK) )\
		{\
			printf(fmt, ##args);\
		}\
	}while(0)







/**********************�ṹ���ö��********************************************************/
typedef enum
{

	WIRELESS_PAIRING,

	LAST_PAIRING,

	FORCE_PAIRING,

	FAST_PAIRING,

	FACTORY_PAIRING,

	PAIRING_NR,

}PairingType_e;


typedef enum
{
	IP_ADDR,

	NETMASK_ADDR,

	GATEWAY_ADDR,

	HW_ADDR,
	
}AddrType_e;
	

typedef enum 
{
	GOTOBRG= 1,
	BRGSIG = 2,
	IPC_ACK = 3,
	REBOOT = 4,
	GOTOSLEEP = 5,
	FORCE = 6,
	AUTOSWITCH = 7,
	IPconflict = 8,
	PIR_SET = 9,
	POWER_OFF_SET = 10,
	
	Invalid,
	
} StringType_e;

typedef enum 
{
	Sunday,
	Monday,
	Tuesday,
	Wednesday,
	Thursday,
	Friday,
	Saturday,
		
} DateTime_e;


typedef enum HostWakeReason
{
	REASON_TYPE_NULL               		= 0,        /* None */
	REASON_TYPE_MAGIC_PACKET       		= 1,        /* Wakeup on Magic Packet */
	REASON_TYPE_NETPATTERN_TCP     		= 2,        /* Wakeup on TCP NetPattern */
	REASON_TYPE_NETPATTERN_UDP     		= 3,        /* Wakeup on UDP NetPattern */
	REASON_TYPE_DISASSOC_RX        		= 4,        /* �Զ�ȥ����/ȥ��֤��Wakeup on Disassociation/Deauth */
	REASON_TYPE_DISASSOC_TX        		= 5,        /* �Զ�ȥ����/ȥ��֤��Wakeup on Disassociation/Deauth */
	REASON_TYPE_AUTH_RX            		= 6,        /* ���˶˹�������Wakeup on auth */
	REASON_TYPE_TCP_UDP_KEEP_ALIVE 		= 7,        /* Wakeup on TCP/UDP keep alive timeout */
	REASON_TYPE_HOST_WAKEUP        		= 8,        /* Host wakeup */
	REASON_TYPE_OAM_LOG            		= 9,        /* OAM LOG wakeup */
	REASON_TYPE_SSID_SCAN          		= 10,       /* SSID Scan wakeup */
	REASON_TYPE_MCU_KEY        			= 11,       /* MCU key wakeup */
	REASON_TYPE_MCU_PIR        			= 12,       /* MCU pir wakeup */
	REASON_TYPE_MCU_RESET      			= 13,       /* MCU reset wakeup */
	REASON_TYPE_MCU_RTC        			= 19,       /* MCU rtc wakeup */
	REASON_TYPE_BUT
}HostWakeReason_e;

typedef enum BarState
{
	START_BAR_OFF,
	START_BAR_ON,
	BAR_RESULT_YES = 0,
	BAR_RESULT_NO,
	START_BAR_FORBIDDEN,
}BarState_e;



typedef enum WlanToolState
{
	HOSTAPD_STOPED,
	HOSTAPD_RUNING,
	WPA_SUPPLICANT_STOPED,
	WPA_SUPPLICANT_RUNING,
	NR_WLAN_TOOL_STATE,
}WlanToolState_e;








typedef struct ArpAddr
{
	unsigned char src_mac_hdr[6];
	unsigned char dst_mac_hdr[6];
	unsigned char src_mac[6];
	unsigned char src_ip[18];
	unsigned char dst_mac[6];
	unsigned char dst_ip[18];
}ArpAddr_s;


struct arpMsg
{
	struct ethhdr ethhdr;	/* Ethernet header */
	u_short 	htype;		/* hardware type (must be ARPHRD_ETHER) */
	u_short 	ptype;		/* protocol type (must be ETH_P_IP) */
	u_char  	hlen;		/* hardware address length (must be 6) */
	u_char  	plen;		/* protocol address length (must be 4) */
	u_short 	operation;	/* ARP opcode */
	u_char  	sHaddr[6];	/* sender's hardware address */
	u_char  	sInaddr[4];	/* sender's IP address */
	u_char  	tHaddr[6];	/* target's hardware address */
	u_char  	tInaddr[4];	/* target's IP address */
	u_char  	pad[18];	/* pad for min. Ethernet payload (60 bytes) */
};

typedef struct IpcRuningDate
{
	char 		LanMac[12 + 1];
	int 		connected;
	int 		DeamonSocketFd;
	struct wpa_ap_info	WifiNvrInfo;
	int			CountOfSearchFailed;
}IpcRuningDate_s;

IpcRuningDate_s	g_IpcRuningData;




typedef struct QrBarcodeState
{
	int barSwitch;		
	int barState;
	char barResult[150];
	
}QrBarcodeState_s;

QrBarcodeState_s g_QrBarcodeState;


typedef struct StringToNum
{
    const char *name;
    StringType_e num;
} StringToNum_s;







/*********************************************
**��������			����������
**param [in]	��keys �����ַ���
**param[out]	��pwifi_scan �����õ����ݴ�Žṹ��			pResultNum �õ����ϵ�����	
**����ֵ			��0 û��������		1 ������
**********************************************/
extern int Search_Wifi(struct wpa_ap_info *pwifi_scan, int *pResultNum, char **keys);


/*********************************************
**��������			������������NVRͨѶ
**param [in]	����
**param[out]	����
**����ֵ			��-1
**********************************************/
extern int WirelessHeartbeat(void);

extern int WirelessPairing(int pairing_type);




/*********************************************
**��������			������NVR socket
**param [in]	��NvrIpaddr	nvr��������ַ
**param[out]	����
**����ֵ			��socked	sock���ӵı�ʶ
**********************************************/
extern int ConnectNvrSocket(char *NvrIpaddr);



/*********************************************
**��������			������ģ��ͻ���ģʽ��ȡ�����ȵ���ź�ǿ��
**param [in]	��ifname	��������������
**param[out]	����
**����ֵ			��ipcLevel	�ź�ǿ��
**********************************************/
extern int GetWifiLevel(char * ifname);











#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif








