/******************************************************************************
  Copyright (C), 2004-2050, Hisilicon Tech. Co., Ltd.
******************************************************************************
  File Name     : driver_hisi_lib_api.h
  Version       : Initial Draft
  Author        : Hisilicon WiFi software group
  Created       : 2017-01-06
  Last Modified :
  Description   : API for user calls
  Function List :
  History       :
  1.Date        : 2017-01-06
  Author        :
  Modification  : Created file
******************************************************************************/

#ifndef _DRIVER_HISI_LIB_API_H_
#define _DRIVER_HISI_LIB_API_H_




#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/


/*****************************************************************************
  2 �����������Ͷ���
*****************************************************************************/
#define HISI_SUCC            0
#define HISI_EFAIL           1
#define HISI_EINVAL         22
#define HISI_NULL           (0L)

#define ETH_ALEN                 6
#define MAX_SSID_LEN             32
#define ETH_ADDR_LEN             6
#define HISI_RATE_INFO_FLAGS_MCS                    (1<<0)
#define HISI_RATE_INFO_FLAGS_VHT_MCS                (1<<1)
#define HISI_RATE_INFO_FLAGS_40_MHZ_WIDTH           (1<<2)
#define HISI_RATE_INFO_FLAGS_80_MHZ_WIDTH           (1<<3)
#define HISI_RATE_INFO_FLAGS_80P80_MHZ_WIDTH        (1<<4)
#define HISI_RATE_INFO_FLAGS_160_MHZ_WIDTH          (1<<5)
#define HISI_RATE_INFO_FLAGS_SHORT_GI               (1<<6)
#define HISI_RATE_INFO_FLAGS_60G                    (1<<7)


/*****************************************************************************
  4 ö�ٶ���
*****************************************************************************/
typedef enum
{
    HISI_BOOL_FALSE   = 0,
    HISI_BOOL_TRUE    = 1,
    HISI_BOOL_BUTT
}hisi_bool_type_enum;


typedef enum
{
    HISI_BAND_WIDTH_40PLUS                 = 0,
    HISI_BAND_WIDTH_40MINUS                = 1,
    HISI_BAND_WIDTH_20M                    = 2,

    HISI_BAND_WIDTH_BUTT
}hisi_channel_bandwidth_enum;
typedef unsigned char hisi_channel_bandwidth_enum_uint8;

typedef enum
{
    HISI_MONITOR_SWITCH_OFF,
    HISI_MONITOR_SWITCH_MCAST_DATA,//�ϱ��鲥(�㲥)���ݰ�
    HISI_MONITOR_SWITCH_UCAST_DATA,//�ϱ��������ݰ�
    HISI_MONITOR_SWITCH_MCAST_MANAGEMENT,//�ϱ��鲥(�㲥)�����
    HISI_MONITOR_SWITCH_UCAST_MANAGEMENT,//�ϱ����������
    HISI_MONITOR_SWITCH_BUTT
}hisi_monitor_switch_enum;
typedef unsigned char hisi_monitor_switch_enum_uint8;

typedef enum
{
    HISI_KEEPALIVE_OFF,
    HISI_KEEPALIVE_ON,
    HISI_KEEPALIVE_BUTT
}hisi_keepalive_switch_enum;
typedef unsigned char hisi_keepalive_switch_uint8;


typedef int (*hisi_upload_frame_cb)(void* frame, unsigned int len);


/*��ӡ����*/
typedef enum
{
    HISI_MSG_EXCESSIVE      =    0,
    HISI_MSG_MSGDUMP        =    1,
    HISI_MSG_DEBUG          =    2,
    HISI_MSG_INFO           =    3,
    HISI_MSG_WARNING        =    4,
    HISI_MSG_ERROR          =    5,
    HISI_MSG_OAM_BUTT
}e_hisi_msg_type_t;

typedef struct databk_addr_info  * (*get_databk_addr_info)(void);

typedef enum
{
    HISI_WOW_EVENT_ALL_CLEAR          = 0,          /* Clear all events */
    HISI_WOW_EVENT_MAGIC_PACKET       = 1<<0,       /* Wakeup on Magic Packet */
    HISI_WOW_EVENT_NETPATTERN_TCP     = 1<<1,       /* Wakeup on TCP NetPattern */
    HISI_WOW_EVENT_NETPATTERN_UDP     = 1<<2,       /* Wakeup on UDP NetPattern */
    HISI_WOW_EVENT_DISASSOC           = 1<<3,       /* ȥ����/ȥ��֤��Wakeup on Disassociation/Deauth */
    HISI_WOW_EVENT_AUTH_RX            = 1<<4,       /* �Զ˹�������Wakeup on auth */
    HISI_WOW_EVENT_HOST_WAKEUP        = 1<<5,       /* Host wakeup */
    HISI_WOW_EVENT_TCP_UDP_KEEP_ALIVE = 1<<6,       /* Wakeup on TCP/UDP keep alive timeout */
    HISI_WOW_EVENT_OAM_LOG_WAKEUP     = 1<<7,       /* OAM LOG wakeup */
    HISI_WOW_EVENT_SSID_WAKEUP        = 1<<8,       /* SSID Scan wakeup */
}hisi_wow_event_enum;

typedef enum
{
    HISI_WOW_WKUP_REASON_TYPE_NULL               = 0,        /* None */
    HISI_WOW_WKUP_REASON_TYPE_MAGIC_PACKET       = 1,        /* Wakeup on Magic Packet */
    HISI_WOW_WKUP_REASON_TYPE_NETPATTERN_TCP     = 2,        /* Wakeup on TCP NetPattern */
    HISI_WOW_WKUP_REASON_TYPE_NETPATTERN_UDP     = 3,        /* Wakeup on UDP NetPattern */
    HISI_WOW_WKUP_REASON_TYPE_DISASSOC_RX        = 4,        /* �Զ�ȥ����/ȥ��֤��Wakeup on Disassociation/Deauth */
    HISI_WOW_WKUP_REASON_TYPE_DISASSOC_TX        = 5,        /* �Զ�ȥ����/ȥ��֤��Wakeup on Disassociation/Deauth */
    HISI_WOW_WKUP_REASON_TYPE_AUTH_RX            = 6,        /* ���˶˹�������Wakeup on auth */
    HISI_WOW_WKUP_REASON_TYPE_TCP_UDP_KEEP_ALIVE = 7,        /* Wakeup on TCP/UDP keep alive timeout */
    HISI_WOW_WKUP_REASON_TYPE_HOST_WAKEUP        = 8,        /* Host wakeup */
    HISI_WOW_WKUP_REASON_TYPE_OAM_LOG            = 9,        /* OAM LOG wakeup */
    HISI_WOW_WKUP_REASON_TYPE_SSID_SCAN          = 10,       /* SSID Scan wakeup */
    HISI_WOW_WKUP_REASON_TYPE_BUT
}hisi_wow_wakeup_reason_type_enum;


/*****************************************************************************
  5 ȫ�ֱ�������
*****************************************************************************/

/*****************************************************************************
  6 ��Ϣͷ����
*****************************************************************************/

/*****************************************************************************
  7 ��Ϣ����
*****************************************************************************/



/*****************************************************************************
  8 STRUCT����
*****************************************************************************/

typedef struct _hisi_rf_customize_stru
{
    int                             l_11b_scaling_value;
    int                             l_11g_u1_scaling_value;
    int                             l_11g_u2_scaling_value;
    int                             l_11n_20_u1_scaling_value;
    int                             l_11n_20_u2_scaling_value;
    int                             l_11n_40_u1_scaling_value;
    int                             l_11n_40_u2_scaling_value;
    int                             l_ban1_ref_value;
    int                             l_ban2_ref_value;
    int                             l_ban3_ref_value;
    int                             l_customize_enable;
    int                             l_disable_bw_40;
    int                             l_dtim_setting;
    int                             l_pm_switch;
} hisi_rf_customize_stru;

typedef struct _hisi_wpa_status_stru
{
    unsigned char                  auc_ssid[MAX_SSID_LEN];
    unsigned char                  auc_bssid[ETH_ADDR_LEN];
    unsigned char                  auc_rsv[2];
    unsigned int                   ul_status;

} hisi_wpa_status_stru;

typedef struct
{
    unsigned char                           uc_channel_num;
    hisi_channel_bandwidth_enum_uint8       uc_channel_bandwidth;
}hisi_channel_stru;

typedef struct _hisi_tcp_params_stru
{
    unsigned int        ul_sess_id;
    unsigned char       auc_dst_mac[6];  /* Ŀ��MAC��ַ */
    unsigned char       auc_resv[2];
    unsigned char       auc_src_ip[4];   /* ԴIP��ַ */
    unsigned char       auc_dst_ip[4];   /* Ŀ��IP��ַ */
    unsigned short      us_src_port;    /* Դ�˿ں� */
    unsigned short      us_dst_port;    /* Ŀ�Ķ˿ں� */
    unsigned int        ul_seq_num;     /* ���к� */
    unsigned int        ul_ack_num;     /* ȷ�Ϻ� */
    unsigned short      us_window;      /* TCP���ڴ�С */
    unsigned short      us_retry_max_count;      /* ����ش����� */
    unsigned int        ul_interval_timer;       /* �������������� */
    unsigned int        ul_retry_interval_timer; /* �ش�ʱ�������������� */
    unsigned int        ul_time_value;
    unsigned int        ul_time_echo;
    unsigned char      *puc_tcp_payload;
    unsigned int        ul_payload_len;
}hisi_tcp_params_stru;

struct databk_addr_info
{
    unsigned long                     databk_addr; /*flash addr, store data backup data*/
    unsigned int                      databk_length; /*data length, the length of the data backup data*/
    get_databk_addr_info              get_databk_info; /*get data backup info,include databk_addr and databk_length*/
};

struct station_info
{
    int    l_signal;/* �ź�ǿ�� */
    int    l_txrate;/* TX���� */
};
/*****************************************************************************
  9 UNION����
*****************************************************************************/

/*****************************************************************************
  10 OTHERS����
*****************************************************************************/

/*****************************************************************************
  11 ��������
*****************************************************************************/

/*****************************************************************************
  11.1 ˯�߻�����ض��Ⱪ¶�ӿ�
*****************************************************************************/
/*****************************************************************************
 �� �� ��  : hisi_wlan_suspend
 ��������  : ǿ��˯�� API�ӿ�
 �������  : ��
 �������  : ��
 �� �� ֵ  : ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��01��05��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern void hisi_wlan_suspend(void);

/*****************************************************************************
 �� �� ��  : hisi_wlan_set_wow_event
 ��������  : ����ǿ��˯�߹��ܿ��ؽӿ�
 �������  : unsigned int ul_event �¼�����ֵ
 �������  : ��
 �� �� ֵ  : ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��01��05��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern void hisi_wlan_set_wow_event(unsigned int ul_event);

/*****************************************************************************
 �� �� ��  : hisi_wlan_add_netpattern
 ��������  : ǿ��˯��netpattern���ѱ��ĸ�ʽ�����API�ӿ�
 �������  : unsigned int    ul_netpattern_index: netpattern ������, 0~3
             unsigned char  *puc_netpattern_data: netpattern ������
             unsigned int    ul_netpattern_len  : netpattern �����ݳ���, 0~64
 �������  : ��
 �� �� ֵ  : 0  : �ɹ�
             ��0: ʧ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��01��05��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern unsigned int hisi_wlan_add_netpattern(
                        unsigned int    ul_netpattern_index,
                        unsigned char  *puc_netpattern_data,
                        unsigned int    ul_netpattern_len
                        );

/*****************************************************************************
 �� �� ��  : hisi_wlan_del_netpattern
 ��������  : ǿ��˯��netpattern���ѱ��ĸ�ʽ��ɾ��API�ӿ�
 �������  : unsigned int    ul_netpattern_index: netpattern ������, 0~3
 �������  : ��
 �� �� ֵ  : 0  : �ɹ�
             ��0: ʧ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��01��05��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern unsigned int hisi_wlan_del_netpattern(unsigned int ul_netpattern_index);

/*****************************************************************************
 �� �� ��  : hisi_wlan_wow_enable
 ��������  : ��֤wow��ز����ܹ�˳������device,�ú���һ��Ҫ�������µ�ǰ���ò���������ɺ����
 �������  :
 �������  : ��
 �� �� ֵ  : 0  : �ɹ�
             ��0: ��������ʧ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��12��06��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern unsigned int hisi_wlan_wow_enable(void);

/*****************************************************************************
 �� �� ��  : hisi_wlan_set_wakeup_ssid
 ��������  : ��AP�쳣���ڵ���ʱ����оƬ����ڹ��Ŀ��ǣ����µ磻
             �ó���������SSID����wifiɨ�赽��SSID�ȵ�ʱ��������оƬ
 �������  : char *ssid: netpattern ������, 2~32
 �������  : ��
 �� �� ֵ  : 0  : �ɹ�
             ��0: ʧ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��02��25��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern int hisi_wlan_set_wakeup_ssid(char *ssid);

/*****************************************************************************
 �� �� ��  : hisi_wlan_clear_wakeup_ssid
 ��������  : ���SSID����hisi_wlan_set_wakeup_ssid���ʹ��
 �������  :
 �������  : ��
 �� �� ֵ  : 0  : �ɹ�
             ��0: ʧ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��02��25��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern int hisi_wlan_clear_wakeup_ssid(void);


/*****************************************************************************
 �� �� ��  : hisi_wlan_get_wakeup_reason
 ��������  : ǿ��˯�߻���ԭ��Ļ�ȡAPI�ӿ�
 �������  : unsigned int * pul_wakeup_reason[OUT]: ����ԭ��
 �������  : ��
 �� �� ֵ  : 0  : �ɹ�
             ��0: ʧ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��01��05��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern unsigned int hisi_wlan_get_wakeup_reason(unsigned int * pul_wakeup_reason);
/*****************************************************************************
 �� �� ��  : hisi_wlan_get_databk_addr_info
 ��������  : ��ȡwifi����databk addr info
 �������  : ��
 �������  : ��
 �� �� ֵ  : databk addr info
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��02��14��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern struct databk_addr_info * hisi_wlan_get_databk_addr_info(void);

/*****************************************************************************
  11.3 wifi��ض��Ⱪ¶�ӿ�
*****************************************************************************/

/*****************************************************************************
 �� �� ��  : hisi_wlan_wifi_init
 ��������  :
 �������  :
 �������  :
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2016��12��19��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
//extern int hisi_wlan_wifi_init(struct netif **pst_wifi);

/*****************************************************************************
 �� �� ��  : hisi_wlan_wifi_deinit
 ��������  :
 �������  :
 �������  :
 �� �� ֵ  :

 �޸���ʷ      :
  1.��    ��   : 2016��12��19��
    ��    ��   : 
    �޸�����   : �����ɺ���
*****************************************************************************/
extern int hisi_wlan_wifi_deinit(void);
/*****************************************************************************
  11.4 hilink��smartconfig��ض��Ⱪ¶�ӿ�
*****************************************************************************/
/*****************************************************************************
 �� �� ��  : hisi_wlan_set_monitor
 ��������  : ����monitorģʽ����API�ӿ�
 �������  : monitor_switch:���ز���
 �������  : ��
 �� �� ֵ  : 0  : �ɹ�
             ��0: ʧ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��01��16��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern int hisi_wlan_set_monitor(unsigned char monitor_switch, char rssi_level);
/*****************************************************************************
 �� �� ��  : hisi_wlan_set_channel
 ��������  : �����ŵ���API�ӿ�
 �������  : ���ݽṹ:hisi_channel_stru *s,����monitorģʽʹ��
             ���ŵ��żӴ��� ����˵��: 0->40M+  1->40M-  ��֧��20m����
 �������  : ��
 �� �� ֵ  : 0  : �ɹ�
             ��0: ʧ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��01��16��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern int hisi_wlan_set_channel(hisi_channel_stru *channel_info);

#ifndef WIN32
/*****************************************************************************
 �� �� ��  : hisi_wlan_get_channel
 ��������  : ��ȡ�ŵ�
 �������  : ���ݽṹ:hisi_channel_stru *s
 �������  :
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��6��29��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern int hisi_wlan_get_channel(hisi_channel_stru *channel_info);


/*****************************************************************************
 �� �� ��  : hisi_wlan_set_country
 ��������  : ���ù�����
 �������  :
 �������  :
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��6��29��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern int hisi_wlan_set_country(unsigned char *puc_country);

/*****************************************************************************
 �� �� ��  : hisi_wlan_get_country
 ��������  : ��ȡ������
 �������  :
 �������  :
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��6��29��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern char * hisi_wlan_get_country(void);

/*****************************************************************************
 �� �� ��  : hisi_wlan_rx_fcs_info
 ��������  : ��ȡ�հ���
 �������  :
 �������  :
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��6��29��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern int hisi_wlan_rx_fcs_info(int *pl_rx_succ_num);

/*****************************************************************************
 �� �� ��  : hisi_wlan_set_always_tx
 ��������  : ���ó���
 �������  : ����Ϊһ���ַ������飬����4��Ԫ�أ�ÿ��Ԫ�ؿռ��С����Ϊ20���ֽڣ�ģʽΪ: �������� ����ģʽ �ŵ� ����
             ����: char ac_buffer[4][20] = {"1", "11b", "7", "11"};����7�ŵ�����11b 11m�����ʳ���
 �������  :
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��6��29��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern int hisi_wlan_set_always_tx(char *pc_param);

/*****************************************************************************
 �� �� ��  : hisi_wlan_set_pm_switch
 ��������  : ���õ͹��Ŀ���
 �������  : �͹��Ŀ���: 0 | 1(����ֵ��Ч)
 �������  :
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��6��29��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern int hisi_wlan_set_pm_switch(unsigned int uc_pm_switch);


/*****************************************************************************
 �� �� ��  : hisi_wlan_set_always_rx
 ��������  : ���ó���
 �������  : ����Ϊһ���ַ������飬����3����Ա��ģʽΪ: �������� ����ģʽ �ŵ�
             ����: char ac_buffer[3][20] = {"1", "11b", "7"};����7�ŵ�����11b����
 �������  :
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��6��29��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern int hisi_wlan_set_always_rx(char *pc_param);
#endif
/*****************************************************************************
 �� �� ��  : hisi_wlan_register_upload_frame_cb
 ��������  : hilink��smartconfig�ϱ�����֡�Ļص�
 �������  : func�ص���������ָ��
 �������  : ��
 �� �� ֵ  : 0  : �ɹ�
             ��0: ʧ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��01��16��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern unsigned int hisi_wlan_register_upload_frame_cb(hisi_upload_frame_cb func);

/*****************************************************************************
  11.5 TCP������ض��Ⱪ¶�ӿ�
*****************************************************************************/
/*****************************************************************************
 �� �� ��  : hisi_wlan_set_tcp_params
 ��������  : ���ñ���TCP��·������API�ӿ�
 �������  : tcp_params����TCP�����Ĳ���ָ��
 �������  : ��
 �� �� ֵ  : 0  : �ɹ�
             ��0: ʧ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��01��16��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern int hisi_wlan_set_tcp_params(hisi_tcp_params_stru *tcp_params);

/*****************************************************************************
 �� �� ��  : hisi_wlan_set_keepalive_switch
 ��������  : ���ñ���TCP��·���ܿ��ص�API�ӿ�
 �������  : keepalive_switch����ֵ
 �������  : ��
 �� �� ֵ  : 0  : �ɹ�
             ��0: ʧ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��01��16��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern int hisi_wlan_set_keepalive_switch(unsigned char keepalive_switch, unsigned int keepalive_num);

/*****************************************************************************
 �� �� ��  : hisi_wlan_get_macaddr
 ��������  : ��ȡMac��ַ
 �������  :
 �������  :
 �� �� ֵ  : 0  : �ɹ�
             ��0: ʧ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��01��16��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern unsigned char* hisi_wlan_get_macaddr(void);

/*****************************************************************************
 �� �� ��  : hisi_wlan_ip_notify
 ��������  : ֪ͨ����IP��ַ�仯
 �������  : ip,��ǰ��IPֵ��mode��ȡ��ɾ��IP
 �������  : ��
 �� �� ֵ  : 0  : �ɹ�
             ��0: ʧ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��01��16��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern int hisi_wlan_ip_notify(unsigned int ip, unsigned int mode);


/*****************************************************************************
 �� �� ��  : hisi_wlan_get_lose_tcpid
 ��������  : ��ȡTCP������tcp����ID
 �������  : ��
 �������  : ��
 �� �� ֵ  : ����TCP��·ID�ı��λ,��ǰ֧�����4��TCP����,����ͼ��ʾ
             ÿһ��bitλ������Ӧ��TCP��·�Ƿ����1��ʾ������0��ʾ������
             | 31bit - 4bit | 3bit | 2bit | 1bit | 0bit |
             |    unused    | ��ʶ | ��ʶ | ��ʶ | ��ʶ |
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��02��20��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern int hisi_wlan_get_lose_tcpid(void);


/*****************************************************************************
 �� �� ��  : hisi_wlan_no_fs_config
 ��������  : wifi�������ļ�ϵͳʱ�ļ���������
 �������  : �����ļ���flash��ַ�ͳ���
 �������  : ��
 �� �� ֵ  : ��
 ���ú���  :
 ��������  :
*****************************************************************************/
extern void hisi_wlan_no_fs_config(unsigned long ul_base_addr, unsigned int u_length);
/*****************************************************************************
 �� �� ��  : hisi_wlan_get_station
 ��������  : ��ȡstation��Ϣ��API�ӿ�(ֻ֧��stationģʽ)
 �������  :struct station_info *pst_sta
 �������  :
 �� �� ֵ  : 0  : �ɹ�
             ��0: ʧ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��7��1��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/
extern int  hisi_wlan_get_station(struct station_info *pst_sta);

/*****************************************************************************
 �� �� ��  : hisi_wifi_debug_info
 ��������  : ����wifi_debug�ӿ�
 �������  : void

 �������  : ��
 �� �� ֵ  :void
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��7��26��
    ��    ��   : 
    �޸�����   : �����ɺ���

*****************************************************************************/

extern void hisi_wifi_debug_info(void);


/*****************************************************************************
 ���������ṩ��OAMά����־�ӿ�
*****************************************************************************/
#if (_HI113X_SW_VERSION == _HI113X_SW_DEBUG)
extern unsigned int oam_log_sdt_out(unsigned short      us_level,
                                    const signed char   *pc_func_name,
                                    const signed char         *pc_fmt,
                                    ...);

#define wpa_printf(level, fmt, ...) \
do{ \
    oam_log_sdt_out((unsigned short)level, (const signed char*)__func__, (const signed char*)fmt, ##__VA_ARGS__); \
    }while(0)

#define HISI_PRINT_INFO(fmt, ...) \
do{ \
    oam_log_sdt_out(HISI_MSG_INFO, (const signed char*)__func__, (const signed char*)fmt, ##__VA_ARGS__); \
    }while(0)

#define HISI_PRINT_WARNING(fmt, ...) \
do{ \
    oam_log_sdt_out(HISI_MSG_WARNING, (const signed char*)__func__, (const signed char*)fmt, ##__VA_ARGS__); \
    }while(0)

#define HISI_PRINT_ERROR(fmt, ...) \
do{ \
    oam_log_sdt_out(HISI_MSG_ERROR, (const signed char*)__func__, (const signed char*)fmt, ##__VA_ARGS__); \
    }while(0)

#elif (_HI113X_SW_VERSION == _HI113X_SW_RELEASE)
#define HISI_PRINT_INFO(fmt, arg...)
#define HISI_PRINT_WARNING(fmt, arg...)
#define HISI_PRINT_ERROR(fmt, arg...) \
do{ \
    printf(fmt, ##arg); \
    printf("\n"); \
    }while(0)

#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif    /*_DRIVER_HISI_LIB_API_H_*/
