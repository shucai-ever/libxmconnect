
#ifndef __XMEXT_LIB_H__
#define __XMEXT_LIB_H__




#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */


typedef struct tagSYSTEM_TIME
{
	int  year;		///< 年。   
	int  month;		///< 月，January = 1, February = 2, and so on.   
	int  day;		///< 日。   
	int  wday;		///< 星期，Sunday = 0, Monday = 1, and so on   
	int  hour;		///< 时。   
	int  minute;	///< 分。   
	int  second;	///< 秒。   
	int  isdst;		///< 夏令时标识。   
} SYSTEM_TIME;

typedef struct Queue
{
	void *mutex_lock;
	size_t res;
	unsigned char *buf;
	unsigned char *head;
	unsigned char *tail;
	unsigned char *buf_start_point;
	unsigned char *buf_end_point;
}Queue;

typedef unsigned char  Type;

typedef struct WLAN_KEEPALIVE_CONFIG
{
	int 				sockfd;					 /* TCP socket id*/
	unsigned int        ul_sess_id;
	unsigned int        ul_interval_timer;       /* 心跳包发送周期 */
    unsigned int        ul_retry_interval_timer; /* 重传时心跳包发送周期 */
    unsigned short      us_retry_max_count;      /* 最大重传次数 */
	unsigned short		keepalive_buf_len;		 /* keepalive_buf 的长度*/
	unsigned char       keepalive_buf[128];
} WLAN_KEEPALIVE_CONFIG;


#define MAX_PIR_LIST_NUM 2

/*weekDayEn->bit0:以下触发时间段是否有效,bit1-7分别表示周一到周日是否有效，
		若bit1-bit7全为0,且bit0为1,就只触发一次*/
typedef struct PirDNDMode
{
	unsigned char weekDayEn;
	SYSTEM_TIME *pStartTime;//开始时间
	SYSTEM_TIME *pEndTime;//结束时间
} PirDNDMode_s;

typedef struct PirDNDModeList
{
	PirDNDMode_s pirMode[MAX_PIR_LIST_NUM];//pir触发时间段列表
} PirDNDModeList_s;


/*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@引用外部库函数@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*/

/*********************************************
**函数功能			：读取电池剩余容量
**param [in]	：state 充电状态 0 : 未充电  1 : 充电中 2 : 已充满
**param[out]	：pCap 返回剩余容量百分比
**返回值			：0 成功		<0 读失败
**********************************************/
extern int GetSystemPowerCap(unsigned char * pCap, int state);



/*********************************************
**函数功能			：获取供电状态
**param [in]	：无
**param[out]	：无
**返回值			：无     11:满电充电 10：满电没充电 01：非满电充电 00：非满电非充电
**********************************************/
extern void HI_HAL_MCUHOST_Power_Poll(void);



/*********************************************
**函数功能			：uart数据结尾字符生成
**param [in]	：inBuf 待发送数据字符串			inLen 发送字符串的长度
**param[out]	：无
**返回值		：无     
**********************************************/
extern unsigned char XOR_Inverted_Check(unsigned char* inBuf, unsigned char inLen);
	
	
/*********************************************
**函数功能			：控制单片机led命令
**param [in]	：ledstate {02, 5, 100, 00, 5, 100}蓝灯亮五次，每次100*10ms,红灯不亮
**param[out]	：无
**返回值			：无     
**********************************************/	
extern void HI_HAL_MCUHOST_LedState_Control(char *ledstate);


/*********************************************
**函数功能			：和单片机保活
**param [in]	：无
**param[out]	：无
**返回值			：无     
**********************************************/	
extern void HI_HAL_MCUHOST_KeepAlive_Set(void);


/*********************************************
**函数功能			：使能单片机红外和设置抑制期
**param [in]	：Pirflag 是否使能		 Pirtime 抑制期
**param[out]	：无
**返回值			：无     
**********************************************/		
extern void HI_HAL_MCUHOST_Set_PIR_Time(bool Pirflag,unsigned short *Pirtime);


/*********************************************
**函数功能			：设置红外感应唤醒时间
**param [in]	：Pirtime 唤醒时间
**param[out]	：无
**返回值			：无     
**********************************************/	
extern void HI_HAL_MCUHOST_Set_PIR_CheckTime(unsigned char *Pirtime);
	

/*********************************************
**函数功能			：设置单片机rtc时间
**param [in]	：无
**param[out]	：无
**返回值			：无     
**********************************************/	
extern void HI_HAL_MCUHOST_Rtc_Sync(void);


/***********************************************

**函数功能			：设置定时唤醒任务

	
	wakeupReason:唤醒事件:\
		_DHCP_CONNECT = 0//离线时重连服务器
		_APPOINTMENT_POWERUP = 1,//预约来电 
		_SERVER_SYNCHRONIZATION_POWERUP = 2,//同步服务器，一般12个小时一次定时开机 					
		_INTERVAL_WAKE = 3,//间隔唤醒
		 = 4,////定时唤醒
	pStartTime:定时唤醒时间
	wakeupSwitch:
		1表示开启定时，0表示关闭
	doowBellSwitch:
		1表示触发定时任务时同时触发433响铃，0表示不触发响铃
	Parameter:	 无
	Return: 	  无
*************************************************/
extern void HI_HAL_MCUHOST_Set_Wakeup_Time(unsigned char wakeupSwitch,unsigned char wakeReason,SYSTEM_TIME *pStartTime, unsigned char doowBellSwitch);


/*********************************************
**函数功能			：和单片机通信发送函数
**param [in]	：fd 串口标识 sbuf 待发送的数据
**param[out]	：无
**返回值			：0 成功    
**********************************************/	
extern int USART_Send_Data(int fd, unsigned char* sbuf);


/*********************************************
**函数功能			：获取无线队列数据
**param [in]	：无
**param[out]	：无
**返回值			：Queue * 结构体    
**********************************************/	
extern Queue* GetNvrQueue(void);



extern int queue_init(Queue **queue);
extern int En_Queue(Queue *queue, Type *data);
extern int De_Queue(Queue *queue, Type *buf);
extern int is_empty(Queue *queue);
extern int is_full(Queue *queue);
extern void display_queue(Queue *queue);
extern void destroy_queue(Queue *queue);
extern void LibDvr_Clean_queue(Queue *queue);

typedef int(*fYUVCallBack) (long lYuvHandle, char* pBuffer, int nBufLen);
extern int HiCap_CaptureYUVStart(int VpssGrp, int exChn, int width, int height, fYUVCallBack fun);
extern int HiCap_CaptureYUVStop(int VpssGrp, int exChn);



extern int WlanSetKeepAliveTcpParams(WLAN_KEEPALIVE_CONFIG *pParam);
extern int WlanKeepAliveSwitch(unsigned char keepalive_switch, unsigned int keepalive_num);
extern void HI_HAL_MCUHOST_Pir_DNDMode_Config(PirDNDModeList_s *pirDNDList);







#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */






#endif




















