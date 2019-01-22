#ifndef __XMNET_H__
#define __XMNET_H__




#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */





/*********************函数被引用**********************************************/

/*********************************************
**函数功能			：和单片机保活
**param [in]	：无
**param[out]	：无
**返回值			：0 发送成功
**********************************************/
extern int Xm_KeepAlive_Set(void);


/*********************************************
**函数功能			：获取单片机系统时间
**param [in]	：无
**param[out]	：无
**返回值			：0 发送成功
**********************************************/
extern int HI_HAL_MCUHOST_Systemtime_Get(void);



/*********************************************
**函数功能			：心跳包中将接受到的数据包命令转换为数字，便于switch case
**param [in]	：str	接受到的命令字符串
**param[out]	：无
**返回值			：转换后得到的数字
**********************************************/
extern int StringToNum(const char * str);


/*********************************************
**函数功能			：数字转为字符
**param [in]	：set 要转的数字
**param[out]	：out 转换得到的字符
**返回值			：0 成功
**********************************************/
extern int NumToDate(int set, char *out);


/*********************************************
**函数功能			：获取开机后的tick数（100/s)tick
**param [in]	：ch		打印输出的字符串
**param[out]	：tick	获得的tick数
**返回值			：无
**********************************************/
extern void xm_get_tick(const char * ch, int *tick);


/*********************************************
**函数功能			：给变量赋值加互斥锁
**param [in]	：num		赋给变量的值
**param[out]	：variable	被赋值的变量
**返回值			：0 成功 -1 失败
**********************************************/
extern int Mux_Operate(int *variable, int num);


/*********************************************
**函数功能			：函数运行加锁
**param [in]	：无
**param[out]	：无
**返回值			：0 成功 -1 失败
**********************************************/
extern int Mux_Operate_Lock(void);


/*********************************************
**函数功能			：函数运行解锁
**param [in]	：无
**param[out]	：无
**返回值			：0 成功 -1 失败
**********************************************/
extern int Mux_Operate_Unlock(void);


/*********************************************
**函数功能			：唤醒原因显示函数
**param [in]	：无
**param[out]	：无
**返回值			：无
**********************************************/
extern void HostWake_Reason_Show(void);


/*********************************************
**函数功能			：获取电池电量
**param [in]	：state 	0:未充电 	1：充电中 		2：已充满电
**param[out]	：pCap	电量百分比值
**返回值			：0 获取成功		-1 获取失败
**********************************************/
extern int XmBatShow(unsigned char * pCap, int state);


/*********************************************
**函数功能			：执行睡眠操作
**param [in]	：reason 睡眠原因	
**param[out]	：无
**返回值			：0 执行成功	
**********************************************/
extern int XmSuspendByWlan(const char *reason);


/*********************************************
**函数功能			：获取mac地址
**param [in]	：ifname wlan0		type 无效		
**param[out]	：out 输出mac地址
**返回值			：0 获取成功	
**********************************************/
extern int XmGetHwAttr(const char *ifname, AddrType_e type, unsigned char* out);


/*********************************************
**函数功能			：获取ip,gateway, 子网掩码，地址
**param [in]	：ifname wlan0		type 0/1/2/3		
**param[out]	：out 输出地址
**返回值			：0 获取成功		-1 获取失败
**********************************************/
extern int XmGetEthAttr(const char *ifname, AddrType_e type, char* out);


/*********************************************
**函数功能			：设置ip,gateway, 子网掩码,mac地址（一次只能设置其中一个）
**param [in]	：ifname wlan0		type 0/1/2/3		str 要设置地址字符串	
**param[out]	：无
**返回值			：0 设置成功		-1 设置失败
**********************************************/
extern int XmSetEthAttr(const char *ifname, AddrType_e type, const char *str);


/*********************************************
**函数功能			：设置静态网络地址，ip值随机获取
**param [in]	：无	
**param[out]	：无
**返回值			：0 设置成功		-1 设置失败
**********************************************/
extern int XmSetStaticIp(void);


/*********************************************
**函数功能			：简单文件读取
**param [in]	：path 文件地址				count 读取大小	
**param[out]	：buf 读取内容存放
**返回值			：0 读取成功		-1 读取失败
**********************************************/
extern int FileSimpleRead(const char * path,char *buf,int count);


/*********************************************
**函数功能			：简单写文件
**param [in]	：path 文件地址		buf 写内容存放		count 写大小	
**param[out]	：无
**返回值			：0 写成功		-1 写失败
**********************************************/
extern int FileSimpleWrite(const char * path,const char *buf,int count);

/*********************************************
**函数功能			：读文件，获取含有特定字符串后面内容
**param [in]	：path 文件地址		num 1 /2		
**param[out]	：out 读取得到的内容
**返回值			：0 读取成功		-1 读取失败
**********************************************/
extern int Read_Config_File(const char *path, int num, char *out);


/*********************************************
**函数功能			：写文件，写含有特定字符串后面内容
**param [in]	：path 文件地址		pssid 要写入热点名称		auth_type 1/2		
**param[out]	：无
**返回值			：0 写成功		-1 写失败
**********************************************/
extern int Write_Config_File(const char *path, const char *pssid, int auth_type);


/*********************************************
**函数功能			：获取文件指定字符串内容
**param [in]	：filename 文件名		src 指定字符串			
**param[out]	：out 获取到的字符
**返回值			：0 获取成功		-1 获取失败
**********************************************/
extern int Get_File_Value(const char * filename, const char *src, char *out);


/*********************************************
**函数功能			：发送广播arp,表明自己ip和mac
**param [in]	：device_name(wlan0) 			
**param[out]	：无
**返回值			：0 发送成功		-1 发送失败
**********************************************/
extern int send_Gratuitous_Arps(const char* device_name);


/*********************************************
**函数功能			：发送广播arp,其中的地址可以任意指定
**param [in]	：type 请求1/回复2		arpaddr arp地址结构体		boo 1:打印输出信息 0：不打印输出信息			
**param[out]	：无
**返回值			：0 发送成功		-1 发送失败
**********************************************/
extern int send_Gratuitous_Arps_test(int type, ArpAddr_s *arpaddr, int boo);


/*********************************************
**函数功能			：设置随机网络地址
**param [in]	：set 	0:根据mac地址 1：随机			
**param[out]	：无
**返回值			：0 设置成功		-1 设置失败
**********************************************/
extern int Wireless_Ipconfig(int set);


/*********************************************
**函数功能			：检测IP冲突
**param [in]	：device 网卡名		ip 待检测ip		
**param[out]	：无
**返回值			：0 不冲突		-1 发生了冲突
**********************************************/
extern int IsIpConflict(char* device , char* ip) ;


/*********************************************
**函数功能			：停用hostapd
**param [in]	：无		
**param[out]	：无
**返回值			：无
**********************************************/
extern void hapd_stop_xm(void);


/*********************************************
**函数功能			：停用wpa_supplicant
**param [in]	：无		
**param[out]	：无
**返回值			：无
**********************************************/
extern void wpa_stop_xm(void);


/*********************************************
**函数功能			：启用wpa_supplicant
**param [in]	：无		
**param[out]	：无
**返回值			：无
**********************************************/
extern void wap_start_xm(void);



/*********************************************
**函数功能			：wpa模式下去连接
**param [in]	：无		
**param[out]	：无
**返回值			：无
**********************************************/
extern void wpa_disconnect_xm(void);


/*********************************************
**函数功能			：使能唤醒的方式
**param [in]	：无		
**param[out]	：无
**返回值			：无
**********************************************/
extern void set_wake_flag(void);


/*********************************************
**函数功能			：主控睡眠前保存配置文件
**param [in]	：无		
**param[out]	：无
**返回值			：无
**********************************************/
extern void Host_Sleep_Conf_Handle(bool state);
	

/*********************************************
**函数功能			：使能pir唤醒，设置唤醒时间
**param [in]	：periodtime 设置后抑制期		checktime 设置唤醒时间		
**param[out]	：无
**返回值			：无
**********************************************/
extern void Host_Wake_PirSet(bool pirswitch, unsigned char checktime);


/*********************************************
**函数功能			：使能rtc唤醒，设置唤醒时间
**param [in]	：times 唤醒时间		
**param[out]	：无
**返回值			：无
**********************************************/
extern void Host_Wake_RtcSet(int times);




/*********************************************
**函数功能			：开始二维码扫描出图
**param [in]	：无	
**param[out]	：无
**返回值			：0 成功 -1失败
**********************************************/
extern int hicap_capture_start(void);


/*********************************************
**函数功能			：结束二维码扫描出图
**param [in]	：无	
**param[out]	：无
**返回值			：0 成功 -1失败
**********************************************/
extern int hicap_capture_stop(void);


/*********************************************
**函数功能			：queue内存地址情况打印
**param [in]	：wifiqueue 起始地址		
**param[out]	：无
**返回值			：无
**********************************************/
extern void xm_wifiqueue_addrshow(Queue * wifiqueue);


/*********************************************
**函数功能			：处理uart里面的数据
**param [in]	：无		
**param[out]	：无
**返回值			：无
**********************************************/
extern void xm_uarthandle_demo_build(void);






/*********************************************
**函数功能			：和单片机通信，发送心跳
**param [in]	：无		
**param[out]	：无
**返回值			：无
**********************************************/
extern void xm_sendheart_demo_build(void);



/*********************************************
**函数功能			：使能下电保活函数
**param [in]	：off_on 是否使能		num 使能几条tcp连接		
**param[out]	：无
**返回值			：0 使能成功
**********************************************/
extern int xm_keepalive_demo_set_switch(int off_on, int num);


/*********************************************
**函数功能			：创建上电保活
**param [in]	：type 	连接类型
**param[out]	：无
**返回值			：0 创建成功
**********************************************/
extern int xm_keepalive_demo_build(void);


/*********************************************
**函数功能			：创建睡眠线程
**param [in]	：无
**param[out]	：无
**返回值			：0 创建成功	（上电过程一直运行，不返回）
**********************************************/
extern int xm_sleep_demo_build(void);


/*********************************************
**函数功能			：厂测模式线程创建
**param [in]	：无
**param[out]	：无
**返回值			：0 创建成功	
**********************************************/
extern int xm_barcode_demo_build(void);





#ifdef __cplusplus
#if __cplusplus
	}
#endif
#endif /* __cplusplus */





#endif
