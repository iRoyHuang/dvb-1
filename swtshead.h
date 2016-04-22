#ifndef __SWTS_H__
#define __SWTS_H__
/**
* @file swstruct.h
* @brief PAT和PMT解析内容的结构体和函数声明
* @author WuQingwen
* @history
* 			2016-04-13 WuQingwen created
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "swkernellist.h"

#define PACKET_SIZE		188
#define SYNC_BYTE		0X47
#define PATHSIZE		100

typedef struct  sw_ts_pat_program
{
	unsigned program_num;
	unsigned program_map_pid;
	struct list_head pat_list;	
}sw_ts_pat_list_t;

typedef struct sw_ts_pat_stream
{
	unsigned stream_type;
	unsigned elementary_pid;
	unsigned es_info_length;
	unsigned program_num;
	struct list_head pmt_list;
}sw_ts_pmt_list_t;

/**
 * @brief 得到TS包的PID
 * @param[in] buf  读取到TS包数据的buf
 * @return pid
 */
short sw_getpid(unsigned char *buf);

/**
 * @brief 读取TS包到buf中
 * @param[in] buf
 * @param[in] length
 * @param[in] file_headle
 * @return <0失败
 */
size_t sw_read_ts_packet(unsigned char *buf,int length,FILE *file_headle);

/**
 * @brief 搜索TS包中的PAT表
 * @param[in] packetbuf
 * @return 1,找到PAT; -1, 没找到PAT
 */
int sw_find_pat(unsigned char *packetbuf);

/**
 * @brief 从patbuf中分析PAT表，将分析结果放入头节点为pat_list_head的链表中
 * @param[in] packetbuf
 * @param[in] pat_list_head
 * @return 1，成功；-1，失败
 */
int sw_parse_pat(unsigned char *patbuf,sw_ts_pat_list_t *pat_list_head);

/**
 * @brief 搜索TS包中的PMT表
 * @param[in] file_headle   ts文件指针
 * @param[in] pmt_pid		根据PAT表解析出的PMT的PID
 * @param[in] filesize		ts文件长度
 * @param[in] pmt_buf		存pmt包的buf
 * @return 1,成功；-1，失败
 */
int sw_find_pmt(FILE *file_headle,unsigned short pmt_pid,int filesize,unsigned char *pmt_buf);

/**
 * @brief 从pmtbuf中分析PMT表，将分析结果放入头节点为upmt_list_head的链表
 * @param[in] pmtbuf
 * @param[in] pmt_list_head
 * @return 1，成功；-1，失败
 */
int sw_parse_pmt(unsigned char *pmtbuf,sw_ts_pmt_list_t *pmt_list_head);


/*找出video和audio的表*/
//unsigned char* sw_find_video_audio(FILE *file_headle,unsigned short programe_pid,unsigned char type);


/**
 * @brief 打印TS中所有的PMT的PID
 * @param[in] pat_list_head 	保存PMT的PID的链表头节点
 * @return
 */
void sw_print_pmtid(sw_ts_pat_list_t* pat_list_head);

/**
 * @brief 打印TS中节目的信息
 * @param[in] pmt_list_head 	保存节目信息的链表头节点
 * @return
 */
void sw_print_video_audio_pid(sw_ts_pmt_list_t *pmt_list_head);

/**
  * @brief 初始化保存解析pat内容的链表
  * @return sw_ts_pat_list_t类型的指针，表示链表的头节点
  */
sw_ts_pat_list_t* init_pat_list();

/**
  * @brief 初始化保存解析pmt内容的链表
  * @return sw_ts_pmt_list_t类型的指针，表示该链表的头节点
  */
sw_ts_pmt_list_t* init_pmt_list();

/**
 * @brief 将PAT解析出的内容加进链表中
 * @param[in] pat_list_head 保存pat解析信息的链表头节点
 * @return 1，成功；-1，失败
 */
int add_pat_list(sw_ts_pat_list_t pat_program,sw_ts_pat_list_t *pat_head);

/**
 * @brief 将PMT解析出的内容加进链表中
 * @param[in] pmt_list_head 保存pmt解析信息的链表头节点
 * @return 1，成功；-1，失败
 */
int add_pmt_list(sw_ts_pmt_list_t pmt_stream,sw_ts_pmt_list_t *pmt_head);

/**
 * @brief 释放pat_list链表的资源
 * @param[in] pat_list_head 	保存pat解析信息的链表头节点
 * @return 
 */
void free_pat_list(sw_ts_pat_list_t *pat_list_head);

/**
 * @brief 释放pmt_list链表的资源
 * @param[in] pmt_list_head 	保存pmt解析信息的链表
 * @return
 */
void free_pmt_list(sw_ts_pmt_list_t* pmt_list_head);

/**
  *@brief 从src中复制字符串到siz大小的dst
  *@param[in] dst
  *@param[out] src
  *@param[in] siz  sizeof(dst)
  */
size_t strlcpy( char *dst, const char *src, size_t siz );

#endif /*__SWTS_H__*/
