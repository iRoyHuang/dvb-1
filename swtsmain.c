/**
* @file swtsmain.c
* @brief 主函数,从ts文件中搜索出节目信息，使用./swdvb xxx.ts
* @author WuQingwen
* @history
* 			2016-04-13 WuQingwen created
*/
#include "swtshead.h"

int main(int argc,char *argv[])
{
	if( argc != 2 )
	{
		printf("错误：请使用./swdvb xxx.ts\n");
		return 0;
	}

	char filepath[PATHSIZE];
	memset(filepath,0,PATHSIZE);
	if( strlcpy(filepath,argv[1],sizeof(filepath))<0 )
	{
		return 0;
	}

	//初始化一条空链表,存放pat解析出的信息
	sw_ts_pat_list_t *pat_list_head = init_pat_list();

	if( pat_list_head == NULL )
	{
		printf("init_pat_list fail.\n");
		return 0;
	}
	//初始化一条空链表,存放pmt解析出的信息
	sw_ts_pmt_list_t *pmt_list_head = init_pmt_list();
	if( pmt_list_head == NULL )
	{
		printf("init_pmt_list fail.\n");
		free_pat_list(pat_list_head);
		return 0;
	}
	/*使链表头指向自身，防止断错误*/
	INIT_LIST_HEAD(&pat_list_head->pat_list);
	INIT_LIST_HEAD(&pmt_list_head->pmt_list);

	FILE *file_headle=NULL;	
	if( (file_headle=fopen(filepath,"rb"))==NULL )
	{
		perror("fopen:");
		free_pat_list(pat_list_head);
		free_pmt_list(pmt_list_head);
		return 0;	
	}

	/*求出文件长度*/
	struct stat file_stat;
	if( stat(filepath,&file_stat) == -1 )
	{
		free_pat_list(pat_list_head);
		free_pmt_list(pmt_list_head);
		fclose(file_headle);
		return 0;
	}
	unsigned long long filesize = file_stat.st_size;
	//printf("filesize=%lld\n",filesize );
	int i=0;
	unsigned char packet_buf[PACKET_SIZE];
	memset(packet_buf,0,PACKET_SIZE);

	/*搜索pat，找到一个则退出*/
	for( i=0; i < filesize/PACKET_SIZE; ++i )
	{
		if( sw_read_ts_packet(packet_buf,PACKET_SIZE,file_headle)<0 )
		{
			free_pat_list(pat_list_head);
			free_pmt_list(pmt_list_head);
			fclose(file_headle);
			return 0;
		}	
		int ret = sw_find_pat(packet_buf);
		if( ret == 1 )
		{
			break;
		}	
		else
		{			
			memset(packet_buf,0,PACKET_SIZE);
			continue;
		}
		printf("Not find PAT.\n");
	}	

	/*解析pat，并且找出pmt的pid*/
	int retval = sw_parse_pat(packet_buf,pat_list_head);
	if( retval == -1 )
	{
		free_pat_list(pat_list_head);
		free_pmt_list(pmt_list_head);
		fclose(file_headle);
		return 0;
	}
	/*打印分析出的PMT的pid和节目号*/
	//sw_print_pmtid(pat_list_head);
	rewind(file_headle);
	struct list_head *pos = NULL; 
	struct list_head *n = NULL;	//sw_ts_pat_list_t的成员
	sw_ts_pat_list_t *pat_program = NULL;
	/*遍历小结构体struct list_head 链表*/
	list_for_each_safe(pos,n,&pat_list_head->pat_list)
	{
		/*
		 *用小结构体指针struct list_head *pos来求得
		 *大结构体sw_ts_pat_list_t *pat_program的指针
		 */
		pat_program = list_entry(pos,sw_ts_pat_list_t,pat_list);
		if( pat_program == NULL )
		{
			free_pat_list(pat_list_head);
			free_pmt_list(pmt_list_head);
			fclose(file_headle);
			return 0;
		} 		
		/*找pmt，找到则返回PACKET_SIZEbyte的buf*/
		unsigned char pmt_buf[PACKET_SIZE];//存放PMT包的BUF
		memset(pmt_buf,0,PACKET_SIZE);
		int ret = sw_find_pmt(file_headle,pat_program->program_map_pid,filesize,pmt_buf);
		if( ret = 1 )//成功找到pmt
		{
			/*解析pmt，得到video和vudio等的pid*/
			if( sw_parse_pmt(pmt_buf,pmt_list_head) ==-1 )
			{
				free_pat_list(pat_list_head);
				free_pmt_list(pmt_list_head);
				fclose(file_headle);
				return 0;			
			}
		}
		else if( ret == -1)//没找到，继续找
		{
			continue;
		}
		memset(pmt_buf,0,PACKET_SIZE);
	}
	/*打印节目信息*/
	sw_print_video_audio_pid(pmt_list_head);

	/*处理并退出*/	
	free_pat_list(pat_list_head);
	free_pmt_list(pmt_list_head);
	fclose(file_headle);
	return 0;
}

