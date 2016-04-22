/**
* @file swtsfunction.c
* @brief  实现ts搜索节目的各类函数
* @author WuQingwen
* @history
* 			2016-04-13 WuQingwen created
*/

#include "swtshead.h"
/**
 * 解析TS包的PID
 * 返回该包的pid
 */
short sw_getpid(unsigned char *buf)
{
	if( buf == NULL )
	{
		return -1;
	}
	unsigned char *pidbuf = buf;
	short pid = ( (pidbuf[1] & 0x1f) << 8 ) | pidbuf[2];
	return pid;
}

/**
 * 读取TS包数据到buf中，file_headle为TS文件的文件指针，
 * length为一个TS包的大小
 */
size_t sw_read_ts_packet(unsigned char *buf,int length,FILE *file_headle)
{
	if( buf == NULL || file_headle ==NULL || length <= 0 )
		return -1;
	return fread(buf,1,length,file_headle);
}

/**
 * 搜索含有一个TS包数据的packetbuf中的PAT表
 * 返回 1,找到PAT; -1, 没找到PAT
 */
int sw_find_pat(unsigned char *packetbuf)
{
	if( packetbuf == NULL )
	{
		return -1;
	}
	unsigned char *buf = packetbuf;

	int sync_byte = buf[0];
	if( sync_byte != SYNC_BYTE )
	{
		printf("It's not a packet.\n");
		return -1;
	}

	short pat_pid = sw_getpid(buf);
	if( pat_pid < 0 )
	{
		return -1;
	}
	if( pat_pid == 0x0 )
	{
		return 1;
	}
	return -1;
}


/**
 * 从包含pat包数据的patbuf中分析PAT表
 * 将分析结果即pmt的pid和program_num放入链表中
 * return 1,成功；-1，失败
 */
int sw_parse_pat(unsigned char *patbuf,sw_ts_pat_list_t *pat_head)
{
	if( patbuf == NULL || pat_head == NULL )
	{
		printf("sw_parse_pat error.\n");
		return -1;
	}
	unsigned char *buf = patbuf;
	sw_ts_pat_list_t *pat_list_head = pat_head;
	unsigned char *data_buf = NULL;

	unsigned char payload_unit_start_indicator = (buf[1] >> 6) & 0x1; 
	//printf("payload_unit_start_indicator=%d\n",payload_unit_start_indicator );
	/*判断是否要除去data开头一个字节*/
	if( payload_unit_start_indicator == 0 )
	{
		data_buf = buf+4;
	}
	else
	{
		/*除去data中第一个字节*/
		data_buf = buf+5;
	}
	/*判断是否为pat*/
	unsigned short table_id = data_buf[0];
	//printf("pattable_id=%d\n",table_id );
	if( table_id != 0x0 )  
	{
		perror("pat_table_id");
		return -1;
	}
	/*确定段长度*/
	unsigned short section_length = (data_buf[1] & 0xf) << 8 | data_buf[2]; 

	/*开始解析出program_num和pmt_pid*/
	int n = 0;
	for( n = 0; n<section_length-9; n+=4 )
	{
		unsigned short program_num = ( data_buf[8+n] << 8 ) | data_buf[9+n];
		unsigned short network_pid = 0x00;
		if( program_num == 0x00 )
		{
			network_pid = ( data_buf[10+n] & 0x1f ) << 8 | data_buf[11+n];
		}
		else
		{
			sw_ts_pat_list_t new_pat_program;
			memset(&new_pat_program,0,sizeof(sw_ts_pat_list_t));
			new_pat_program.program_num = program_num;
			new_pat_program.program_map_pid = ( data_buf[10+n] & 0x1f ) << 8 | data_buf[11+n];
			//加进链表
			if( add_pat_list(new_pat_program,pat_list_head)<0 )
			{
				return -1;
			}
		}
	}

	return 1;
}


/**
 * 搜索文件长度为filezize的TS包中pid为pmt_pid的包，即pmt。
 * file_headle 为TS的文件指针
 * 成功，return 1 ；失败，return -1
 */
int sw_find_pmt(FILE *file_headle,unsigned short pmt_pid,int filesize,unsigned char *pmt_buf)
{
	if( file_headle == NULL || pmt_buf == NULL )
	{
		return -1;
	}
	unsigned char *buf = pmt_buf;
	rewind(file_headle);

	int i = 0;
	for( i=0; i < filesize/PACKET_SIZE; ++i )
	{
		if( sw_read_ts_packet(buf,PACKET_SIZE,file_headle)<0 )
		{
			return -1;
		}
		int sync_byte = buf[0];
		if( sync_byte != SYNC_BYTE )
		{
			printf("It's not a packet.\n");
			return -1;
		}
		unsigned short pid = sw_getpid(buf);
		if( pid == pmt_pid )
		{
			/*找到就返回*/
			return 1;
		}
		memset(buf,0,PACKET_SIZE);
	}
	return -1;
}


/**
 * 从包含pmt数据的pmtbuf中分析PMT表，
 * 将分析结果即stream_type、elementary_pid、
 * program_num和es_info_length放入链表中
 * return 1;成功；-1失败
 */
int sw_parse_pmt(unsigned char *pmtbuf,sw_ts_pmt_list_t *list_head)
{
	if( pmtbuf == NULL || list_head == NULL )
	{
		return -1;
	}

	unsigned char *buf = pmtbuf;
	sw_ts_pmt_list_t *pmt_list_head = list_head;

	unsigned char *data_buf = NULL;
	unsigned char payload_unit_start_indicator = (buf[1] >> 6) & 0x1; 
	/*判断是否要除去data开头一个字节*/
	if( payload_unit_start_indicator == 0 )
	{
		data_buf = buf+4;
	}
	else
	{
		/*除去data中第一个字节*/
		data_buf = buf+5;
	}
	/*判断是否为pmt*/
	unsigned short table_id = data_buf[0];
	if( table_id != 0x02 )  
	{
		perror("table_id");
		return -1;
	}

	unsigned short section_length = (data_buf[1] & 0xf) << 8 | data_buf[2];
	unsigned short program_info_length = (data_buf[10] & 0xf) << 8 | data_buf[11];
	
	int n = 0;
	/*开始解析出stream_type、elementary_pid和es_info_length*/
	for ( n = 0; n < section_length-13-program_info_length; )
	{

		sw_ts_pmt_list_t new_pmt_stream;
		memset(&new_pmt_stream,0,sizeof(sw_ts_pmt_list_t));
		new_pmt_stream.program_num = (data_buf[3] << 8) | data_buf[4];
		new_pmt_stream.stream_type = data_buf[12+n];
		new_pmt_stream.elementary_pid = (data_buf[13+n] & 0x1f) << 8 | data_buf[14+n];
		new_pmt_stream.es_info_length = (data_buf[15+n] & 0xf) << 8 | data_buf[16+n];
		if( new_pmt_stream.es_info_length != 0 )
			n += new_pmt_stream.es_info_length;
		n += 5;
		//加进链表
		if( add_pmt_list(new_pmt_stream,pmt_list_head)<0 )
		{
			return -1;
		}		
	}

	return 1;
}


/**
 * 	从容器pat_program中打印TS中所有的PMT的PID
 */
void sw_print_pmtid(sw_ts_pat_list_t* list_head)
{
	if( list_head == NULL )
	{
		return;
	}
	sw_ts_pat_list_t* pat_list_head = list_head;

	struct list_head *pos = NULL; 
	struct list_head *n = NULL;	//sw_ts_pat_list_t 里的
	list_for_each_safe(pos,n,&pat_list_head->pat_list)
	{
		sw_ts_pat_list_t *pat_program=list_entry(pos,sw_ts_pat_list_t,pat_list);
		if( pat_program == NULL )
			return;
		printf("program_num=0x%x,pmt_pid=0x%x\n",
						pat_program->program_num,
						pat_program->program_map_pid);
	}
}



/**
 * 打印TS中所有节目的信息
 */
void sw_print_video_audio_pid(sw_ts_pmt_list_t *list_head)
{
	if( list_head == NULL )
	{
		return;
	}
	sw_ts_pmt_list_t* pmt_list_head = list_head;

	struct list_head *pos = NULL; 
	struct list_head *n = NULL;	//sw_ts_pat_list_t 里的
	list_for_each_safe(pos,n,&pmt_list_head->pmt_list)
	{
		sw_ts_pmt_list_t *pmt_stream=list_entry(pos,sw_ts_pmt_list_t,pmt_list);
		if( pmt_stream == NULL )
			return;
		printf("program_num=0x%x,stream_type=0x%x,elementary_pid=0x%x,es_info_length=0x%x\n",																
																pmt_stream->program_num,
																pmt_stream->stream_type,
																pmt_stream->elementary_pid,
																pmt_stream->es_info_length );

		printf("节目号：%d\n",pmt_stream->program_num);
		if( pmt_stream->stream_type == 0x2 )
			printf("流类型：0x%x  --MPEG-2 视频\n",pmt_stream->stream_type);
		else if( pmt_stream->stream_type == 0x4 )
			printf("流类型：0x%x  --MPEG-2 音频\n",pmt_stream->stream_type);
		else if( pmt_stream->stream_type == 0x6 )
			printf("流类型：0x%x  --包含私有数据包的PES包\n",pmt_stream->stream_type);
		else
			printf("流类型：0x%x  --其他类型\n",pmt_stream->stream_type);
		
		printf("PID: 0X%X\n",pmt_stream->elementary_pid);
	}
}

/*
 *初始化保存解析pat内容的链表
 */
sw_ts_pat_list_t* init_pat_list()
{
	sw_ts_pat_list_t *head = (sw_ts_pat_list_t *)malloc(sizeof(sw_ts_pat_list_t));
	if( head != NULL )
	{
		/*让头节点的链表指针指向自己，防止乱指，避免产生段错误*/
		INIT_LIST_HEAD(&head->pat_list);
	}

	return head;
}

/*
 *初始化保存解析pmt内容的链表
 */
sw_ts_pmt_list_t* init_pmt_list()
{
	sw_ts_pmt_list_t *head = (sw_ts_pmt_list_t*)malloc(sizeof(sw_ts_pmt_list_t));
	if( head == NULL )
	{
		/*让头节点的链表指针指向自己，防止乱指，避免产生段错误*/
		INIT_LIST_HEAD(&head->pmt_list);
	}

	return head;
}

/*
 *将PAT解析出的内容加进链表中
 *return -1,成功；-1，失败
 */
int add_pat_list(sw_ts_pat_list_t pat_program,sw_ts_pat_list_t *pat_head)
{
	if( pat_head == NULL )
	{
		return -1;
	}
	sw_ts_pat_list_t *pat_list_head = pat_head;
	sw_ts_pat_list_t  *new_pat_program = (sw_ts_pat_list_t*)malloc(sizeof(sw_ts_pat_list_t));
	if( new_pat_program == NULL )
	{
		return -1;
	}
	new_pat_program->program_num = pat_program.program_num;
	new_pat_program->program_map_pid = pat_program.program_map_pid;

	/*让新节点的链表指针指向自己，防止乱指，避免产生段错误*/
	INIT_LIST_HEAD(&new_pat_program->pat_list);
	/*加进链表*/
	list_add(&new_pat_program->pat_list, &pat_list_head->pat_list);
	
	return 1;
}

/*
 *将PMT解析出的内容加进链表中
 *return -1,成功；-1，失败
 */
int add_pmt_list(sw_ts_pmt_list_t pmt_stream,sw_ts_pmt_list_t *pmt_head)
{
	if( pmt_head == NULL )
	{
		return -1;
	}
	sw_ts_pmt_list_t *pmt_list_head = pmt_head;

	sw_ts_pmt_list_t *new_pmt_stream = (sw_ts_pmt_list_t*)malloc(sizeof(sw_ts_pmt_list_t));
	if( new_pmt_stream == NULL)
	{
		return -1;
	}
	new_pmt_stream->stream_type = pmt_stream.stream_type;
	new_pmt_stream->elementary_pid = pmt_stream.elementary_pid;
	new_pmt_stream->es_info_length = pmt_stream.es_info_length;
	new_pmt_stream->program_num = pmt_stream.program_num;

	/*让新节点的链表指针指向自己，防止乱指，避免产生段错误*/
	INIT_LIST_HEAD(&new_pmt_stream->pmt_list);
	list_add(&new_pmt_stream->pmt_list, &pmt_list_head->pmt_list);

	return 1;

}


/*
 *释放pat_list链表的资源
 */
void free_pat_list(sw_ts_pat_list_t *pat_list_head)
{
	if( pat_list_head == NULL)
	{
		return;
	}
	struct list_head *pos = NULL; 
	struct list_head *n = NULL;	//sw_ts_pat_list_t的成员
	/*遍历小结构体struct list_head 链表*/
	list_for_each_safe(pos,n,&pat_list_head->pat_list)
	{
		/*
		 *用小结构体指针struct list_head *pos来求得
		 *大结构体sw_ts_pat_list_t *pat_program的指针
		 */
		sw_ts_pat_list_t *pat_program=list_entry(pos,sw_ts_pat_list_t,pat_list);
		if( pat_program != NULL )
		{
			free(pat_program);
			pat_program = NULL;
		}
	}
	pos = NULL;
	n = NULL;	
}

/*
 *释放pmt_list链表的资源
 */
void free_pmt_list(sw_ts_pmt_list_t* pmt_list_head)
{
	if( pmt_list_head == NULL )
	{
		return;
	}
	struct list_head *pos = NULL; 
	struct list_head *n = NULL;	//sw_ts_pat_list_t 里的
	list_for_each_safe(pos,n,&pmt_list_head->pmt_list)
	{
		sw_ts_pmt_list_t *pmt_stream=list_entry(pos,sw_ts_pmt_list_t,pmt_list);
		if( pmt_stream != NULL )
		{
			free(pmt_stream);
			pmt_stream = NULL;
		}
	}
	pos = NULL;
	n = NULL;
}


/*
 * 从src拷贝字符串到大小siz的dst中
 * 最多拷贝siz-1个字符， Always NUL terminates (unless siz == 0).
 * 返回strlen(src); 如果retval >= siz, 发生截断.
*/
size_t strlcpy( char *dst, const char *src, size_t siz )
{
    char* d = dst;
    const char* s = src;
    size_t n = siz;
    if ( s == 0 || d == 0 )
         return 0;
    /* Copy as many bytes as will fit */
    if (n != 0 && --n != 0)
    {
        do
        {
            if ((*d++ = *s++) == 0)
                break;
        } while (--n != 0);
    }
    /* Not enough room in dst, add NUL and traverse rest of src */
    if (n == 0)
    {
        if (siz != 0)
            *d = '\0';                /* NUL-terminate dst */
        while (*s++)
            ;
    }
    return(s - src - 1);        /* count does not include NUL */
}