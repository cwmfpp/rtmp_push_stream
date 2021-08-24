    
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <sys/epoll.h>
#include <stdlib.h>


#include "librtmp/rtmp.h"

#include "media_rtmp.h"

#if 0
#define MRtmpLog_Trace(fmt, x...)  printf("%s:%s:%d: " fmt "\n", __FILE__, __FUNCTION__, __LINE__, ##x);
#define MRtmpLog_Debug(fmt, x...)  printf("%s:%s:%d: " fmt "\n", __FILE__, __FUNCTION__, __LINE__, ##x);
#define MRtmpLog_Error(fmt, x...)  printf("%s:%s:%d: " fmt "\n", __FILE__, __FUNCTION__, __LINE__, ##x);
#define MRtmpLog_Warn(fmt, x...)  printf("%s:%s:%d: " fmt "\n", __FILE__, __FUNCTION__, __LINE__, ##x);
#else


#endif

#define RTMP_TIMESTAMP_INIT   (~0)

typedef struct
{//ISO/IEC 14496-3 ADTS²¿·Ö
    //adts_fixed_header
    int synword;                                        //0~11      12 bslbf
    unsigned char ID;                                   //12            1  bslbf
    unsigned char layer;                                //13~14     2  uimsbf
    unsigned char protection_absent;                    //15            1  bslbf
    unsigned char profile_ObjectType;                   //16~17     2  uimsbf
    unsigned char sampling_frequency_index;         //18~21     4  uimsbf
    unsigned char private_bit;                          //22            1  bslbf
    unsigned char channel_configuration;                //23~25     3  uimsbf
    unsigned char original_copy;                        //26            1  bslbf
    unsigned char home;                             //27            1  bslbf
    //adts_variable_header
    unsigned char copyright_identification_bit;         //28            1  bslbf
    unsigned char copyright_identification_start;           //29            1  bslbf
    unsigned char _[1];
    int aac_frame_length;                               //30~42     13 bslbf
    int adts_buffer_fullness;                           //33~53     11 bslbf
    unsigned char number_of_raw_data_blocks_in_frame;   //54~55     2 uimsfb
    unsigned char __[3];
}TADTSHeader;

#define ADTS_HEADER_LENGTH 7



typedef struct _RtmpInfo
{
    RTMP *m_pstRTMP;
    RtmpAttribute m_stRtmpAttribute;
    int m_iIsSendKeyFrame;
    int m_iIsSendVideoConfig;
    TADTSHeader m_stTADTSHeader;
    unsigned int m_uiVideoTimestampPrev;
    unsigned int m_uiVideoTimestampSum;
    unsigned int m_uiAudioTimestampPrev;
    unsigned int m_uiAudioTimestampSum;
}RtmpInfo;

static int InitRtmpAttribute(RtmpAttribute *_pstRtmpAttribute)
{
    int iRet = 0;
    if(NULL == _pstRtmpAttribute)
    {
        MRtmpLog_Error("invalid _pstRtmpAttribute(%p)", _pstRtmpAttribute);
        iRet = -1;
        goto end;
    }

    _pstRtmpAttribute->m_iProtocol = MEDIA_RTMP_FEATURE_WRITE;
    _pstRtmpAttribute->m_pcUrlArry[0] = '\0';
    
end:
    return iRet;
}

static int InitTADTSHeader(TADTSHeader *_pstTADTSHeader)
{
    int iRet = 0;
    if(NULL == _pstTADTSHeader)
    {
        MRtmpLog_Error("invalid _pstTADTSHeader(%p)", _pstTADTSHeader);
        iRet = -1;
        goto end;
    }
    
    _pstTADTSHeader->synword = 0;
    _pstTADTSHeader->layer = 0;
    _pstTADTSHeader->protection_absent = 0;
    _pstTADTSHeader->profile_ObjectType = 0;
    _pstTADTSHeader->sampling_frequency_index = 0;
    _pstTADTSHeader->private_bit = 0;
    _pstTADTSHeader->channel_configuration = 0;
    _pstTADTSHeader->original_copy = 0;
    _pstTADTSHeader->home = 0;
    _pstTADTSHeader->copyright_identification_bit = 0;
    _pstTADTSHeader->copyright_identification_start = 0;
    _pstTADTSHeader->_[0] = '\0';
    _pstTADTSHeader->aac_frame_length = 0;
    _pstTADTSHeader->adts_buffer_fullness = 0;
    _pstTADTSHeader->number_of_raw_data_blocks_in_frame = 0;
    _pstTADTSHeader->__[0] = '\0';
    
end:
    return iRet;
}

void *RTMP_Create()
{
    void *pvRtmpH = NULL;
    RtmpInfo *pstRtmpInfo = NULL;
    RTMP *pstRTMP = NULL;
    
    pstRtmpInfo = (RtmpInfo *)malloc(sizeof(RtmpInfo));
    if(NULL == pstRtmpInfo)
    {
        MRtmpLog_Error("call malloc failed!");
        goto end;
    }
    memset(pstRtmpInfo, 0, sizeof(RtmpInfo));

    pstRTMP = RTMP_Alloc();
    if(NULL == pstRTMP)
    {
        MRtmpLog_Error("call RTMP_Alloc failed!");
        goto end;
    }

    RTMP_Init(pstRTMP);

    pstRtmpInfo->m_pstRTMP = pstRTMP;

    if(InitRtmpAttribute(&pstRtmpInfo->m_stRtmpAttribute) < 0)
    {
        MRtmpLog_Error("call InitRtmpAttribute failed!");
        goto end;
    }
    pstRtmpInfo->m_iIsSendKeyFrame = 1;
    pstRtmpInfo->m_iIsSendVideoConfig = 1;
    pstRtmpInfo->m_uiVideoTimestampPrev = RTMP_TIMESTAMP_INIT;
    pstRtmpInfo->m_uiVideoTimestampSum = 0;
    pstRtmpInfo->m_uiAudioTimestampPrev = RTMP_TIMESTAMP_INIT;
    pstRtmpInfo->m_uiAudioTimestampSum = 0;

    if(InitTADTSHeader(&pstRtmpInfo->m_stTADTSHeader) < 0)
    {
        MRtmpLog_Error("call InitTADTSHeader failed!");
        goto end;
    }
    
    pvRtmpH = pstRtmpInfo;
    
end:
    
    if(NULL == pvRtmpH)
    {
        if(NULL != pstRTMP)
        {
            RTMP_Free(pstRTMP);
            pstRTMP = NULL;
        }
        if(NULL != pstRtmpInfo)
        {
            free(pstRtmpInfo);
            pstRtmpInfo = NULL;
        }
    }
    
    return pvRtmpH;
}

int RTMP_SetAttribute(void *_pvRtmpH, RtmpAttribute *_pstRtmpAttribute)
{
    int iRet = 0;
    RtmpInfo *pstRtmpInfo = NULL;

    if(NULL == _pvRtmpH ||
        NULL == _pstRtmpAttribute)
    {
        MRtmpLog_Error("invalid _pvRtmpH(%p) _pstRtmpAttribute(%p)", _pvRtmpH, _pstRtmpAttribute);
        iRet = -1;
        goto end;
    }

    pstRtmpInfo = (RtmpInfo *)_pvRtmpH;

    memcpy(&pstRtmpInfo->m_stRtmpAttribute, _pstRtmpAttribute, sizeof(RtmpAttribute));
    
end:
    return iRet;
}

static int RTMPSetChunkSize(RTMP *rtmp, int val)
{
#if 0
    return TRUE;
#else
    RTMPPacket pack;
    if(RTMPPacket_Alloc(&pack, 4) != FALSE)
    {
        pack.m_headerType = RTMP_PACKET_SIZE_LARGE;
        pack.m_packetType = 0x01;
        pack.m_hasAbsTimestamp = FALSE;
        pack.m_nChannel = 0x02;
        pack.m_nTimeStamp = 0;
        pack.m_nInfoField2 = 0;
        pack.m_nBodySize = 4;
        pack.m_nBytesRead = 0;
        
        pack.m_body[3] = val & 0xff;
        pack.m_body[2] = val >> 8;
        pack.m_body[1] = val >> 16;
        pack.m_body[0] = val >> 24;
        rtmp->m_outChunkSize = val;
        if(RTMP_SendPacket(rtmp, &pack, 0) == FALSE)
        {
            RTMPPacket_Free(&pack);
            goto ERROR;
        }
        RTMPPacket_Free(&pack);
    }

    return TRUE;
ERROR:
    return FALSE;
#endif
}



static int RTMPSetDataFrame()
{

    return 0;
}

static int RtmpSetSocketFdBlock(int _iSocketFd)
{
    int flags;

    flags = fcntl(_iSocketFd, F_GETFL);
    if (flags == -1)
        return -1;

    flags &= ~O_NONBLOCK;
    flags = fcntl(_iSocketFd, F_SETFL, flags);
    return flags;
}

/* nonblocking socket */
static int RtmpSetSocketFdNonBlock(int _iSocketFd)
{
    int flags;

    flags = fcntl(_iSocketFd, F_GETFL);
    if (flags == -1)
        return -1;

    flags |= O_NONBLOCK;
    flags = fcntl(_iSocketFd, F_SETFL, flags);
    return flags;
}


static int RtmpSetSocketFdRecvTimeout(int _iSocketFd)
{
    struct timeval nTimeout;
    nTimeout.tv_sec = 0;   
    nTimeout.tv_usec = 100 * 1000;
    
    if(setsockopt(_iSocketFd, SOL_SOCKET,SO_RCVTIMEO,(char *)&nTimeout,sizeof(nTimeout)) < 0)
    {
        MRtmpLog_Trace("NULL == _pRtmpServerInfo");
        return -1;
    }

    return 0;
}

static int RtmpSetSocketFdSendTimeout(int _iSocketFd)
{
    struct timeval nTimeout;
    nTimeout.tv_sec = 0;   
    nTimeout.tv_usec = 200 * 1000;
    
    if(setsockopt(_iSocketFd, SOL_SOCKET,SO_SNDTIMEO,(char *)&nTimeout,sizeof(nTimeout)) < 0)
    {
        MRtmpLog_Trace("NULL == _pRtmpServerInfo");
        return -1;
    }

    return 0;
}
 
static int RtmpSetSocketFdRecvBufferSize(int _iSocketFd)
{
    int size = 0;
    
    size = 128*1024;
    if(setsockopt(_iSocketFd, SOL_SOCKET, SO_RCVBUF, (void *) &size, sizeof (int)) == -1)
    {
        MRtmpLog_Trace("setsockopt: unable to set socket buffer size");
        return -1;
    }
    
    return 0;
}

static int RtmpSetSocketFdSendBufferSize(int _iSocketFd)
{
    int size = 0;
    
    size = 128*1024;
    if(setsockopt(_iSocketFd, SOL_SOCKET, SO_SNDBUF, (void *) &size, sizeof (int)) == -1)
    {
        MRtmpLog_Trace("setsockopt: unable to set socket buffer size");
        return -1;
    }
    
    return 0;
}


static int RtmpGetSocketFdSendBufferSize(int _iSocketFd)
{
    int size = 0;
    socklen_t optlen;
    optlen = sizeof(int);
    
    if(getsockopt(_iSocketFd, SOL_SOCKET, SO_SNDBUF, (void *) &size, &optlen) == -1)
    {
        MRtmpLog_Trace("setsockopt: unable to set socket buffer size");
        return -1;
    }
        
    return 0;
}


#if 0
static int RtmpDisableTcpNagle(int _iSocketFd)
{
    /* Disable the Nagle (TCP No Delay) algorithm */
    int flag = 0;
    
    flag = 1;
    if(-1 == setsockopt( _iSocketFd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag) ))
    {
        MRtmpLog_Error("Couldn't setsockopt(TCP_NODELAY)\n");
        return -1;
    }
   
    return 0;
}
#endif

int RTMP_ConnectProtocol(void *_pvRtmpH)
{
    int iRet = 0;
    RtmpInfo *pstRtmpInfo = NULL;
    char *pcRtmpUrl = NULL;
    RTMP *pstRTMP = NULL;
    int iProtocol = 0;
    int iRtmpSocket = -1;
    
    if(NULL == _pvRtmpH)
    {
        MRtmpLog_Error("invalid _pvRtmpH(%p)", _pvRtmpH);
        iRet = -1;
        goto end;
    }

    pstRtmpInfo = (RtmpInfo *)_pvRtmpH;
    
    pcRtmpUrl = pstRtmpInfo->m_stRtmpAttribute.m_pcUrlArry;
    iProtocol = pstRtmpInfo->m_stRtmpAttribute.m_iProtocol;
    
    if(strlen(pcRtmpUrl) < 8)
    {
        MRtmpLog_Error("invalid pcRtmpUrl:%s", pcRtmpUrl);
        iRet = -1;
        goto end;
    }

    if(NULL == pstRtmpInfo->m_pstRTMP)
    {
        MRtmpLog_Error("invalid pstRtmpInfo->m_pstRTMP(%p)", pstRtmpInfo->m_pstRTMP);
        iRet = -1;
        goto end;
    }

    pstRTMP = pstRtmpInfo->m_pstRTMP;
    if(RTMP_SetupURL(pstRTMP, pcRtmpUrl) < 0)
    {
        MRtmpLog_Error("call RTMP_SetupURL failed!");
        iRet = -1;
        goto end;
    }

    if(MEDIA_RTMP_FEATURE_WRITE == iProtocol)
    {
        RTMP_EnableWrite(pstRTMP);
    }
    
    if(RTMP_Connect(pstRTMP, NULL) < 0)
    {
        MRtmpLog_Error("call RTMP_Connect failed!");
        iRet = -1;
        goto end;
    }

    if(1 != RTMP_IsConnected(pstRTMP))
    {
        MRtmpLog_Error("call RTMP_IsConnected failed for socket is invalid!");
        iRet = -1;
        goto end;
    }

    if(RTMP_ConnectStream(pstRTMP, 0) < 0)
    {
        MRtmpLog_Error("call RTMP_ConnectStream failed!");
        iRet = -1;
        goto end;
    }

    if(RTMPSetChunkSize(pstRTMP, 1380) < 0)
    {
        MRtmpLog_Error("call RTMPSetChunkSize failed!");
        iRet = -1;
        goto end;
    }

    iRtmpSocket = RTMP_Socket(pstRTMP);
    if(iRtmpSocket <= 0)
    {
        MRtmpLog_Error("call RTMP_Socket failed!");
        iRet = -1;
        goto end;
    }
    
    if(RtmpSetSocketFdSendTimeout(iRtmpSocket) < 0)
    {
        MRtmpLog_Error("call RtmpSetSocketFdSendTimeout failed!");
        iRet = -1;
        goto end;
    }
    
end:
    return iRet;
}


/* NAL unit types */
enum {
    NAL_AVCC_SLICE           = 1,
    NAL_AVCC_DPA             = 2,
    NAL_AVCC_DPB             = 3,
    NAL_AVCC_DPC             = 4,
    NAL_AVCC_IDR_SLICE       = 5,
    NAL_AVCC_SEI             = 6,
    NAL_AVCC_SPS             = 7,
    NAL_AVCC_PPS             = 8,
    NAL_AVCC_AUD             = 9,
    NAL_AVCC_END_SEQUENCE    = 10,
    NAL_AVCC_END_STREAM      = 11,
    NAL_AVCC_FILLER_DATA     = 12,
    NAL_AVCC_SPS_EXT         = 13,
    NAL_AVCC_AUXILIARY_SLICE = 19,
    NAL_AVCC_FF_IGNORE       = 0xff0f001,
};

typedef struct
{// NALU
    int m_iType;  
    int m_iVedioSize;  
    unsigned char* m_pucVedioData;  
}TMP4Nalu;

static int RTMPH264_AnalyzeNalu(unsigned char* _pcVedioBuf, unsigned int _uiVedioBufLen, unsigned int _uiOffSet, TMP4Nalu* _pstNalu)
{
    int iThisFunRes = -1;
    unsigned char* pcVedioBuf = NULL;
    int iVedioBufLen = 0;
    TMP4Nalu* pstNalu = NULL;
    int i = 0;
    int iPos = 0;
    int iPrevType = 0;
    int iNextType = 0;
    
    if((NULL == _pcVedioBuf) || (NULL == _pstNalu))
    {
        MRtmpLog_Error("%d: Input parameters is error!\n", __LINE__);
        iThisFunRes = -1;
        goto end;
    }
    
    pcVedioBuf = (unsigned char*)_pcVedioBuf;
    iVedioBufLen = (int)_uiVedioBufLen;
    i = (int)_uiOffSet;
    pstNalu = _pstNalu;
 
    while(i<iVedioBufLen)  
    {  
        if(pcVedioBuf[i++] == 0x00 && pcVedioBuf[i++] == 0x00 && pcVedioBuf[i++] == 0x00 && pcVedioBuf[i++] == 0x01)
        {
            iPos = i;
            iPrevType = pcVedioBuf[iPos] & 0x1f;
            while (iPos<iVedioBufLen)  
            {  
                if(pcVedioBuf[iPos+0] == 0x00 && pcVedioBuf[iPos+1] == 0x00 && pcVedioBuf[iPos+2] == 0x00 && pcVedioBuf[iPos+3] == 0x01)  
                {  
                    iPos += 4;

                    iNextType = pcVedioBuf[iPos] & 0x1f;                        
                    if(iNextType == iPrevType)
                    {
                        continue;
                    }

                    break;  
                }  
                iPos = iPos + 1;
            }  
            
            if(iPos == iVedioBufLen)  
            {  
                pstNalu->m_iVedioSize= iPos-i;
            }  
            else  
            {  
                pstNalu->m_iVedioSize = (iPos-4)-i;  
            }
            pstNalu->m_iType = pcVedioBuf[i] & 0x1f;
            pstNalu->m_pucVedioData =(unsigned char*)&pcVedioBuf[i];    
            iThisFunRes = (pstNalu->m_iVedioSize+i-(int)_uiOffSet); 
            goto end;
        }  
    } 
    
    iThisFunRes = 0;
    
end:
    return iThisFunRes;  
}


int H264_Probe(unsigned char *_pData, int _iDataSize)
{
    uint32_t code = (unsigned int)-1;
    int sps = 0, pps = 0, idr = 0, res = 0, sli = 0;
    int i;

    if(NULL == _pData)
    {
        return -1;
    }

    for (i = 0; i < _iDataSize; i++) {
        code = (code << 8) + _pData[i];
        if ((code & 0xffffff00) == 0x100) {
            int ref_idc = (code >> 5) & 3;
            int type    = code & 0x1F;
            static const int8_t ref_zero[] = {
                 2,  0,  0,  0,  0, -1,  1, -1,
                -1,  1,  1,  1,  1, -1,  2,  2,
                 2,  2,  2,  0,  2,  2,  2,  2,
                 2,  2,  2,  2,  2,  2,  2,  2
            };

            if (code & 0x80) // forbidden_bit
                return 0;

            if (ref_zero[type] == 1 && ref_idc)
                return 0;
            if (ref_zero[type] == -1 && !ref_idc)
                return 0;
            if (ref_zero[type] == 2) {
                if (!(code == 0x100 && !_pData[i + 1] && !_pData[i + 2]))
                    res++;
            }

            switch (type) {
            case 1:
                sli++;
                break;
            case 5:
                idr++;
                break;
            case 7:
                if (_pData[i + 2] & 0x03)
                    return 0;
                sps++;
                break;
            case 8:
                pps++;
                break;
            default:
                break;
            }
        }
    }

    if (sps && pps && (idr || sli > 3) && res < (sps + pps + idr))
        return 1;  // 1 more than .mpg

    return 0;
}

static int RTMPAVDataPacket(RTMP *_pstRTMP, unsigned char _ucHeaderType, unsigned char pt, unsigned int timestamp, char *body, int bodyLen, char *body1, int body1Len)
{
    int iRet = 0;
    
#if 1
    if((body == NULL && body1 == NULL)
    ||(bodyLen == 0 && body1Len == 0)
    ||bodyLen < 0
    ||body1Len < 0
    ||RTMP_IsConnected(_pstRTMP) == FALSE)
    {
        MRtmpLog_Error("invalid data");
        MRtmpLog_Error("RTMP_IsConnected(_pstRTMP)=%d", RTMP_IsConnected(_pstRTMP));
        iRet = -1;
        goto end;
    }
#endif
    int iBodySize = bodyLen + body1Len;
    RTMPPacket packet;
    if(RTMPPacket_Alloc(&packet, iBodySize) == FALSE)
    {
        MRtmpLog_Error("call RTMPPacket_Alloc failed!");
        iRet = -1;
        goto end;
    }
    
    packet.m_headerType = _ucHeaderType;
    packet.m_packetType = pt;
    packet.m_hasAbsTimestamp = FALSE;
    if(RTMP_PACKET_TYPE_VIDEO == pt)
    {
        packet.m_nChannel = 0x04;
    }else
    {
        packet.m_nChannel = 0x05;
    }
    packet.m_nTimeStamp = timestamp;  
    packet.m_nInfoField2 = 1;//node->rtmplink->m_stream_id;
    packet.m_nBodySize = iBodySize;
    packet.m_nBytesRead = 0;

    if(body != NULL && bodyLen != 0)
    {
        memcpy(packet.m_body, body, bodyLen);
    }
    if(body1 != NULL && body1Len != 0)
    {
        memcpy(packet.m_body + bodyLen, body1, body1Len);
    }
    if(RTMP_SendPacket(_pstRTMP, &packet, FALSE) == FALSE)
    {
        RTMPPacket_Free(&packet);
        MRtmpLog_Error("call RTMP_SendPacket failed!");
        iRet = -1;
        goto end;
    }
    RTMPPacket_Free(&packet);
    
end:
    
    return iRet;
}

static void RTMPAVCSeqHdrA(char *sps, int spsLen, char *pps, int ppsLen, char *seqhdr, int *seqhdrLen)
{
    int i = 0;
    int x = 0;
    
    if(NULL == sps || NULL == pps || NULL == seqhdr || NULL == seqhdrLen)
    {
        MRtmpLog_Error("invalid sps(%p) pps(%p) seqhdr(%p) seqhdrLen(%p)", sps, pps, seqhdr, seqhdrLen);
        return;
    }

    if((16 + spsLen + ppsLen) > *seqhdrLen)
    {
        MRtmpLog_Error("invalid (16 + spsLen(%d) + ppsLen(%d)) > *seqhdrLen(%d)", spsLen, ppsLen, *seqhdrLen);
        return;
    }
    
    seqhdr[x++] = 0x17;
    seqhdr[x++] = 0x00;
    seqhdr[x++] = 0x00;
    seqhdr[x++] = 0x00;
    seqhdr[x++] = 0x00;
    seqhdr[x++] = 0x01;
    seqhdr[x++] = sps[1];
    seqhdr[x++] = sps[2];
    seqhdr[x++] = sps[3];
    seqhdr[x++] = 0xff;
    seqhdr[x++] = 0xE1;
    seqhdr[x++] = spsLen>>8;
    seqhdr[x++] = spsLen&0xff;
    for(i = 0; i < spsLen; i++)
    {
        seqhdr[x++] = sps[i];
    }
    seqhdr[x++] = 0x01;
    seqhdr[x++] = ppsLen>>8;
    seqhdr[x++] = ppsLen&0xff;
    for(i = 0; i < ppsLen; i++)
    {
        seqhdr[x++] = pps[i];
    }

    *seqhdrLen = x;
    return;
}

static int RTMPSendH264Config(RTMP * _pstRTMP, unsigned int _uiTimestamp, char *_pcSps, int _iSpsLen, char *_pcPps, int _iPpsLen)
{
    int iRet = 0;
    char pcSeqHdrArry[128] = {0};
    int iSeqHdrLen = 0;

    iSeqHdrLen = sizeof(pcSeqHdrArry);
    RTMPAVCSeqHdrA(_pcSps, _iSpsLen, _pcPps, _iPpsLen, pcSeqHdrArry, &iSeqHdrLen);
    if(iSeqHdrLen <= 0)
    {
        MRtmpLog_Debug("invalid iSeqHdrLen(%d) <= 0", iSeqHdrLen);
        iRet = -1;
        goto end;
    }

    if(RTMPAVDataPacket(_pstRTMP, RTMP_PACKET_SIZE_LARGE, RTMP_PACKET_TYPE_VIDEO, _uiTimestamp, pcSeqHdrArry, iSeqHdrLen, NULL, 0) < 0)
    {
        MRtmpLog_Debug("call RTMPAVDataPacket failed!");
        iRet = -1;
        goto end;

    }
    
end:    
    return iRet;
}

static int RTMPSendH264Data(RTMP * _pstRTMP, unsigned int _uiTimestamp, int _iIsKeyFrame, char *_pcVData, int _iVDataLen)
{
    int iRet = 0;
    char pcTagVideoArr[32]= {0};
    int x = 0;
    
    if(1 == _iIsKeyFrame)
    {
        pcTagVideoArr[x++] = 0x17;
    }
    else
    {
        pcTagVideoArr[x++] = 0x27;
    }

    pcTagVideoArr[x++] = 0x01;
    pcTagVideoArr[x++] = 0x00;
    pcTagVideoArr[x++] = 0x00;
    pcTagVideoArr[x++] = 0x00;
    pcTagVideoArr[x++] = (_iVDataLen>>24)&0xff;
    pcTagVideoArr[x++] = (_iVDataLen>>16)&0xff;
    pcTagVideoArr[x++] = (_iVDataLen>>8)&0xff;
    pcTagVideoArr[x++] = _iVDataLen&0xff;

    if(RTMPAVDataPacket(_pstRTMP, RTMP_PACKET_SIZE_MEDIUM, RTMP_PACKET_TYPE_VIDEO, _uiTimestamp, pcTagVideoArr, x, _pcVData, _iVDataLen) < 0)
    {
        MRtmpLog_Debug("call RTMPAVDataPacket failed!");
        iRet = -1;
        goto end;

    }

end:
    
    return iRet;
}

static int RTMPSendVideoData(RtmpInfo *_pstRtmpInfo, char *_pcVData, int _iDataLen, RtmpPacketInfo *_pstRtmpPacketInfo)
{
    int iRet = 0;
    RTMP *pstRTMP = NULL;
    char* pcH264 = NULL;
    int iH264Size = 0;
    int iPos = 0;
    int iAnalyzeRes = 0;
    TMP4Nalu stNalu = {0};
    char *pcSps = NULL;
    int iSpsLen = 0;
    char *pcPps = NULL;
    int iPpsLen = 0;
    unsigned int uiTimestamp = 0;
    
    if(NULL == _pstRtmpInfo ||
        NULL == _pcVData ||
        NULL == _pstRtmpPacketInfo)
    {
        iRet = -1;
        goto end;
    }
    
    pstRTMP = _pstRtmpInfo->m_pstRTMP;

    if(RTMP_TIMESTAMP_INIT == _pstRtmpInfo->m_uiVideoTimestampPrev)
    {
        _pstRtmpInfo->m_uiVideoTimestampPrev = _pstRtmpPacketInfo->m_uiTimeStampAbs;
    }

    if(_pstRtmpPacketInfo->m_uiTimeStampAbs > _pstRtmpInfo->m_uiVideoTimestampPrev)
    {
        _pstRtmpInfo->m_uiVideoTimestampSum = _pstRtmpInfo->m_uiVideoTimestampSum + (_pstRtmpPacketInfo->m_uiTimeStampAbs - _pstRtmpInfo->m_uiVideoTimestampPrev);
    }
    
    _pstRtmpInfo->m_uiVideoTimestampPrev = _pstRtmpPacketInfo->m_uiTimeStampAbs;

    uiTimestamp = _pstRtmpInfo->m_uiVideoTimestampSum;
    
    pcH264 = _pcVData;
    iH264Size = _iDataLen;
    
    while (0 != (iAnalyzeRes = RTMPH264_AnalyzeNalu((unsigned char *)pcH264, (unsigned int)iH264Size, (unsigned int)iPos, &stNalu)))   
    {        
        iPos += iAnalyzeRes;
    
        stNalu.m_pucVedioData -= 4;
        stNalu.m_iVedioSize += 4;
        

        if(1 == _pstRtmpInfo->m_iIsSendKeyFrame)
        {
            if(NAL_AVCC_SPS == stNalu.m_iType)
            {
                _pstRtmpInfo->m_iIsSendKeyFrame = 0;
                iRet = 0;
                MRtmpLog_Debug("find Key Frame successful");
            }else
            {
                MRtmpLog_Debug("continue find Key Frame");
                iRet = -1;
                continue;
            }
        }
        
        if(NAL_AVCC_SLICE == stNalu.m_iType)
        {
            if(RTMPSendH264Data(pstRTMP, uiTimestamp, 0, (char *)(stNalu.m_pucVedioData), stNalu.m_iVedioSize) < 0)
            {
                MRtmpLog_Error("call RTMPSendH264Data failed!");
                iRet = -1;
                goto end;
            }
        }else if(NAL_AVCC_SPS == stNalu.m_iType)
        {
            if(1 == _pstRtmpInfo->m_iIsSendVideoConfig)
            {
                pcSps = (char *)(stNalu.m_pucVedioData) + 4;
                iSpsLen = stNalu.m_iVedioSize - 4;
            }
            
        }else if(NAL_AVCC_PPS == stNalu.m_iType)
        {
            if(1 == _pstRtmpInfo->m_iIsSendVideoConfig)
            {
                MRtmpLog_Debug("send h264 config");
                pcPps = (char *)(stNalu.m_pucVedioData) + 4;
                iPpsLen = stNalu.m_iVedioSize - 4;
                if(RTMPSendH264Config(pstRTMP, uiTimestamp, pcSps, iSpsLen, pcPps, iPpsLen) < 0)
                {
                    MRtmpLog_Error("call RTMPSendH264Config failed!");
                    iRet = -1;
                    goto end;
                }
                _pstRtmpInfo->m_iIsSendVideoConfig = 0;
            }
        }else if(NAL_AVCC_IDR_SLICE == stNalu.m_iType)
        {
            if(RTMPSendH264Data(pstRTMP, uiTimestamp, 1, (char *)(stNalu.m_pucVedioData), stNalu.m_iVedioSize) < 0)
            {
                MRtmpLog_Error("call RTMPSendH264Data failed!");
                iRet = -1;
                goto end;
            }      
        }else if(NAL_AVCC_SEI == stNalu.m_iType)
        {
    
        }else
        {
            MRtmpLog_Debug("continue stNalu.m_iType=%d\n", stNalu.m_iType);
            continue;
        }
        
    }
    

end:
    return iRet;
}

int RTMP_SendVideoData(void *_pvRtmpH, char *_pcVData, int _iDataLen, RtmpPacketInfo *_pstRtmpPacketInfo)
{
    int iRet = 0;

    if(NULL == _pvRtmpH ||
        NULL == _pcVData ||
        NULL == _pstRtmpPacketInfo)
    {
        MRtmpLog_Error("invalid _pvRtmpH(%p) _pcVData(%p) _pstRtmpPacketInfo(%p)", _pvRtmpH, _pcVData, _pstRtmpPacketInfo);
        iRet = -1;
        goto end;
    }

    if(RTMPSendVideoData((RtmpInfo *)_pvRtmpH, _pcVData, _iDataLen, _pstRtmpPacketInfo) < 0)
    {
        MRtmpLog_Error("call RTMPSendVideoData failed!");
        iRet = -1;
        goto end;
    }
    
end:
    return iRet;
}

static int decode_adts_header(TADTSHeader *header, char *aac_buf, int aac_len)
{
    if(NULL==header|| NULL==aac_buf || aac_len<ADTS_HEADER_LENGTH) 
    {
        MRtmpLog_Trace("(NULL==header|| NULL==aac_buf || aac_len<ADTS_HEADER_LENGTH)");
        return -1;
    }

    if ((aac_buf[0] == 0xFF)&&((aac_buf[1] & 0xF0) == 0xF0))      //syncword 12¸ö1
    {
        header->synword = (aac_buf[0] << 4 )  | (aac_buf[1] >> 4);
        header->ID = ((unsigned int) aac_buf[1] & 0x08) >> 3;
        header->layer = ((unsigned int) aac_buf[1] & 0x06) >> 1;
        header->protection_absent = (unsigned int) aac_buf[1] & 0x01;
        header->profile_ObjectType = ((unsigned int) aac_buf[2] & 0xc0) >> 6;
        header->sampling_frequency_index = ((unsigned int) aac_buf[2] & 0x3c) >> 2;
        header->private_bit = ((unsigned int) aac_buf[2] & 0x02) >> 1;
        header->channel_configuration = ((((unsigned int) aac_buf[2] & 0x01) << 2) | (((unsigned int) aac_buf[3] & 0xc0) >> 6));
        header->original_copy = ((unsigned int) aac_buf[3] & 0x20) >> 5;
        header->home = ((unsigned int) aac_buf[3] & 0x10) >> 4;
        header->copyright_identification_bit = ((unsigned int) aac_buf[3] & 0x08) >> 3;
        header->copyright_identification_start = (unsigned int) aac_buf[3] & 0x04 >> 2;     
        header->aac_frame_length = (((((unsigned int) aac_buf[3]) & 0x03) << 11) | (((unsigned int) aac_buf[4] & 0xFF) << 3)| ((unsigned int) aac_buf[5] & 0xE0) >> 5) ;
        header->adts_buffer_fullness = (((unsigned int) aac_buf[5] & 0x1f) << 6 | ((unsigned int) aac_buf[6] & 0xfc) >> 2);
        header->number_of_raw_data_blocks_in_frame = ((unsigned int) aac_buf[6] & 0x03);

        return 0;
    }
    else 
    {
        MRtmpLog_Trace("ADTS_HEADER : BUF ERROR\n");

        return -1;
    }
    
}

static int get_aac_frame_count(void * _pcframedata, int size)
{
    int iCountaac = 0;
    char *audioStart = NULL;
    int audioLeftSize = 0;
    
    if (NULL == _pcframedata || size <= 0)
    {
        MRtmpLog_Error("Input parameters is error!\n");
        return -1;
    }
    
    audioStart = (char*)_pcframedata;
    audioLeftSize = size;
    for(iCountaac = 0; audioLeftSize > ADTS_HEADER_LENGTH; iCountaac++)
    {
        TADTSHeader tHeader;
        memset(&tHeader, 0, sizeof(TADTSHeader));
        decode_adts_header(&tHeader, audioStart, audioLeftSize);
        if(tHeader.aac_frame_length <= 0)
        {
            break;
        }
        audioStart += tHeader.aac_frame_length;
        audioLeftSize -= tHeader.aac_frame_length;
    }
    
    return iCountaac;
}

static int RTMPSendAACConfig(RTMP *_pstRTMP, TADTSHeader *_pstTADTSHeader)
{
    int iRet = 0;
    int x = 0;
    char pcTagAudioArr[16];

    x = 0;
    pcTagAudioArr[x++] = 0xAF;
    pcTagAudioArr[x++] = 0x00;
    pcTagAudioArr[x++] = ((_pstTADTSHeader->profile_ObjectType & 0xff) << 3)|((_pstTADTSHeader->sampling_frequency_index >> 1) & 0x07);
    pcTagAudioArr[x++] = (((_pstTADTSHeader->sampling_frequency_index & 0x01) << 7)|((_pstTADTSHeader->channel_configuration & 0xff) <<3)) & 0xf8;
    if(RTMPAVDataPacket(_pstRTMP, RTMP_PACKET_SIZE_LARGE, RTMP_PACKET_TYPE_AUDIO, 0, pcTagAudioArr, x, NULL, 0) < 0)
    {
        MRtmpLog_Debug("call RTMPAVDataPacket failed!");
        iRet = -1;
        goto end;
    }

end:
    return iRet;
}

static int RTMPSendAACData(RTMP *_pstRTMP, char *_pcAData, int _iADataLen, unsigned int _uiTimestamp)
{
    int iRet = 0;
    char pcTagAudioArr[32]= {0};
    int x = 0;
    
    x = 0;
    pcTagAudioArr[x++] = 0xAF;
    pcTagAudioArr[x++] = 0x01;

    if(RTMPAVDataPacket(_pstRTMP, RTMP_PACKET_SIZE_LARGE, RTMP_PACKET_TYPE_AUDIO, _uiTimestamp, pcTagAudioArr, x, _pcAData, _iADataLen) < 0)
    {
        MRtmpLog_Debug("call RTMPAVDataPacket failed!");
        iRet = -1;
        goto end;

    }

end:

    return iRet;
}


static int RTMPSendAudioData(RtmpInfo *_pstRtmpInfo, char *_pcAData, int _iDataLen, RtmpPacketInfo *_pstRtmpPacketInfo)
{
    int iRet = 0;
    unsigned int uiTimeStamp = 0;
    int i = 0;
    
    if(NULL == _pstRtmpInfo ||
        NULL == _pcAData ||
        _iDataLen <= 0 ||
        NULL == _pstRtmpPacketInfo)
    {
        MRtmpLog_Error("invalid _pstRtmpInfo(%p) _pcAData(%p) _iDataLen(%d) _pstRtmpPacketInfo(%p)", _pstRtmpInfo, _pcAData, _iDataLen, _pstRtmpPacketInfo);
        iRet = -1;
        goto end;
    }

    if(RTMP_TIMESTAMP_INIT == _pstRtmpInfo->m_uiAudioTimestampPrev)
    {
        _pstRtmpInfo->m_uiAudioTimestampPrev = _pstRtmpPacketInfo->m_uiTimeStampAbs;
    }

    if(_pstRtmpPacketInfo->m_uiTimeStampAbs > _pstRtmpInfo->m_uiAudioTimestampPrev)
    {
        _pstRtmpInfo->m_uiAudioTimestampSum = _pstRtmpInfo->m_uiAudioTimestampSum + (_pstRtmpPacketInfo->m_uiTimeStampAbs - _pstRtmpInfo->m_uiAudioTimestampPrev);
    }
    
    _pstRtmpInfo->m_uiAudioTimestampPrev = _pstRtmpPacketInfo->m_uiTimeStampAbs;

    uiTimeStamp = _pstRtmpInfo->m_uiAudioTimestampSum;

    //aac
    if(_pcAData[0] == 0xff && (_pcAData[1] >> 4) == 0xf)
    {
        int AACFrameCount = 0;
        AACFrameCount = get_aac_frame_count(_pcAData, _iDataLen);
        TADTSHeader tHeader = {0};
        char *audioStart = NULL;
        int audioLeftSize= 0;
        int iSendConfig = 0;
        
        if(AACFrameCount <= 0)
        {
            MRtmpLog_Warn("AACFrameCount=%d", AACFrameCount);
            goto end;
        }
        
        audioStart = _pcAData;
        audioLeftSize = _iDataLen;
        
        for(i = 0; i < AACFrameCount; i++)
        {
            decode_adts_header(&tHeader, (char*)audioStart, audioLeftSize);            

            if(_pstRtmpInfo->m_stTADTSHeader.profile_ObjectType != tHeader.profile_ObjectType || 
                _pstRtmpInfo->m_stTADTSHeader.sampling_frequency_index != tHeader.sampling_frequency_index)
            {
                MRtmpLog_Debug("send aac config");
                MRtmpLog_Debug("tHeader.profile_ObjectType=%d", tHeader.profile_ObjectType);
                MRtmpLog_Debug("tHeader.sampling_frequency_index=%d", tHeader.sampling_frequency_index);
                if(RTMPSendAACConfig(_pstRtmpInfo->m_pstRTMP, &tHeader) < 0)
                {
                    MRtmpLog_Error("call RTMPSendAACConfig failed!");
                    iRet = -1;
                    goto end;
                }
                _pstRtmpInfo->m_stTADTSHeader.profile_ObjectType = tHeader.profile_ObjectType;
                _pstRtmpInfo->m_stTADTSHeader.sampling_frequency_index = tHeader.sampling_frequency_index;
            }

            if(RTMPSendAACData(_pstRtmpInfo->m_pstRTMP, audioStart + 7, tHeader.aac_frame_length - 7, uiTimeStamp) < 0)
            {
                MRtmpLog_Error("call RTMPSendAACData failed!");
                iRet = -1;
                goto end;
            }
            
            audioStart += tHeader.aac_frame_length;
            audioLeftSize -= tHeader.aac_frame_length;
        }
    }
end:
    return iRet;
}

int RTMP_SendAudioData(void *_pvRtmpH, char *_pcAData, int _iDataLen, RtmpPacketInfo *_pstRtmpPacketInfo)
{
    int iRet = 0;

    if(NULL == _pvRtmpH ||
        NULL == _pcAData ||
        _iDataLen <= 0 ||
        NULL == _pstRtmpPacketInfo)
    {
        MRtmpLog_Error("invalid _pvRtmpH(%p) _pcAData(%p) _iDataLen(%d) _pstRtmpPacketInfo(%p)", _pvRtmpH, _pcAData, _iDataLen, _pstRtmpPacketInfo);
        iRet = -1;
        goto end;
    }
    
    if(RTMPSendAudioData((RtmpInfo *)_pvRtmpH, _pcAData, _iDataLen, _pstRtmpPacketInfo) < 0)
    {
        MRtmpLog_Error("call RTMPSendAudioData failed!");
        iRet = -1;
        goto end;
    }
end:
    return iRet;
}

int RTMP_Destroy(void *_pvRtmpH)
{
    int iRet = 0;
    RtmpInfo *pstRtmpInfo = NULL;
    
    if(NULL == _pvRtmpH)
    {
        iRet = -1;
        goto end;
    }

    pstRtmpInfo = (RtmpInfo *)_pvRtmpH;

    if(NULL != pstRtmpInfo->m_pstRTMP)
    {
        RTMP_Close(pstRtmpInfo->m_pstRTMP);
        RTMP_Free(pstRtmpInfo->m_pstRTMP);
    }
    free(pstRtmpInfo);
    
end:
    return iRet;
}

